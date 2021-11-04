// Node-only functionality in schadnfreude
use crate::innermain::*;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use super::stream::*;
use SfErr::NoneErr;
use crate::*;

pub const PIDLEN: usize = CRYPTO_BOX_MACBYTES + CRYPTO_SIGN_PUBLICKEYBYTES;
pub const FILE_OVERHEAD: i64 = 4096; //4k to cover DB and FS metadata, etc.
pub const MSG_OVERHEAD: i64 = 1024; //1k to cover DB metadata
pub const MAX_BACKUPS: usize = 3; //oughtta be enough for anybody

pub enum Stream {
    Syncer(ReadStream<MsgStream>), //Send
    Writer(WriteStream<File>),     //gets bits from the client and writes them to a file
    Reader(ReadStream<File>),      //reads a file and sends it down to the client
}

pub struct MsgStream {
    cid: ConvoId,
    seq: i64,
    last: Option<Vec<u8>>,
    db: Tree,
    inc: i64,
}
impl Read for MsgStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.len() == 0 {
            return Ok(0);
        }
        if let Some(ref mut l) = self.last {
            debug!("Finishing sync {} / {}", buf.len(), l.len());
            let endoff = l.len().min(buf.len());
            (&mut buf[..endoff]).copy_from_slice(&l[..endoff]);
            if endoff == l.len() {
                self.last.take();
            } else {
                l.drain(..endoff); //cut off what we can
            }
            return Ok(endoff);
        }
        let d = if let Ok(Some(r)) = self.db.get(&db_key(&self.cid, self.seq, b"mesg")[..]) {
            r
        } else {
            debug!("Syncer reached end");
            return Ok(0);
        };
        debug!("{} {}: {}-6 syb {}", self.seq, self.inc, d.len(), buf.len());
        let dat = &d[8..]; //skip the timestamp
        self.seq += self.inc;
        buf[0] = (dat.len() & 0xFF) as u8;
        if buf.len() == 1 {
            let mut v = Vec::with_capacity(dat.len() + 1);
            v.push(((dat.len() / 256) & 0xFF) as u8);
            v.extend_from_slice(dat);
            self.last = Some(v);
            return Ok(1);
        }
        buf[1] = ((dat.len() / 256) & 0xFF) as u8;
        if buf.len() >= dat.len() + 2 {
            (&mut buf[2..2 + dat.len()]).copy_from_slice(&dat);
            return Ok(2 + dat.len());
        }
        buf.copy_from_slice(&dat[..buf.len()]);
        self.last = Some(dat[buf.len()..].to_vec());
        Ok(buf.len())
    }
}

pub struct Session {
    pub last_seen: Instant,
    pub key: SecKey,
    pub spk: SignPKey,
    pub acks: Option<(i64, i64)>,
    pub timeout: Option<Instant>,
    pub rttms: f64, //in milliseconds
    pub write_privs: bool,
    pub streams: BTreeMap<i64, (Stream, Tube, Option<i64>)>, //id - stream,t,fid
    pub streamsrev: BTreeMap<i64, i64>,                      //fid -> id
}

impl Session {
    pub fn new(d: &Document, c: ConvoId, db: &Db, s: SignPKey, w: bool, t: Tube) -> Self {
        let mut streams = BTreeMap::new();
        let min_seq = d.get_i64("seq");
        let (seq, inc) = if let Ok(sq) = min_seq {
            (sq, 1)
        } else {
            (db_next_id(db, &c, b"mesg").max(1) - 1, -1)
        };
        let msg_stream = MsgStream {
            cid: c,
            seq: seq,
            last: None,
            db: (&db as &Tree).clone(),
            inc: inc,
        };
        let rtt = d.get_i32("rtt").unwrap_or(250).min(1000).max(10) as f64; //pick sane RTT bounds
        let sinker = Stream::Syncer(ReadStream::new(0, msg_stream, rtt));
        streams.insert(0, (sinker, t, None));
        Self {
            last_seen: Instant::now(),
            key: wr_randomkey(),
            spk: s,
            acks: None,
            timeout: None,
            rttms: rtt,
            write_privs: w,
            streams: streams,
            streamsrev: BTreeMap::new(),
        }
    }

    //Sets a session timeout. Call after a send or resend
    fn rto(&mut self, addr: &SocketAddr, rtos: &mut BTreeMap<Instant, SocketAddr>) {
        self.clear_rto(rtos); //remove old if present
        self.timeout = Some(Instant::now() + Duration::from_millis(self.rttms as u64 * 2));
        let to = self.timeout.as_mut().unwrap(); //convenience reference
        trace!("Setting RTO for {} to {:?}", addr, *to);
        let mut insed = rtos.insert(*to, *addr);
        while insed.is_some() {
            rtos.insert(*to, insed.unwrap()); //put the old one back
            *to += Duration::new(0, 100); //increment 100 ns
            insed = rtos.insert(*to, *addr); //put ours in again
        }
    }

    //Clear session timeout. Opposite of rto
    fn clear_rto(&mut self, rtos: &mut BTreeMap<Instant, SocketAddr>) {
        if let Some(to) = self.timeout {
            trace!("Clearing RTO {:?}", to);
            rtos.remove(&to); //clear timeout. We may replace it.
            self.timeout = None;
        }
    }
    fn rm_stream(&mut self, sid: i64, do_notice: bool) -> Option<Document> {
        info!("Removing stream {} notice {}", sid, do_notice);
        if let Some((strm, _tube, Some(fid))) = self.streams.remove(&sid) {
            if let Stream::Writer(wrtr) = strm {
                if wrtr.offset > 0 && do_notice && fid >= 0 {
                    return Some(doc! {"op":"fwr","fid":fid,"ln":wrtr.offset,"st":wrtr.start});
                }
            }
            self.streamsrev.remove(&fid); //Removes it from streamsrev too
        }
        None
    }
}

//Meets are conn requests
type PendingMeet = Vec<u8>;
//An active listener
pub struct MeetListen {
    key: SecKey, // symmetric, for the tunnel back to home
    saddr: SocketAddr,
    pending_conns: Arc<Mutex<HashMap<ConvoId, PendingMeet>>>, //other pubkey -> meet
    lastpolled: Instant,
    rtt: Duration,
    disp_name_enc: Vec<u8>,
}

pub struct Convo {
    pub sessions: HashMap<SocketAddr, Session>,
    pub seq: i64, //The number of the next reliable message to be sent
    pub convoid: ConvoId,
    pub path: String,
    pub flocks: BTreeMap<i64, (SocketAddr, Instant)>,
    pub moves: BTreeMap<i64, i64>,
    pub moverev: BTreeMap<i64, i64>,
    pub fid: i64, //FID’s are i64’s autoincremented on server side representing the latest file
    pub primary: bool, //whether we're the primary node
}
impl Convo {
    fn add_session(&mut self, p: &[u8], srv: &mut SfSrv, address: SocketAddr, session: Session) {
        let mut pid = [0; PIDLEN];
        (&mut pid[..]).copy_from_slice(p); //insert into the DB if not already there
        let (none, some) = (None as Option<&[u8]>, Some(Vec::new())); //don't actually allocate
        let prid_key = db_plkey(&self.convoid, b"prid", &pid);
        let res = srv.db.compare_and_swap(&prid_key, none, some);
        if let Ok(Ok(())) = res {
            if pid != [0; PIDLEN] {
                let rdoc = doc! {"e":{"op":"ent", "ent":binary_bson(&pid[..])}, "q":self.seq};
                log_err!(srv.send(None, rdoc, self), "srvsend"); // let everybody know
            }
        }
        log_err!(res, "DB cas");
        self.sessions.insert(address, session);
    }
    //does the connection from this addr have a file lock on the given fid?
    fn has_flock(&self, fid: i64, src_addr: &SocketAddr) -> bool {
        let l = self.flocks.get(&fid);
        l.map(|(add, _tm)| add == src_addr).unwrap_or(false)
    }

    fn oid_fid(&self, cash: &Db, origid: &[u8]) -> SfRes<i64> {
        let fidoid = array_ref![leneq(origid, 32)?, 0, 32];
        let record = cash.get(&db_id(&self.convoid, b"oid_", fidoid)[..])?;
        Ok(bytes_to_u64(leneq(&record.ok_or_else(sfnone)?, 8)?) as i64)
    }

    fn new_fid(
        &mut self,
        id: i64,
        doc: &Document,
        reply: &mut Document,
        src_addr: &SocketAddr,
        cash: &Db,
    ) -> SfRes<(i64, [u8; 8])> {
        let origid = leneq(doc.get_binary_generic("origid")?, 32)?;
        let oid_key = db_id(&self.convoid, b"oid_", array_ref![origid, 0, 32]);
        let ts = now_as_bin_microseconds();
        let mut met = origid.to_vec(); //metadata is oid32bytes + timestamp8bytes + meta
        met.extend_from_slice(&ts[..]);
        met.extend_from_slice(doc.get_binary_generic("meta")?);
        info!("Newfid {} {}", self.fid, b64spk(array_ref![origid, 0, 32]));
        if let Some(conts) = cash.get(&oid_key[..])? {
            //The file already exists, let's see if it's a resent open
            let fid = bytes_to_u64(leneq(&conts, 8)?) as i64; //get fid from bytes
            if !self.has_flock(fid, src_addr) {
                warn!("New fid error, OID exists but no lock"); //not a resent open?
                return Err(SfErr::OidExists);
            }
            info!("Resending new file response"); //valid fid, so resend acceptance
            *reply = doc! {"id": id, "fid": fid, "origid": binary_bson(origid)};
            return Err(SfErr::Resend); //err since we did not allocate a new FID, but no problem
        }
        cash.insert(&oid_key[..], &u64_bytes(self.fid as u64))?; //save oid->fid
        cash.insert(&db_key(&self.convoid, self.fid, b"meta")[..], met)?; //save metadata
        debug!("Saved metadata for new fid {}", self.fid); //valid fid, so resend acceptance
        let mut binopener = OpenOptions::new();
        let binpath = format!("{}{:018}", self.path, self.fid);
        binopener.write(true).create_new(true).open(&binpath)?; // create empty data file
        *reply = doc! {"id": id, "fid": self.fid, "origid": binary_bson(origid)};
        self.fid += 1; //increment fid for next time
        Ok((self.fid - 1, ts)) //return fid for this one
    }

    //Removes all locks and info about a fid
    fn rmflock(&mut self, fid: i64) {
        self.flocks.remove(&fid);
        if let Some(oldfid) = self.moverev.get(&fid).map(|oldfid| *oldfid) {
            self.moverev.remove(&fid);
            self.moves.remove(&oldfid);
        }
    }

    //Grants or renews a file lock
    fn file_lock(&mut self, src: &SocketAddr, fid: i64, cash: &Db) -> SfRes<()> {
        let good = if let Some((add, tm)) = self.flocks.get(&fid) {
            add == src || // we already have it?
            (tm.elapsed() > Duration::from_secs(16) //other locker went dark
            && !cash.contains_key(&db_key(&self.convoid, fid, b"lock")[..])?)
        } else {
            !cash.contains_key(&db_key(&self.convoid, fid, b"lock")[..])? //must not be permalocked
        };
        if good {
            debug!("Granting {} flock on {}", src, fid);
            self.flocks.insert(fid, (src.clone(), Instant::now()));
            return Ok(());
        }
        info!("Lock failed for {} on {}", src, fid);
        debug!(
            "current lock? {:?} permalock? {}",
            self.flocks.get(&fid),
            cash.contains_key(&db_key(&self.convoid, fid, b"lock")[..])?
        );
        Err(SfErr::LockFailed)
    }

    //Kills all sessions from a given client key (to boot a revoked backup server)
    fn rm_sessions_by_key(&mut self, key: &SignPKey, sfsrv: &mut SfSrv) {
        'outer: loop {
            for (addr, sess) in self.sessions.iter() {
                if sess.spk == *key {
                    let a = addr.clone();
                    self.rm_session(&a, sfsrv); //this invalidates the iter
                    continue 'outer; //so we gotta restart
                }
            }
            break; //until there aren't any left
        }
    }

    //Removes a client from clients by source address
    fn rm_session(&mut self, src: &SocketAddr, sfsrv: &mut SfSrv) {
        info!("Client {} exiting chat", src);
        sfsrv.clis.remove(src);
        if let Some(mut s) = self.sessions.remove(src) {
            s.clear_rto(&mut sfsrv.rtos);
            while !s.streams.is_empty() {
                let sid = *s.streams.keys().next().unwrap();
                if let Some(notice) = s.rm_stream(sid, true) {
                    log_err!(sfsrv.send(None, doc! {"e":notice,"q":self.seq}, self), "");
                }
            }
        }
        if self.sessions.is_empty() {
            // we just removed the last client. Now we can drop the whole convo from memory.
            sfsrv.convos.remove(&self.convoid); // the convo and all locks are now gone. Data still in DB.
        } else {
            // There are still people in the convo, release that guy's locks and streams
            let mut rmfids = Vec::new();
            for (fid, locks) in self.flocks.iter() {
                if locks.0 == *src {
                    rmfids.push(*fid);
                }
            }
            for fid in rmfids {
                self.rmflock(fid);
            }
        }
    }
}

//This is a hop from the server side; only cares about key and next hop. Flag to initiate shut down.
pub struct Tunnel {
    key: SecKey, // Secret key
    fwds: [Option<(Tube, Arc<AtomicBool>)>; MAX_TUNNELS],
    last_seen: Instant,
    sender: Tube,
}

//Relays TCP connections to UDP
fn run_tcp_relay(mut sockaddr: SocketAddr) {
    let listener = match TcpListener::bind(&sockaddr) {
        Ok(l) => l,
        Err(e) => {
            error!("TCP listener failed to bind {}", e);
            return;
        }
    };
    sockaddr.set_ip(if sockaddr.is_ipv4() {
        IpAddr::V4(Ipv4Addr::LOCALHOST) //bind is 0.0.0.0 or [::] but need localhost to connect
    } else {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    });
    spawn_thread("tcplistn", move || loop {
        //Get a TCP connection then establish a localhost UDP one to our listener
        if let Err(e) = Tube::tcp_accept(&listener).and_then(|mut cli_tube| -> SfRes<()> {
            let fwd_tube = Tube::udp_connect(&sockaddr)?;
            fwd_tube.set_timeout(secs(60))?;
            let cli_recv = cli_tube.split_off_recv()?;
            let fwd_send = fwd_tube.clone_sender()?;
            //Spawn a thread to forward up then one to forward down
            spawn_thread("tcpfwdup", move || loop {
                if let Err(e) = cli_recv.recv_vec().and_then(|v| fwd_send.send_vec(v)) {
                    debug!("closing tcpfwdup? {}", e);
                    break; //error closes the thread
                }
            });
            spawn_thread("tcpfdown", move || loop {
                if let Err(e) = fwd_tube.recv_vec().and_then(|v| cli_tube.send_vec(v)) {
                    debug!("closing tcpfdown? {}", e);
                    break; //again, error closes thread
                }
            });
            Ok(())
        }) {
            error!("TCP forward failure: {}", e);
            thread::park_timeout(time::Duration::from_secs(1)); // in case the server sock is dead
        }
    })
}

//Watches a client downloading stream and resends when RTO gets hit
fn streamdown(carc: Arc<Mutex<Convo>>, rttmsf: f64, k: SecKey, sid: i64, add: SocketAddr) {
    let mut delay_dead = (Duration::from_millis((rttmsf * 2.0) as u64), false);
    while {
        if let Ok(mut conn) = carc.lock() {
            if let Some(sess) = conn.sessions.get_mut(&add) {
                if let Some((stream, stube, _)) = sess.streams.get_mut(&sid) {
                    if let Stream::Reader(ref mut rd) = stream {
                        delay_dead = rd.check_rto(&stube, Some(&k));
                    }
                } else {
                    debug!("stream gone dead");
                    delay_dead.1 = true //client exited or something
                }
                if delay_dead.1 {
                    sess.rm_stream(sid, false); // Passing false since there's no need to send notices
                }
            }
        }
        if !delay_dead.1 {
            thread::sleep(delay_dead.0);
        }
        !delay_dead.1 //while condition
    } {}
    debug!("streamdown rto thread done");
}

//Finds highest ID + 1 for a given convo and suffix
fn db_next_id(cash: &Tree, convoid: &ConvoId, suffix: &[u8; 4]) -> i64 {
    let start = db_key(convoid, 0, suffix);
    if let Some(Ok(kbin)) = cash.scan_prefix(&start[..36]).keys().next_back() {
        debug!("db_next_id found something");
        if kbin.len() == 32 + 4 + 8 {
            return be_to_i64(array_ref![kbin, 36, 8]) + 1;
        }
    }
    debug!("db_next_id found nothing");
    0
}

//Schadnfreude node server
pub struct SfSrv {
    pub ctxt: Context,
    pub sock: Arc<UdpSocket>,
    pub local_sndr: Sender<Sync>,
    pub rtos: BTreeMap<Instant, SocketAddr>,
    pub clis: HashMap<SocketAddr, (SecKey, Arc<Mutex<Convo>>)>,
    pub tunnels: HashMap<SocketAddr, Tunnel>,
    pub meets: HashMap<SignPKey, MeetListen>,
    pub convos: HashMap<ConvoId, Arc<Mutex<Convo>>>,
    pub db: Arc<Db>,
    pub totl_key: [u8; 32 + 4], //DB key to store total count of bytes used
    pub max_db_size: u64,       //messages/files auto-deleted by default once DB hits this size
    pub max_msg_age: u64,       //messages/files auto-deleted by default after this many seconds
    pub max_convo: u64,         //messages/files auto-deleted by default once convo hits this size
}
impl SfSrv {
    pub fn new(ctxt: &Context, socket: Arc<UdpSocket>, config: &Yaml, ls: Sender<Sync>) -> Self {
        Self {
            ctxt: Arc::clone(ctxt),
            sock: socket,
            local_sndr: ls,
            rtos: BTreeMap::new(), //timeout -> session src_addr
            clis: HashMap::new(),
            tunnels: HashMap::new(),
            meets: HashMap::new(), // listener pubkey -> record
            convos: HashMap::new(),
            db: Arc::clone(&ctxt.cache),
            totl_key: [0; 36],
            max_db_size: config["max_db_size"].as_i64().unwrap_or(i64::max_value()) as u64,
            max_msg_age: config["max_msg_age"].as_i64().unwrap_or(i64::max_value()) as u64,
            max_convo: config["max_convo"].as_i64().unwrap_or(i64::max_value()) as u64,
        }
    }

    //Resends any pending RTO's. Returns delay until next or None if all caught up
    fn process_rtos(&mut self) -> Option<Duration> {
        loop {
            let (due_date, addr) = if let Some((due_date, cli_addr)) = self.rtos.iter().next() {
                if let Some(dur) = due_date.checked_duration_since(Instant::now()) {
                    debug!("RTO timeout in {}", dur.as_secs_f64());
                    return Some(dur); //Wait up to next timeout for the next packet
                } else {
                    (due_date.clone(), cli_addr.clone()) //due_date < now (i.e. need to resend)
                }
            } else {
                break; //No RTO's scheduled.
            };
            if let Some(arc_lock) = self.clis.get(&addr).map(|arcm| Arc::clone(&arcm.1)) {
                let al = arc_lock.lock(); //cloned arc so we can drop the reference to sctx
                if let Ok(mut convo) = al {
                    debug!("Resending to {} ({:?})", addr, due_date);
                    log_err!(self.resend(&mut convo, &addr), "Resend"); // do the resend
                }
            }
            if let Some(_) = self.rtos.remove(&due_date) {
                error!("This shouldn't ever happen");
            }
        }
        None
    }
    //Evaluates an RPC call. These functions handlers should not block.
    //They should gracefully handle duplicate calls as the underlying transport is unreliable.
    //Please note TCP would not fix this, as we must prepare for malicious MITM attacks.
    fn evaluate_rpc(&mut self, ct: &[u8], src: &SocketAddr) -> SfRes<Vec<u8>> {
        let ctxt = &self.ctxt;
        let mut plain = Cursor::new(wr_crypto_box_seal_open(ct, &ctxt.keys.bx)?);
        let doc = decode_document(&mut plain).map_err(|e| SfErr::BsonDecErr(e))?;
        let rk = doc.get_binary_generic("respkey")?;
        let spk: SignPKey = copy_to_array(leneq(rk, CRYPTO_SIGN_PUBLICKEYBYTES)?);
        let fnc = doc.get_str("fnc")?;
        let id = doc.get_i64("id").unwrap_or(0);
        debug!("{:X}: {} len {} {}", id, fnc, plain.into_inner().len(), src);
        let rpk = wr_crypto_sign_pk_to_box(&spk);
        let mut resp = doc! { "err": "invalid fnc or parameters" }; //default to generic err
        let try_num = doc.get_i32("tr").unwrap_or(0);
        debug!("F {} try {} ID {:X}", fnc, try_num, id);
        match fnc {
            "nodelist" => nodelist(ctxt, &doc, src, spk, &rpk, &mut resp),
            "nodeannounce" => nodeannounce(ctxt, &doc, &mut resp),
            "fwd" => self.fwd(&doc, src, &mut resp),
            "fwdclose" => self.fwdclose(src, &mut resp, doc.get_i32("c").unwrap_or(0)),
            "listen" => self.listen(&doc, &mut resp, spk, src),
            "meetack" => self.meetack(&doc, spk, &mut resp),
            "openchat" => self.openchat(doc, src, &spk, &mut resp),
            "joinchat" => self.join(&doc, src, &spk, &rpk, &mut resp),
            "backupcon" => self.back(doc, src.clone(), &rpk, &spk, &mut resp),
            _ => {}
        }
        resp.insert("id", bson::Bson::I64(id)); //id in resp if in req
        resp.insert("tr", bson::Bson::I32(try_num));
        let encreply = wr_crypto_box_easy(&bdoc_to_u8vec(&resp), &rpk, &self.ctxt.keys.bx.sk);
        debug!("response {} bytes ID {:X}", encreply.len(), id);
        Ok(encreply)
    }
    // Removes clients who have gone dark for 5 minutes from active chats
    fn trim_sessions(&mut self) {
        let mut rm_sessions = HashMap::new();
        for (_cid, cs_mutex) in self.convos.iter() {
            //figure out which ones to remove
            let convo = ok_or_continue!(cs_mutex.lock());
            for (addr, sess) in convo.sessions.iter() {
                if sess.last_seen.elapsed() > Duration::from_secs(300) {
                    rm_sessions.insert(*addr, Arc::clone(&cs_mutex));
                }
            }
        }
        for (addr, cs_arc) in rm_sessions {
            let mut convo = ok_or_continue!(cs_arc.lock());
            convo.rm_session(&addr, self); // then fry 'em!
        }
    }
    //handle tunnel msg
    pub fn tunnel_msg(&mut self, src: &SocketAddr, ct: &mut [u8]) -> SfRes<()> {
        let mut t = self.tunnels.get_mut(&src).ok_or_else(sfnone)?;
        let decbuf = wr_crypto_secretbox_open(ct, &t.key)?;
        t.last_seen = Instant::now();
        if decbuf.len() > 1 && decbuf[0] < MAX_TUNNELS as u8 {
            trace!("Good tun msg chan {}", decbuf[0]);
            if decbuf[0] == 0 {
                //process control channel msg, synchronously send reply
                let tsnd = t.sender.clone_sender()?;
                self.evaluate_rpc(&mut decbuf[1..], &src)
                    .and_then(|mut encreply| {
                        encreply.insert(0, 0); //insert reply channel tag
                        tsnd.send_vec(encreply) //then send
                    })
                    .unwrap_or_else(|e| error!("Error tun cmd: {}", e));
            } else if let Some((tun, _f)) = &t.fwds[decbuf[0] as usize] {
                let sendres = tun.send(&decbuf[1..]).map(|_| ());
                trace!("Tun {} > {} len {} {}", src, tun, ct.len(), b64sk(&t.key));
                sendres.unwrap_or_else(|e| error!("Error tun fwd: {}", e));
            }
        }
        Ok(())
    }
    //Handle a session message
    pub fn session_msg(&mut self, src: &SocketAddr, recvbuf: &[u8]) -> SfRes<()> {
        let op = self.clis.get(src).map(|(k, m)| (k.clone(), Arc::clone(m)));
        let (key, session_mutex) = op.ok_or_else(sfnone)?;
        let decrypted = wr_crypto_secretbox_open_easy(recvbuf, &key)?;
        let mut convo = session_mutex.lock()?;
        debug!("{} cid {} {}", src, b64spk(&convo.convoid), decrypted.len());
        log_err!(self.process(src, decrypted, &mut convo), "session message");
        Ok(())
    }

    // Update beancounters on who's used how much, trigger reclamation if over
    fn get_u64(&self, key: &[u8]) -> SfRes<u64> {
        let db_got = self.db.get(key)?.ok_or_else(sfnone)?;
        Ok(bytes_to_u64(leneq(&*db_got, 8)?))
    }
    //Removes an item based on a date log record
    fn rm_date(&mut self, k: &[u8], conv: &mut Convo) -> SfRes<()> {
        if &k[76..80] == b"mesg" {
            let dbk = db_key(&conv.convoid, bytes_to_u64(&k[80..88]) as i64, b"mesg");
            self.rm_convo_msg(conv, &dbk)
        } else {
            self.rm_file(bytes_to_u64(&k[80..88]) as i64, conv, true) //file
        }
    }
    //This function is called to update the amount of space stored, making room if necessary
    fn update_space(&mut self, convo: &mut Convo, space_diff: i64) -> SfRes<()> {
        debug!("Space {} {}", b64spk(&convo.convoid), space_diff);
        let sdiff = u64_bytes(space_diff as u64);
        self.db.merge(&self.totl_key[..], &sdiff)?; //update total data bytes used
        let conv_size_key = db_key(&convo.convoid, 0, b"conv");
        self.db.merge(&conv_size_key[..], &sdiff)?; //and total bytes used by this convo
        if space_diff < 0 {
            return Ok(()); //don't do size checks/trims on delete
        }
        //max_msg_age and max_db_size: Delete oldest DB stuff that's too old or until we have space
        loop {
            let mut tstart = [0; 36]; //secret "time"
            (&mut tstart[0..32]).copy_from_slice(&self.totl_key[0..32]); //private DB info code
            (&mut tstart[32..36]).copy_from_slice(b"time"); //time
            let kv = some_or_break!(self.db.scan_prefix(&tstart[..]).next()); //should unwrap
            let key = kv?.0; //time key: secret "time" [big endian] [cid] "mesg" id
            let mtime = be_to_i64(&leneq(&key, 88)?[(32 + 4)..(32 + 4 + 8)]);
            let age = UNIX_EPOCH.elapsed().unwrap().as_secs() - mtime as u64 / 1_000_000;
            if age > self.max_msg_age || self.max_db_size < self.get_u64(&self.totl_key[..])? {
                self.db.remove(&key)?; //remove it, ensuring it's the right length
                let cid = array_ref![key, 44, 32];
                if *cid == convo.convoid {
                    self.rm_date(&key, convo)? //remove data attached
                } else {
                    let arc = Arc::clone(self.convos.get(cid).ok_or_else(sfnone)?);
                    let mut arcl = arc.lock()?;
                    self.rm_date(&key, &mut *arcl)?
                }
            } else {
                break; //nothing to do
            }
        }
        //max_convo: Trim oldest msg and files in convo until it's under the convo limit
        while self.max_convo < self.get_u64(&conv_size_key[..])? && self.snip(convo)? {
            debug!("Convo big: {}", self.get_u64(&conv_size_key[..])?); //check msg's and files
        }
        Ok(())
    }

    //Removes the oldest convo message
    fn snip(&mut self, convo: &mut Convo) -> SfRes<bool> {
        let start = db_key(&convo.convoid, 0, b"mesg");
        let fstart = db_key(&convo.convoid, 0, b"meta");
        if let Some(msg_k) = self.db.scan_prefix(&start[..36]).next() {
            let (k, mtime) = msg_k.map(|(k, v)| (k, be_to_i64(&v[0..8])))?; //msg time big-endin
            if let Some(fid_item) = self.db.scan_prefix(&fstart[..36]).next() {
                let (k, ftime) = fid_item.map(|(k, v)| (k, be_to_i64(&v[32..40])))?; //file time
                if ftime < mtime {
                    self.rm_file(be_to_i64(&k[36..]), convo, true)?; //skip cid and b"meta"
                    return Ok(true); //deleted a file older than the last msg. now try again
                }
            }
            self.rm_convo_msg(convo, &k)?; //clear old convo msg
        } else {
            if let Some(fid_item) = self.db.scan_prefix(&fstart[..36]).next() {
                self.rm_file(be_to_i64(&fid_item?.0[36..]), convo, true)?; //skip cid and "meta"
            } else {
                error!("Convo {} too big but has nothing", b64spk(&convo.convoid));
                return Ok(false); //should never happen
            }
        }
        Ok(true)
    }

    fn rm_convo_msg(&mut self, convo: &mut Convo, db_k: &[u8]) -> SfRes<()> {
        debug!("deleting convo msg {}", b64spk(&convo.convoid));
        if let Some(rmed) = self.db.remove(&db_k)? {
            self.update_space(convo, 0 - rmed.len() as i64 - MSG_OVERHEAD)?; //rm too-old msgs
            let seq = be_to_i64(&db_k[36..]);
            self.rm_time_key(&convo.convoid, b"mesg", seq, *array_ref![rmed, 0, 8])?;
            let msg = decode_document(&mut Cursor::new(&rmed[8..]))?; //skip timestamp
            debug!("rmm'd {}", msg);
            if let Ok(m) = msg.get_binary_generic("m"){
                let hash = wr_crypto_hash_sha256(m); //get inner msg
                if let None = self.db.remove(&db_id(&convo.convoid, b"hash", &hash)[..])? {
                    warn!("Couldn't find hash of msg {} in DB?", seq); //also rm hash
                }
            }
        }
        Ok(())
    }

    //Reliable message for a Convo: check for duplicates, cache, send out, and send an ack
    fn msg(&mut self, sa: &SocketAddr, msg: Vec<u8>, c: &mut Convo, key: &SecKey) -> SfRes<()> {
        let hash = wr_crypto_hash_sha256(&msg);
        debug!("Ackable message datalen {} {}", msg.len(), b64spk(&hash));
        let hk = db_id(&c.convoid, b"hash", &hash);
        let seqi64 = if let Some(id) = self.db.get(&hk[..])? {
            debug!("Re-acking retrans {}", b64spk(&hash)); //msg already in DB
            bytes_to_u64(leneq(&id, 8)?) as i64
        } else {
            debug!("New msg {}", b64spk(&hash)); //new message, store it and forward to subscribers
            self.db.insert(&hk[..], &u64_bytes(c.seq as u64))?;
            self.send(Some(sa), doc! {"m": binary_bvec(msg), "q": c.seq}, c)? //returns seq
        };
        //Send the ack number back only to the original sender
        let bd = bdoc_to_u8vec(&doc! {"a": binary_bson(&hash), "n":  seqi64});
        self.sock.send_to(&wr_crypto_secretbox_easy(&bd, key), sa)?;
        Ok(())
    }

    fn set_time_key(&self, cid: &ConvoId, data_type: &[u8; 4], seq: i64, ts: [u8; 8]) -> SfRes<()> {
        let key = time_key(&self.totl_key[0..32], &cid, data_type, seq, ts);
        self.db.insert(&key[..], b"")?; //set time log entry
        Ok(())
    }

    fn rm_time_key(&self, cid: &ConvoId, data_type: &[u8; 4], seq: i64, ts: [u8; 8]) -> SfRes<()> {
        let key = time_key(&self.totl_key[0..32], cid, data_type, seq, ts);
        if let None = self.db.remove(&key[..])? {
            debug!("Already removed time entry for mesg {}", seq); //delete time log entry failed
        }
        Ok(())
    }

    //sa is an address to skip, or none if it is to be broadcast to all.
    fn send(&mut self, sa: Option<&SocketAddr>, mut d: Document, c: &mut Convo) -> SfRes<i64> {
        let seq = c.seq;
        debug!("msg seq {}", seq);
        let ts = now_as_bin_microseconds(); //big endian microseconds since epoch
        d.insert("t", i64::from_be_bytes(ts)); //tell the clients when we got it by our clocks
        let mut out = Cursor::new(Vec::with_capacity(256));
        out.write_all(&ts[..])?; //First 8 bytes are timestamp, then message
        log_err!(bson::encode_document(&mut out, d.iter()), "Encode");
        let msg = out.into_inner(); //now get back the vec in its original form
        let m = &msg[8..]; //m = just the message (no timestamp)
        self.update_space(c, msg.len() as i64 + MSG_OVERHEAD)?;
        self.set_time_key(&c.convoid, b"mesg", seq, ts)?;
        debug!("Wrote msg seq {} con {}", seq, b64spk(&c.convoid));
        c.seq += 1;
        let mut re_enc = vec![0; m.len() + CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES];
        for (ses_add, sess) in c.sessions.iter_mut() {
            if sa.map(|s| *s != *ses_add).unwrap_or(true) {
                let enclen = wr_crypto_secretbox_inplace(&m, &mut re_enc, &sess.key);
                debug!("reenc msg {} len {} to {}", seq, enclen, ses_add);
                if let Err(e) = self.sock.send_to(&re_enc[..enclen], &ses_add) {
                    warn!("error fwd session message to {}: {}", ses_add, e);
                } else {
                    sess.rto(ses_add, &mut self.rtos); //set resend timeout
                }
            }
        }
        self.db.insert(&db_key(&c.convoid, seq, b"mesg")[..], msg)?; //save msg in DB
        debug!("sent reencrypted? {} {}", seq, b64spk(&c.convoid));
        Ok(seq)
    }

    fn send_to_all_users_but(&self, src: &SocketAddr, pt: &[u8], c: &Convo) -> SfRes<()> {
        let mut bin = vec![0; pt.len() + CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES];
        for (ses_add, dest_session) in c.sessions.iter() {
            if *src != *ses_add && dest_session.write_privs {
                wr_crypto_secretbox_inplace(&pt, &mut bin, &dest_session.key);
                debug!("Sending {} bytes to {}", bin.len(), ses_add);
                if let Err(e) = self.sock.send_to(&bin, &ses_add) {
                    warn!("error fwd session u message to {}: {}", ses_add, e);
                }
            }
        }
        Ok(())
    }

    //Processes a command/message sent over a connected session
    pub fn process(&mut self, src: &SocketAddr, pt: Vec<u8>, c: &mut Convo) -> SfRes<()> {
        let mut s = c.sessions.get_mut(src).ok_or_else(sfnone)?;
        s.last_seen = Instant::now();
        let sk = s.key.clone();
        let ptlen = pt.len();
        let mut doc = decode_document(&mut Cursor::new(&pt))?;
        debug!("session msg len {} {:?}", ptlen, doc.keys().next());
        if doc.contains_key("exit") {
            c.rm_session(src, self); //remove from clients and convos
            let bin = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&doc! {"exited": true}), &sk);
            Ok(self.sock.send_to(&bin, src).map(|_| ())?)
        } else if doc.contains_key("u") {
            self.send_to_all_users_but(src, &pt, c)
        } else if doc.contains_key("ack") {
            self.ack(&doc, c, src) //ack msg; based on what is or isn't here, can trigger resend
        } else if doc.contains_key("promote") {
            let id = doc.get_i64("id").unwrap_or(0);
            let mut reply = doc! {"r":"err", "id": id};
            log_err!(self.promo(doc, src, c, &mut reply), "promote cmd");
            debug!("Sending promote {:X} reply to {}", id, src);
            let bin = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&reply), &sk);
            Ok(self.sock.send_to(&bin, &src).map(|_| ())?)
        } else if !c.primary || !s.write_privs {
            info!("bad command for backup {} {}", c.primary, s.write_privs); //TODO: not below for backup nodes
            Err(SfErr::NotAllowed) //only exit, promote, ack, or unreliable messages for backup conn
        } else if doc.contains_key("s") {
            let streamid = doc.get_i64("s")?; //does the stream ID exist?
            let sgres = s.streams.get_mut(&streamid); //Is the stream ID valid and for this addr?
            let (ref mut strm, ref mut tube, _) = sgres.ok_or(SfErr::BadId)?;
            let sres = match strm {
                Stream::Syncer(ref mut r) => r.stream_read(tube, Some(&sk), &doc).map(|_| 0),
                Stream::Writer(ref mut w) => w.stream_write(tube, Some(&sk), &doc),
                Stream::Reader(ref mut r) => r.stream_read(tube, Some(&sk), &doc).map(|_| 0),
            };
            if let Err(SfErr::DoneErr) = sres {
                return Ok(()); //end of stream - handled
            } else if let Err(e) = sres {
                info!("Stream {} error: {}", streamid, e);
                if let SfErr::OutOfOrderErr = &e {
                    return Ok(()); //ignore ooo
                } else if let SfErr::IoErr(ie) = &e {
                    if let ErrorKind::UnexpectedEof = ie.kind() {
                        return Ok(()); //not fatal; can't remove stream until client has acked end
                    }
                }
                if let Some(notice) = s.rm_stream(streamid, true) {
                    log_err!(self.send(None, doc! {"e":notice,"q":c.seq}, c), "send");
                }
                return Err(e);
            }
            let written = sres.unwrap();
            if written > 0 {
                self.update_space(c, written as i64)?;
            }
            Ok(())
        } else if doc.contains_key("m") {
            if let Bson::Binary(_, m) = doc.remove("m").ok_or(SfErr::BadMessage)? {
                self.msg(src, m, c, &sk) //normal msg
            } else {
                Err(SfErr::BadMessage)
            }
        } else if doc.contains_key("f") {
            let id = doc.get_i64("id").unwrap_or(0);
            let mut reply = doc! {"f":"error", "id": id};
            let f = doc.get_str("f")?;
            if f == "lve" {
                let part = leneq(doc.get_binary_generic("lve")?, PIDLEN)?;
                let partkey = db_plkey(&c.convoid, b"prid", array_ref![part, 0, PIDLEN]);
                log_err!(self.db.remove(&partkey[..]), "leave DB remove");
                let rdoc = doc! {"e":{"op":"lve", "lve":binary_bson(part)}, "q":c.seq};
                self.send(Some(src), rdoc, c)?; // let everybody know
                if self.db.scan_prefix(&partkey[..36]).next().is_none() {
                    info!("Everyone left {} - wiping", b64spk(&c.convoid));
                    while self.snip(c)? {} // Everyone gone - wipe convo
                }
                reply = doc! {"id": id, "lve": true};
            } else {
                log_err!(self.file_cmd(src, &mut reply, id, c, &doc, f, &sk), "file");
            }
            debug!("Sending f {:X} reply to {}", id, src);
            let bin = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&reply), &sk);
            Ok(self.sock.send_to(&bin, &src).map(|_| ())?)
        } else if doc.contains_key("roll") {
            let id = doc.get_i64("id").unwrap_or(0); //rolling backups
            let mut reply = doc! {"r":"err", "id": id};
            log_err!(self.roll(&mut reply, c, &doc, &pt), "roll cmd error");
            debug!("Sending roll {:X} reply to {}", id, src);
            let bin = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&reply), &sk);
            Ok(self.sock.send_to(&bin, &src).map(|_| ())?)
        } else {
            Err(SfErr::InvalidOp) //No u. No U! And no other commands either
        }
    }

    fn roll(&mut self, r: &mut Document, c: &mut Convo, doc: &Document, bin: &[u8]) -> SfRes<()> {
        let oldb = doc.get_binary_generic("roll")?; //old backup
        let newb = doc.get_binary_generic("newb")?; //new backup
        let wa = doc.get_binary_generic("newa")?; //new address
        let (ob, nb) = (binary_bson(leneq(oldb, 32)?), binary_bson(leneq(newb, 32)?));
        let (na, k) = (binary_bson(leneq(wa, 19)?), db_key(&c.convoid, 0, b"sigh"));
        let h = self.ctxt.cache.get(&k)?.ok_or(NoneErr)?; //We will have signed host entry
        let hash = wr_crypto_hash_sha256(bin);
        let hk = db_id(&c.convoid, b"hash", &hash);
        let seqi64 = if let Some(id) = self.db.get(&hk[..])? {
            debug!("Re-acking roll retrans {}", b64spk(&hash)); //roll already in DB, filters dups
            bytes_to_u64(leneq(&id, 8)?) as i64
        } else {
            let bkey = wr_crypto_sign_pk_to_box(array_ref![&oldb, 0, 32]);
            if let None = self.ctxt.cache.remove(&db_id(&c.convoid, b"bknd", &bkey))? {
                warn!("backup rm not there {}", b64spk(array_ref![&oldb, 0, 32]));
                return Err(SfErr::InvalidOp);
            }
            let mut backbuf = [0; 32 + 19]; //form for setup_backups
            (&mut backbuf)[..19].copy_from_slice(&wa[..19]);
            (&mut backbuf)[19..].copy_from_slice(&newb[..32]);
            setup_backups(c.convoid.clone(), &self.ctxt, &backbuf, &h);
            //forcibly kill any of that old backup's active connections
            c.rm_sessions_by_key(array_ref![oldb, 0, 32], self);
            self.db.insert(&hk[..], &u64_bytes(c.seq as u64))?; //save message seq (send() increments)
            let rdoc = doc! {"e":{"op":"roll", "oldb":ob, "newb":nb, "newa":na}, "q":c.seq};
            self.send(None, rdoc, c)?
        };
        r.insert("a", binary_bson(&hash)); //return ack
        r.insert("n", seqi64);
        Ok(())
    }

    //Load up appropriate msg from a given convo, encrypt it with a session key, and send it
    fn resend(&mut self, c: &mut Convo, src: &SocketAddr) -> SfRes<()> {
        let seq = c.seq;
        let cid = c.convoid.clone();
        let s = c.sessions.get_mut(src).ok_or_else(sfnone)?;
        s.clear_rto(&mut self.rtos);
        let seq = if let Some((low, high)) = s.acks {
            if high + 1 < seq {
                seq - 1 //latest msg
            } else if low > 0 && seq > 0 {
                low - 1 //missing earlier messages
            } else {
                debug!("Nothing to resend, seq {} {}", seq, src);
                let b = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&doc! {"pingack": true}), &s.key);
                return Ok(self.sock.send_to(&b, src).map(|_| ())?); // no message to miss
            }
        } else {
            debug!("Empty acks"); //They haven't received anything yet
            if seq > 0 {
                seq - 1 // send latest msg
            } else {
                debug!("Nothing to resend, seq {} {}", seq, src);
                let b = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&doc! {"pingack": true}), &s.key);
                return Ok(self.sock.send_to(&b, src).map(|_| ())?); // no message to miss
            }
        };
        debug!("looking to resend {} {}", seq, src);
        let msg = self.db.get(&db_key(&cid, seq, b"mesg")[..])?; //get msg in DB. 1st 8 bytes = time
        let enc = wr_crypto_secretbox_easy(&msg.ok_or(NoneErr)?[8..], &s.key); //encrypt it
        self.sock.send_to(&enc, src)?; //send it
        s.rto(src, &mut self.rtos); //set new RTO
        debug!("Read and resent {} ({} bytes) {}", seq, enc.len(), src);
        Ok(())
    }

    //Update acks and resend missing message or ping ack
    fn ack(&mut self, doc: &Document, convo: &mut Convo, addr: &SocketAddr) -> SfRes<()> {
        let ack = doc.get_array("ack")?;
        let mut sess = convo.sessions.get_mut(addr).ok_or(NoneErr)?;
        if ack.len() > 1 {
            let low = ack[0].as_i64().ok_or(NoneErr)?;
            let high = ack[1].as_i64().ok_or(NoneErr)?;
            debug!("Ack low {} high {}", low, high);
            sess.acks = Some((low, high));
        } else {
            if let Some((Stream::Syncer(ref mut rd), stube, _)) = sess.streams.get_mut(&0) {
                if rd.check_rto(&stube, Some(&sess.key)).1 {
                    sess.rm_stream(0, false); //sync stream completed. Back to individual acks
                }
            }
            return Err(NoneErr);
        }
        self.resend(convo, addr)
    }

    fn mov(&mut self, c: &mut Convo, id: i64, id2: i64, ts: [u8; 8]) -> SfRes<()> {
        let old = format!("{}{:018}", c.path, id);
        fs::rename(&old, format!("{}{:018}", c.path, id2))?;
        debug!("Renamed {} to {}.", old, id2);
        log_err!(self.rm_file(id, c, false), "file RM");
        self.set_time_key(&c.convoid, b"file", id2, ts)?;
        Ok(())
    }

    //Handle file related session messages
    pub fn file_cmd(
        &mut self,
        src: &SocketAddr,
        reply: &mut Document,
        id: i64,
        convo: &mut Convo,
        doc: &Document,
        op: &str,
        sk: &SecKey,
    ) -> SfRes<()> {
        debug!("file_cmd {}", op);
        //new file {"f":"new","origid":[hmacsha256 of path,skey],meta:[client enc blob],locked:true}
        if op == "new" {
            let (fid, ts) = convo.new_fid(id, doc, reply, src, &self.db)?; //gets fid, dedups
            let flock = (src.clone(), Instant::now());
            convo.flocks.insert(fid, flock);
            // if locked file exists, nobody else ever can edit it; for sent, not shared files
            if doc.get_bool("locked").unwrap_or(false) {
                let lock_key = db_key(&convo.convoid, fid, b"lock");
                self.db.insert(&lock_key[..], b"")?;
            }
            self.update_space(convo, FILE_OVERHEAD)?;
            self.set_time_key(&convo.convoid, b"file", fid, ts)?;
            return Ok(());
        } else if op == "act" {
            let mut buf = [0; 1024]; //buffer to store which FID's are active
            let mut items = 0;
            let start = db_key(&convo.convoid, doc.get_i64("fid").unwrap_or(0), b"meta");
            let end = db_key(&convo.convoid, -1, b"meta");
            for r in self.db.range(&start[..]..&end[..]).keys() {
                let kbin = ok_or_continue!(r);
                if items >= 128 || kbin.len() != 32 + 4 + 8 {
                    break;
                }
                debug!("Found {}", i64::from_be_bytes(*array_ref![kbin, 36, 8]));
                buf[items * 8..(items + 1) * 8].copy_from_slice(&kbin[36..36 + 8]);
                items += 1;
            }
            *reply = doc! {"id": id, "res": binary_bson(&buf[..items*8])};
            return Ok(());
        }
        let fid = doc
            .get_i64("fid")
            .or_else(|_| convo.oid_fid(&self.db, doc.get_binary_generic("fidoid")?))?; //get fid
        let fpath = format!("{}{:018}", convo.path, fid);
        //Operations that don't require a lock
        match op {
            "met" => {
                //getmetadata: {"f":"met","fid":[fileid]} returns {"gm":[fid],"meta":{..}}
                debug!("{} reading metadata on {} (path {})", src, fid, fpath);
                let meta_key = db_key(&convo.convoid, fid, b"meta");
                if let Some(mbin) = self.db.get(&meta_key[..])? {
                    let met = binary_bson(&mbin[40..]); //skip OID (32 bytes) and timestamp (8)
                    let lock_key = db_key(&convo.convoid, fid, b"lock");
                    let lck = self.db.contains_key(&lock_key[..])?;
                    *reply = doc! {"id": id, "gm": fid, "meta": met, "del": false, "lock": lck};
                    if let Ok(m) = fs::metadata(&fpath) {
                        reply.insert("size", m.len() as i64);
                    }
                } else if convo.fid > fid {
                    *reply = doc! {"id": id, "gm": fid, "del": true};
                }
                return Ok(());
            }
            "cls" => {
                let sid = doc.get_i64("sid")?; //Close stream sid
                let s = convo.sessions.get_mut(src).ok_or_else(sfnone)?; //it's there, we checked
                if let Some(notice) = s.rm_stream(sid, true) {
                    log_err!(self.send(None, doc! {"e":notice,"q":convo.seq}, convo), "");
                }
                *reply = doc! {"id": id, "cls": sid}; //Send closed response
                return Ok(());
            }
            "lck" => {
                convo.file_lock(src, fid, &self.db)?;
                *reply = doc! {"id": id, "lck": fid};
                return Ok(());
            }
            "res" => {
                let mkey = db_key(&convo.convoid, fid, b"meta");
                let s = convo.sessions.get_mut(src).ok_or_else(sfnone)?; //it's there, we checked
                if let Some(strid) = s.streamsrev.get(&fid) {
                    if let Some(&(Stream::Reader(_), _, _)) = s.streams.get(strid) {
                        *reply = doc! {"id": id, "res": *strid}; //resend for duplicate req's
                        return Ok(());
                    }
                }
                let offset = doc.get_i64("off").unwrap_or(0); //start read stream at offset
                debug!("{} starting read stream {} off {}", src, fid, offset);
                let fopres = File::open(&fpath).map_err(|e| SfErr::IoErr(e));
                return Ok(fopres.and_then(|mut f| {
                    f.seek(io::SeekFrom::Start(offset as u64))?;
                    let nb = s.streams.iter().next_back(); //new sid = highest valid sid + 1
                    let sid = nb.map(|s| s.0 + 1).unwrap_or(1); // or just 1
                    let rdr = Stream::Reader(ReadStream::new(sid, f, s.rttms));
                    let tube = Tube::sock_clone((&self.sock, src.clone()));
                    s.streams.insert(sid, (rdr, tube, Some(fid)));
                    s.streamsrev.insert(fid, sid);
                    let a = Arc::clone(&self.clis.get(src).ok_or_else(sfnone)?.1);
                    let (k, sadd, rttms) = (sk.clone(), src.clone(), s.rttms);
                    let meta = self.db.get(&mkey[..])?.ok_or_else(sfnone)?;
                    spawn_thread("streamdn", move || streamdown(a, rttms, k, sid, sadd));
                    *reply = doc! {"id": id, "res": sid, "meta": binary_bson(&meta[40..])};
                    Ok(())
                })?);
            }
            _ => {}
        }
        //Below here are ops which require a locked file
        if !convo.has_flock(fid, src) {
            info!("{} trying file op {} but does not have lock!", src, op);
            *reply = doc! {"f":"error", "info": "no lock", "id": id};
            // if ume and breadcrumbs match, it's a move file retransmit. Resend same new fid.
            if op == "ume" {
                let origid = leneq(doc.get_binary_generic("origid")?, 32)?;
                if let Some(newfid) = convo.moves.get(&fid).map(|f| *f) {
                    if convo.has_flock(newfid, src) {
                        *reply = doc! {"id": id, "fid": newfid, "origid":binary_bson(origid)};
                    }
                }
            }
            return Err(SfErr::LockFailed); //Bail now
        }
        match op {
            "del" => {
                self.rm_file(fid, convo, true)?;
                *reply = doc! {"id": id, "dls": fid};
                self.send(None, doc! {"e":{"op":"del","fid":fid},"q":convo.seq}, convo)
                    .map(|_| ())
            }
            "wrs" => {
                let s = convo.sessions.get_mut(src).ok_or_else(sfnone)?; //it's there
                if let Some(strid) = s.streamsrev.get(&fid) {
                    if let Some(&(Stream::Writer(_), _, _)) = s.streams.get(strid) {
                        *reply = doc! {"id": id, "wrs": *strid}; //resend for duplicate req's
                        return Ok(());
                    }
                }
                let offset = doc.get_i64("off").unwrap_or(0);
                debug!("{} starting write stream {} off {}", src, fid, offset);
                let mut opener = OpenOptions::new();
                let mut f = opener.read(true).write(true).truncate(false).open(&fpath)?;
                f.seek(io::SeekFrom::Start(offset as u64))?;
                let nb = s.streams.keys().next_back(); //new sid = highest valid sid + 1
                let sid = nb.map(|n| *n + 1).unwrap_or(1); // or just 1
                let overlap = fs::metadata(&fpath).map(|m| m.len()).unwrap_or(0) as i64;
                let writer = Stream::Writer(WriteStream::new(sid, f, overlap, offset));
                let tube = Tube::sock_clone((&self.sock, src.clone()));
                s.streams.insert(sid, (writer, tube, Some(fid)));
                s.streamsrev.insert(fid, sid);
                debug!("Write stream started; fid {} sid {}", fid, sid);
                *reply = doc! {"id": id, "wrs": sid};
                Ok(())
            }
            "trc" => {
                debug!("{} truncating {}", src, fid);
                let newlen = self.truncate_file(fid, doc.get_i64("len")?, convo)?;
                *reply = doc! {"id": id, "trc": newlen}; //Truncated file new len
                Ok(())
            }
            "ume" => {
                debug!("{} updating metadata on {}", src, fid); //sets new metadata (renames)
                let fidoid = leneq(doc.get_binary_generic("fidoid")?, 32)?;
                //If this is an overwrite, delete the target file
                if let Ok(delfid) = convo.oid_fid(&self.db, doc.get_binary_generic("origid")?) {
                    convo.file_lock(src, delfid, &self.db)?;
                    self.rm_file(delfid, convo, true)?;
                }
                let (newfid, ts) = convo.new_fid(id, doc, reply, src, &self.db)?;
                //meta is safe to unwrap now because it's checked in new_fid
                let meta = doc.get_binary_generic("meta").unwrap();
                convo.moves.insert(fid, newfid); // leave breadcrumbs
                convo.moverev.insert(newfid, fid);
                self.mov(convo, fid, newfid, ts)?;
                let flock = (src.clone(), Instant::now());
                convo.flocks.insert(newfid, flock);
                let (oid, met) = (binary_bson(fidoid), binary_bson(meta));
                let notice_msg = doc! {
                    "e": {"op": "ume", "fid": fid, "newfid": newfid, "meta": met, "oid": oid},
                    "q": convo.seq,
                };
                self.send(None, notice_msg, convo).map(|_| ())
            }
            "ulk" => {
                debug!("{} unlocking {}", src, fid); //Unlock msg: {"f":"ulk","fid":[fileid]}
                convo.rmflock(fid);
                *reply = doc! {"id": id, "ulk": fid};
                Ok(())
            }
            _ => {
                Err(SfErr::InvalidOp) //unknown command
            }
        }
    }

    fn truncate_file(&mut self, fid: i64, len: i64, convo: &mut Convo) -> SfRes<i64> {
        let fpath = format!("{}{:018}", convo.path, fid);
        let freed = fs::metadata(&fpath)?.len() as i64 - len;
        if freed < 0 || len < 0 {
            return Err(SfErr::InvalidOp);
        }
        let f = OpenOptions::new().write(true).open(&fpath)?;
        f.set_len(len as u64)?; //do the real truncation
        self.update_space(convo, 0 - freed)?;
        Ok(len)
    }

    fn rm_file(&mut self, fid: i64, convo: &mut Convo, contents: bool) -> SfRes<()> {
        debug!("deleting fid {}", fid);
        if let Some(v) = self.db.remove(&db_key(&convo.convoid, fid, b"meta")[..])? {
            self.db
                .remove(&db_id(&convo.convoid, b"oid_", array_ref![v, 0, 32])[..])?; //Remove OID
            self.rm_time_key(&convo.convoid, b"file", fid, *array_ref![v, 32, 8])?;
        }
        self.db.remove(&db_key(&convo.convoid, fid, b"lock")[..])?;
        let fpath = format!("{}{:018}", convo.path, fid);
        if contents {
            let freed = FILE_OVERHEAD + fs::metadata(&fpath)?.len() as i64;
            log_err!(fs::remove_file(&fpath), "rm");
            self.update_space(convo, 0 - freed)?;
        }
        Ok(convo.rmflock(fid)) //delete msg also removes lock
    }

    //Makes a new chat or loads it from disk/DB
    pub fn newchat(&mut self, cid: &ConvoId, primary: bool, seq: i64) -> Arc<Mutex<Convo>> {
        //Create the session and add to clients/convos maps
        let fold = Path::new(&self.ctxt.workdir).join(b64spk(&cid).as_str());
        info!("Chat {} d {}", primary, fold.to_str().unwrap_or("invalid"));
        let mut conv = Convo {
            sessions: HashMap::new(),
            seq: seq,
            convoid: cid.clone(),
            path: format!("{}/", fold.to_str().unwrap_or(".")),
            fid: 0,
            primary: primary,
            flocks: BTreeMap::new(),
            moves: BTreeMap::new(),
            moverev: BTreeMap::new(),
        };
        let cash = &self.ctxt.cache;
        if let Err(e) = fs::create_dir(&fold) {
            info!("Existing convo fdir? {}", e); //Convo already existed? find seq/fid
            conv.seq = db_next_id(cash, &conv.convoid, b"mesg");
            conv.fid = db_next_id(cash, &conv.convoid, b"meta");
        }
        let mut p = if primary { [1; 9] } else { [0; 9] };
        (&mut p)[1..].copy_from_slice(&seq.to_be_bytes()[..]);
        log_err!(cash.insert(&db_id(cid, b"prim", &[0; 32]), &p), "");
        let convo_arc = Arc::new(Mutex::new(conv));
        self.convos.insert(cid.clone(), Arc::clone(&convo_arc));
        convo_arc
    }

    fn get_convo_primary_seq(&self, cid: &ConvoId) -> SfRes<(bool, i64)> {
        let copt = self.ctxt.cache.get(&db_id(cid, b"prim", &[0; 32])[..])?;
        let cval = copt.ok_or(NoneErr)?;
        leneq(&cval, 9)?;
        Ok((cval[0] != 0, i64::from_be_bytes(*array_ref![cval, 1, 8])))
    }

    //We're a backup but now need to take over as master
    fn promo(&mut self, d: Document, a: &SocketAddr, c: &mut Convo, r: &mut Document) -> SfRes<()> {
        let s = d.get_binary_generic("promote")?;
        let backs = d.get_binary_generic("backups")?;
        debug!("{} promo", b64spk(&c.convoid));
        let sig = leneq(wr_crypto_sign_open_inplace(&s, &c.convoid)?, DBK_LEN)?; //signed by convo
        if &sig[..36] != &db_key(&self.ctxt.keys.sign.pk, 0, b"host")[..36] {
            warn!("Promote request {} not for us?", b64spk(&c.convoid));
            return Err(SfErr::BadSignatureErr); //Signed message must say we are host
        }
        let promo_seq = i64::from_be_bytes(*array_ref![sig, 36, 8]);
        let hash = wr_crypto_hash_sha256(&s);
        let hk = db_id(&c.convoid, b"hash", &hash);
        let mut old_or_duplicate_request = false;
        if let Ok((prim, last_seq)) = self.get_convo_primary_seq(&c.convoid) {
            if !prim && last_seq >= promo_seq {
                warn!("{} promo {} >= {}", b64spk(&c.convoid), last_seq, promo_seq);
                return Err(SfErr::BadSignatureErr); //Signed message was from before our current val
            } else if prim && last_seq >= promo_seq {
                old_or_duplicate_request = true;
            }
        }
        let seqi64 = if let Some(id) = self.db.get(&hk[..])? {
            debug!("Re-acking promo retrans {}", b64spk(&hash)); //promotion already in DB
            bytes_to_u64(leneq(&id, 8)?) as i64
        } else if !old_or_duplicate_request {
            info!("Convo {} promoted at {}", b64spk(&c.convoid), promo_seq);
            let primkey = db_id(&c.convoid, b"prim", &[0; 32]);
            let mut sig = sig.to_vec(); //make a mutable copy
            sig[35] = 1; // set the prim key to be [1, 8 bytes of big endian sequence number]
            log_err!(self.ctxt.cache.insert(&primkey, &sig[35..]), "DB promoting");
            c.primary = true; //This will also trigger a backup sync thread to stop
            setup_backups(c.convoid.clone(), &self.ctxt, backs, s);
            self.db.insert(&hk[..], &u64_bytes(promo_seq as u64))?;
            let rdoc = doc! {"e":{"op":"promote", "inner":d}, "q":c.seq};
            self.send(Some(a), rdoc, c)? //returns seq
        } else {
            warn!("Forgotten promo{} for {}?", promo_seq, b64spk(&c.convoid));
            return Err(SfErr::BadMessage);
        };
        r.insert("a", binary_bson(&hash)); //return ack
        r.insert("n", seqi64);
        Ok(())
    }

    //We've been asked to backup a convo. We'll start our own backup thread to join and mirror
    fn back(&mut self, d: Document, src: SocketAddr, bk: &BoxPKey, s: &SignPKey, r: &mut Document) {
        let ct = d.get_binary_generic("cid").map_err(|e| SfErr::ValErr(e));
        ct.and_then(|cidb| {
            let cid: ConvoId = copy_to_array(&leneq(cidb, 32)?[0..32]); //get convo ID
            let signed = d.get_binary_generic("sig")?;
            let port = d.get_i32("np")? as u16;
            let sig = leneq(wr_crypto_sign_open_inplace(signed, &cid)?, DBK_LEN)?; //verify signature
            if &sig[..36] != &db_key(s, 0, b"host")[..36] {
                return Err(SfErr::BadSignatureErr); //not a signed message they host the convo.
            }
            let newseq = i64::from_be_bytes(*array_ref![sig, 36, 8]); //the signature sequence #
            let old = self.get_convo_primary_seq(&cid); //old info if we already had the convo
            if old.as_ref().map(|(_, seq)| *seq > newseq).unwrap_or(false) {
                return Err(SfErr::BadSignatureErr); //deny attempts to override with an older sig
            }
            let mut _temp_holder = None; //dummy var just to extend lifetime of newchat convo
            let (convo, newbk) = if let Some(c) = self.convos.get(&cid) {
                let (old_primary, _) = old?; // convo existed, unwrap info about it
                let moving = old_primary || (src, *bk) != backup_addr_and_key(&self.ctxt, &cid)?;
                if old_primary {
                    c.lock()?.primary = false; // we're no longer primary; we've been demoted
                }
                (c, moving) //moving/newbk = whether we are changing our convo mode or backup host
            } else {
                _temp_holder = Some(self.newchat(&cid, false, newseq)); //create or reload the chat
                (_temp_holder.as_ref().unwrap(), true) //overrides primary flag if signed update
            };
            if newbk {
                let src_srv = SocketAddr::new(src.ip(), port);
                set_backup_addr_and_key(&self.ctxt, &cid, &src_srv, bk); //Set sync info in DB
                let (ctxt, conv) = (Arc::clone(&self.ctxt), Arc::clone(convo));
                let (tk, snd) = (self.totl_key.clone(), self.local_sndr.clone()); //start sync thread
                spawn_thread("chatmirr", move || sync(ctxt, &tk[..], conv, snd));
            }
            *r = doc! {"rsp":"good"};
            Ok(())
        })
        .unwrap_or_else(|e: SfErr| warn!("bad back {}", e));
    }

    //Client connecting to a listen
    fn openchat(&mut self, mut doc: Document, src: &SocketAddr, spk: &SignPKey, r: &mut Document) {
        let bups = doc.remove("backups");
        let t = doc.get_binary_generic("tgt").map_err(|e| SfErr::ValErr(e));
        t.and_then(|tgtkeyb| {
            //Create a new conversation by connecting to a meet listener
            let tgt: SignPKey = copy_to_array(leneq(tgtkeyb, CRYPTO_SIGN_PUBLICKEYBYTES)?);
            let cid = copy_to_array(leneq(doc.get_binary_generic("cid")?, 32)?);
            debug!("Looking for meet listener. {}", b64spk(&tgt));
            let meet = self.meets.get_mut(&tgt).ok_or(SfErr::BadMeet)?;
            if self.clis.contains_key(&src) {
                let k = binary_bson(&self.clis.get(&src).unwrap().0[..]);
                *r = doc! {"rsp":"good", "k": k, "disp_name_enc": binary_bson(&meet.disp_name_enc)};
                return Err(SfErr::DuplicateChatMeet); //already connected, resend
            }
            let handshake = doc.get_binary_generic("handshake")?;
            let partid = leneq(doc.get_binary_generic("partid")?, PIDLEN)?; //enced participant ID
            let signed = doc.get_binary_generic("sig")?;
            let sig = leneq(wr_crypto_sign_open_inplace(signed, &cid)?, DBK_LEN)?;
            if &sig[..36] != &db_key(&self.ctxt.keys.sign.pk, 0, b"host")[..36] {
                return Err(SfErr::BadSignatureErr); //either not for us or not a signed host message
            }
            let prim_key = db_id(&cid, b"prim", &[0; 32]);
            if self.ctxt.cache.contains_key(&prim_key)? {
                *r = doc! { "err": "convo already existed" }; // Can't recreate it - already there
                return Err(SfErr::DuplicateChatMeet);
            }
            let seq = i64::from_be_bytes(*array_ref![sig, 36, 8]); //at what sequence are we host?
            let stube = Tube::sock_clone((&self.sock, src.clone()));
            let sess = Session::new(&doc, *&cid, &self.db, *spk, true, stube);
            let rtt = meet.rtt;
            if let Some(Bson::Binary(_, backups)) = bups {
                setup_backups(cid.clone(), &self.ctxt, &backups, signed); //Start backups
            }
            //now that we own the lock, we insert into the pending map
            let mut pending_conns = meet.pending_conns.lock()?;
            pending_conns.insert(cid.clone(), handshake.to_vec());
            //Tell the listener if one is alive that a connection is inbound
            if meet.lastpolled.elapsed() < secs(60) {
                let pcs = Arc::clone(&meet.pending_conns);
                let thread_tube = Tube::sock_clone((&self.sock, meet.saddr.clone()));
                let msgd = doc! { "h": binary_bson(&handshake), "cid": binary_bson(&cid) };
                let msgenc = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&msgd), &meet.key);
                spawn_thread("openchat", move || {
                    let mut rts = 0; //retransmits
                    while pcs.lock().map(|p| p.contains_key(&cid)).unwrap_or(false) && rts < 5 {
                        log_err!(thread_tube.send(&msgenc), "tts");
                        thread::park_timeout(rtt * 2); //Wait 2 RTTs for ack before retransmit
                        rts += 1;
                    }
                })
            } else {
                warn!("No recent listen for {:X}!", doc.get_i64("id").unwrap_or(0));
            }
            let k = binary_bson(&sess.key);
            *r = doc! {"rsp":"good", "k": k, "disp_name_enc": binary_bson(&meet.disp_name_enc)};
            drop(pending_conns);
            drop(meet);
            let convo = self.newchat(&cid, true, seq); //make the new chat and insert it
            let skey = sess.key.clone();
            convo.lock()?.add_session(partid, self, src.clone(), sess);
            self.clis.insert(src.clone(), (skey, convo));
            Ok(())
        })
        .unwrap_or_else(|e: SfErr| warn!("bad openchat {}", e));
    }

    // Starts a new forward
    fn fwd(&mut self, doc: &Document, sa: &SocketAddr, rsp: &mut Document) {
        let areb = doc.get_binary_generic("addr").map_err(|e| SfErr::ValErr(e));
        areb.and_then(|addrb| {
            let addrlenchecked = array_ref![leneq(addrb, 19)?, 0, 19];
            let addr = debin_addr(addrlenchecked);
            if let Some(t) = self.tunnels.get_mut(sa) {
                if let Ok(tnumi32) = doc.get_i32("tnum") {
                    let tnum = tnumi32 as usize;
                    if tnum < MAX_TUNNELS {
                        let (tup, flg1, tdwn, flg2) = newf(addr, tnum)?;
                        t.fwds[tnum] = Some((tup, flg1));
                        if let Ok(sndr) = t.sender.clone_sender() {
                            spawn_thread("forwardw", move || dumb_fwd(tdwn, sndr, flg2, true));
                        }
                    }
                }
            } else {
                //control (channel 0)
                let ctrlflg = Arc::new(AtomicBool::new(true));
                let ctrlflg2 = Arc::clone(&ctrlflg);
                //wad (crypto forwarding underneath all channels)
                let (waddwn, waddwn2) = Tube::pair(false); //unwrapped but tagged channel
                let wad_raw = Tube::sock_clone((&self.sock, sa.clone())); //raw reply channel
                let fskeyb = leneq(doc.get_binary_generic("key")?, CRYPTO_SECRETBOX_KEYBYTES)?;
                let wad_key: SecKey = copy_to_array(fskeyb);
                spawn_thread("forwardc", move || {
                    tube_wrap(waddwn2, wad_raw, &wad_key, ctrlflg2)
                });
                //new data channel (channel 1)
                let (tup, flg1, tdwn, flg2) = newf(addr, 1)?; //tdwn = tag-added channel down
                let t = Tunnel {
                    key: copy_to_array(fskeyb),
                    fwds: [
                        Some((waddwn.clone_sender()?, ctrlflg)),
                        Some((tup, flg1)),
                        None,
                        None,
                    ],
                    last_seen: Instant::now(),
                    sender: waddwn.clone_sender()?,
                };
                self.tunnels.insert(sa.clone(), t);
                //spawn forwarder thread for channel 1 (data channel)
                spawn_thread("forwardw", move || dumb_fwd(tdwn, waddwn, flg2, true));
            }
            *rsp = doc! { "rsp": "good" }; // our response might have been dropped. Resend it.
            Ok(())
        })
        .unwrap_or_else(|e| error!("ERROR fwd {}", e)); //Print error details
    }

    //Ends a forward
    fn fwdclose(&mut self, addr: &SocketAddr, resp: &mut Document, tnum: i32) {
        if let Some(tun) = self.tunnels.get_mut(addr) {
            debug!("Removing tunnel {} from {}", tnum, addr);
            if (tnum as usize) < tun.fwds.len() && tnum > 0 {
                if let Some((_t, flg)) = tun.fwds[tnum as usize].as_ref() {
                    flg.store(false, Relaxed);
                }
                tun.fwds[tnum as usize] = None;
            } else if tnum == 0 {
                debug!("Closing all tunnels from {}", addr);
                for tn in 0..tun.fwds.len() {
                    if let Some((_t, flg)) = tun.fwds[tn].as_ref() {
                        flg.store(false, Relaxed);
                    }
                }
                self.tunnels.remove(addr);
            }
        }
        *resp = doc! { "rsp": "good" }; //either just shut down the forward, or it was already down
    }

    // Asks the node to accept new conversations and hold them for the client
    //at some point these will probably be stored on disk. Right now though, mem it is
    //meets is key -> map of pending cnx, srckey -> [chatid, sockaddr]
    fn listen(&mut self, doc: &Document, resp: &mut Document, rk: SignPKey, s: &SocketAddr) {
        let notb = doc.get_binary_generic("notice"); //get signed blob
        let notr = notb.map_err(|_| sfnone());
        notr.and_then(|notic| {
            let rtti64 = doc.get_i32("rtt").unwrap_or(250).max(10).min(1000);
            let rtt = Duration::from_millis(rtti64 as u64);
            let mkey = leneq(doc.get_binary_generic("key")?, CRYPTO_SECRETBOX_KEYBYTES)?;
            let diskey = wr_crypto_blind_ed25519_public_key(&rk, "disc");
            // if it was properly signed and is a meet notice
            let meetaddr = if let NodeAddr::Meet(m) = parse_binaddr(notic, &diskey)? {
                m
            } else {
                return Err(SfErr::BadMeet);
            };
            if meetaddr.meet_host != self.ctxt.keys.sign.pk {
                return Err(SfErr::BadMeet); //and that meet notice better be for us
            }
            //their time since unix epoch is in the notice. Make sure it's sane.
            let dur = meetaddr.released.duration_since(UNIX_EPOCH).unwrap();
            let their_timediff = dur.as_secs() as i64;
            let my_timediff = UNIX_EPOCH.elapsed().unwrap().as_secs() as i64;
            if (my_timediff - their_timediff).abs() > CLOCK_TOLERANCE_SECS {
                *resp = doc! { "err": "time", "time": binary_bson(&now_as_bin_seconds())};
                return Err(SfErr::BadTime); //maybe replaying an old notice?
            }
            info!("Listen for {} ({})", b64spk(&rk), b64spk(&diskey));
            *resp = doc! { "rsp": "good" };
            let pending = if let Some(o) = self.meets.remove(&rk) {
                if o.saddr == *s && o.key[..] == *mkey && o.lastpolled.elapsed() < rtt * 2 {
                    self.meets.insert(rk, o); //duplicate listen; just put back the old listener
                    return Ok(()); //and resend the response
                }
                if o.pending_conns.lock().map(|p| p.len() > 0).unwrap_or(false) {
                    let pcs = Arc::clone(&o.pending_conns); //there are still pending conns
                    let thread_tube = Tube::sock_clone((&self.sock, s.clone()));
                    let key = copy_to_array(mkey); //spawn thread to resend their notices
                    spawn_thread("syncpend", move || {
                        let mut rts = 0; //retransmits allowed
                        while pcs.lock().map(|p| p.len() > 0).unwrap_or(false) && rts < 5 {
                            debug!("syncpend sending");
                            for (cid, hndsh) in pcs.lock().unwrap().iter() {
                                let m = doc! {"h": binary_bson(hndsh), "cid": binary_bson(cid)};
                                let msgenc = wr_crypto_secretbox_easy(&bdoc_to_u8vec(&m), &key);
                                log_err!(thread_tube.send(&msgenc), "tts");
                            }
                            thread::park_timeout(rtt * 2); //Wait 2 RTTs for ack before retrans
                            rts += 1;
                        }
                        debug!("syncpend done {} rts", rts)
                    });
                }
                o.pending_conns //keep old pending connections
            } else {
                Arc::new(Mutex::new(HashMap::new()))
            };
            let l = MeetListen {
                key: copy_to_array(mkey),
                saddr: s.clone(),
                pending_conns: pending,
                lastpolled: Instant::now(),
                rtt: rtt,
                disp_name_enc: doc.get_binary_generic("de")?.to_vec(),
            };
            self.meets.insert(rk, l);
            let new_meet_host = meetaddr.meet_host.clone();
            //and add to nodes to distribute through the network
            let n = Node {
                key: diskey.clone(),
                bkey: wr_crypto_sign_pk_to_box(&diskey),
                address: NodeAddr::Meet(meetaddr),
            };
            let oldn = self.ctxt.get_node(&diskey);
            log_err!(self.ctxt.set_node(&diskey, n), "Setting node");
            //decide whether to announce
            if let Ok(n) = oldn {
                if let NodeAddr::Meet(oldmeet) = n.address {
                    if oldmeet.meet_host == new_meet_host {
                        let odur = oldmeet.released.duration_since(UNIX_EPOCH).unwrap();
                        let old_timediff = odur.as_secs() as i64;
                        if (old_timediff - their_timediff).abs() < CLOCK_TOLERANCE_SECS {
                            return Ok(()); //don't re-announce if we just announced.
                        }
                    }
                }
            }
            let ctxclone = Arc::clone(&self.ctxt);
            let noticb = binary_bson(notic);
            let respkb = binary_bson(&diskey[..]);
            let mut next_node = diskey; //push the node announcement to next few nodes
            spawn_thread("announce", move || {
                let mut firstk = None; //but do those in a new thread
                for _ in 0..5 {
                    if firstk.iter().next().map_or(false, |fk| *fk == next_node) {
                        break; //break if we wrapped around and are back where we started
                    }
                    increment_spkey(&mut next_node);
                    if let Some(nextn) = ctxclone.nextnode_wrap(&next_node) {
                        next_node = nextn.key;
                        debug!("Forwarding notice to {}", b64spk(&next_node));
                        if firstk.is_none() {
                            firstk = Some(next_node.clone()) // remember the first node
                        }
                        let msg = doc! {
                            "fnc": "nodeannounce",
                            "ba":noticb.clone(),
                            "pk":respkb.clone()
                        };
                        if let Err(e) = Tube::udp_connect(&nextn.address)
                            .and_then(|tube| do_rpc(msg, &tube, &nextn.bkey, &ctxclone.keys))
                        {
                            info!("notice fwd err {}", e);
                        }
                    }
                }
            });
            Ok(())
        })
        .unwrap_or_else(|e| warn!("ERROR listen {}", e));
    }

    // Mark a pending connection as acked
    fn meetack(&mut self, doc: &Document, respkey_s: SignPKey, rsp: &mut Document) {
        let rm = self.meets.get_mut(&respkey_s).ok_or_else(sfnone);
        rm.and_then(|listener| {
            listener.lastpolled = Instant::now(); // update lastpolled
            let cidb = doc.get_binary_generic("cid")?;
            let cid: ConvoId = copy_to_array(leneq(cidb, CRYPTO_SIGN_PUBLICKEYBYTES)?);
            if let Ok(mut pconns) = listener.pending_conns.lock() {
                let rm = pconns.remove(&cid).is_some(); // Remove acked pending con if present
                debug!("meetack removed? {}", rm);
                *rsp = doc! { "rsp": "good" }; // our response might have been dropped. Resend it.
            }
            Ok(())
        })
        .unwrap_or_else(|e| error!("ERROR meetack {}", e));
    }

    //Client connects to an existing conversation
    fn join(&mut self, d: &Document, a: &SocketAddr, k: &SignPKey, bk: &BoxPKey, r: &mut Document) {
        let cr = d.get_binary_generic("cid").map_err(|e| SfErr::ValErr(e));
        cr.and_then(|cidbraw| {
            let mut _temp_holder = None; //just to extend lifetime of newchat convo
            let cid = array_ref![leneq(cidbraw, 32)?, 0, 32];
            let partid = leneq(d.get_binary_generic("partid")?, PIDLEN)?; //participant ID (enc)
            let bkey = db_id(cid, b"bknd", bk); //key to query to see if we allow backup joins
            let backup = self.ctxt.cache.contains_key(&bkey[..]) == Ok(true);
            let pkey = if backup { k } else { cid }; //whose signature we're checking-backup node or cid
            let sig = d.get_binary_generic("sig")?;
            let sig = wr_crypto_sign_open_inplace(sig, pkey)?;
            if &sig[..32] != &self.ctxt.keys.bx.pk[..] || &sig[32..36] != b"join" {
                return Err(SfErr::BadSignatureErr); //otherwise they must have the key to join
            }
            let convo = if let Some(s) = self.convos.get(cid) {
                s
            } else if let Some(primval) = self.ctxt.cache.get(&db_id(cid, b"prim", &[0; 32])[..])? {
                let primary = leneq(&primval, 9)?[0] == 1; //check length and whether primary
                let seq = i64::from_be_bytes(*array_ref![primval, 1, 8]); //extract sequence #
                _temp_holder = Some(self.newchat(cid, primary, seq)); //reload the chat
                _temp_holder.as_ref().unwrap()
            } else {
                warn!("Joinchat for {} but we don't have that convo", b64spk(cid));
                *r = doc! { "err": "Conversation not found" }; // displayable err
                return Err(sfnone());
            };
            //Get permanent participants from DB keys
            let mut partsbson = Vec::new(); // get participants list
            for k in self.db.scan_prefix(&db_key(cid, 0, b"prid")[..36]).keys() {
                k.ok().map(|kbin| partsbson.push(binary_bson(&kbin[32 + 4..]))); // add participant
            }
            if self.clis.contains_key(a) {
                debug!("Duplicate chat meet open req from {}", a); //already done; resend accept
                let sess = self.clis.get(a).ok_or_else(sfnone)?;
                if Arc::ptr_eq(convo, &sess.1) {
                    *r = doc! {"rsp":"good", "chatkey": binary_bson(&sess.0[..]), "participants": partsbson};
                }
            } else {
                let stube = Tube::sock_clone((&self.sock, a.clone()));
                let sess = Session::new(d, *cid, &self.db, *k, !backup, stube); //register us
                let k = sess.key.clone(); //new session; new key
                let convo = Arc::clone(convo); //get us an owned one
                convo.lock()?.add_session(partid, self, a.clone(), sess);
                *r = doc! {"rsp":"good", "chatkey": binary_bson(&k[..]), "participants": partsbson};
                if convo.lock()?.primary {
                    let rang = self.ctxt.cache.scan_prefix(&db_key(cid, 0, b"bknd")[..36]);
                    let backups = rang.filter_map(|b| b.ok().map(|kv| binary_bson(&kv.1)));
                    (*r).insert("backups", backups.collect::<Vec<Bson>>());
                }
                self.clis.insert(a.clone(), (k, convo));
                info!("Meet join accepted to {}", b64spk(cid));
            }
            if let Ok(Some(signed)) = self.ctxt.cache.get(&db_key(cid, 0, b"sigh")) {
                debug!("Adding signed host attestation...");
                (*r).insert("sig", binary_bson(&signed));
            }
            Ok(())
        })
        .unwrap_or_else(|e: SfErr| warn!("bad joinchat {}", e));
    }

    fn trim_tunnels(&mut self) {
        let mut tuns_to_del = Vec::new();
        for (tkey, tval) in self.tunnels.iter() {
            if tval.last_seen.elapsed() > Duration::from_secs(300) {
                tuns_to_del.push(tkey.clone());
            }
        }
        for tkey in tuns_to_del {
            self.tunnels.remove(&tkey).map(|tn| {
                for f in &tn.fwds {
                    f.as_ref().map(|(_t, flg)| flg.store(false, Relaxed));
                }
            });
        }
    }
}

//Join and wrap a connection directly
type Wrapped = (Tube, Arc<AtomicBool>);
fn jwrap(cid: &ConvoId, sa: &SocketAddr, b: &BoxPKey, k: &Keys, db: &Db) -> SfRes<Wrapped> {
    let tub = Tube::udp_connect(&sa)?;
    let pid = binary_bson(&[0; PIDLEN]); //we're not real people
    let meetjoin = db_key(b, 0, b"join");
    let s = binary_bvec(wr_crypto_sign(&meetjoin[..36], &k.sign.sk)); //sig
    let data = doc! {"fnc": "joinchat", "cid": binary_bson(cid), "partid": pid, "sig": s}; //"rtt"?
    let (doc, rtt) = do_rpc(data, &tub, b, k)?;
    info!("sync monitor {} rtt {}", b64spk(cid), rtt);
    let ck = doc.get_binary_generic("chatkey")?;
    let (wrapd, fl) = wrapping_tubepair(copy_to_array(leneq(ck, CRYPTO_SECRETBOX_KEYBYTES)?), tub)?;
    wrapd.set_timeout(secs(16))?; //16s timeout because servers have time
    if let Ok(participantsarr) = doc.get_array("participants") {
        for partbson in participantsarr {
            if let bson::Bson::Binary(_bt, pid) = partbson {
                if pid.len() == PIDLEN {
                    let prid_key = db_plkey(&cid, b"prid", array_ref![pid, 0, PIDLEN]);
                    log_err!(db.insert(&prid_key, b""), "save sync parts"); //save participants
                }
            }
        }
    }
    Ok((wrapd, fl))
}

//Key used in time order DB series to keep track of oldest stuff in DB
fn time_key(tkey: &[u8], c: &ConvoId, data_type: &[u8; 4], seq: i64, ts: [u8; 8]) -> [u8; 88] {
    let mut msg_k = [0; 32 + 4 + 8 + 32 + 4 + 8]; //secret "time" [big endian] [cid] "mesg" seq
    (&mut msg_k[0..32]).copy_from_slice(&tkey[0..32]); //private DB info code
    (&mut msg_k[32..36]).copy_from_slice(b"time"); //(time)
    (&mut msg_k[36..44]).copy_from_slice(&ts); //timestamp - big endian epoch microseconds
    (&mut msg_k[44..76]).copy_from_slice(c); //cid
    (&mut msg_k[76..80]).copy_from_slice(data_type); //type of data "mesg" or "file"
    (&mut msg_k[80..88]).copy_from_slice(&u64_bytes(seq as u64)); // sequence number
    msg_k
}

fn set_backup_addr_and_key(ctxt: &Context, cid: &ConvoId, sa: &SocketAddr, bpk: &BoxPKey) {
    let mut bki = [0; 19 + 32]; //store backup information (src address & key)
    (&mut bki[..19]).copy_from_slice(&sockaddr_to_bin(sa));
    (&mut bki[19..]).copy_from_slice(bpk);
    let primid = db_id(&cid, b"prim", &[1; 32]);
    log_err!(ctxt.cache.insert(&primid, &bki[..]), "sbaak");
}
fn backup_addr_and_key(ctxt: &Context, cid: &ConvoId) -> SfRes<(SocketAddr, BoxPKey)> {
    let p = ctxt.cache.get(&db_id(&cid, b"prim", &[1; 32])[..])?; // load address/boxkey from DB
    let inf = p.ok_or_else(sfnone)?; //primary server address then server box key
    leneq(&inf, BIN_SOCKADDR_LEN + 32)?; //verify length
    Ok((debin_addr(array_ref![inf, 0, 19]), *array_ref![inf, 19, 32]))
}

// Thread to sit on the local end of a convo backup sync connection and cache it
fn sync(ctxt: Context, k: &[u8], convo: Arc<Mutex<Convo>>, snd: Sender<Sync>) -> SfRes<()> {
    let cid = convo.lock()?.convoid.clone();
    let (addr, bkey) = backup_addr_and_key(&ctxt, &cid)?;
    let (mut tube, mut flag) = jwrap(&cid, &addr, &bkey, &ctxt.keys, &ctxt.cache)?;
    //Figures out which acks we have already cached by enumerating DB keys
    let mut acks = Vec::new();
    let prefix = db_key(&cid, 0, b"mesg");
    for k_result in ctxt.cache.scan_prefix(&prefix[..36]).keys() {
        let dbk = ok_or_continue!(k_result);
        if dbk.len() == 32 + 8 + 4 && dbk[40..44] == *b"mesg" {
            update_acks(&mut acks, bytes_to_u64(&dbk[32..40]) as i64);
        }
    }
    let mut stream_opens = BTreeMap::new(); //for callid -> (fid, open blob) calls
    let mut streams = BTreeMap::new();
    let mut lastping = Instant::now();
    let mut last_rcvd_or_tried = Instant::now();
    let mut force_ack = true; //on first start, always send ping
    while !convo.lock()?.primary && (addr, bkey) == backup_addr_and_key(&ctxt, &cid)? {
        if last_rcvd_or_tried.elapsed() > Duration::new(60 * 5, 0) {
            warn!("sync lost {} attempting reconnect", b64spk(&cid));
            last_rcvd_or_tried = Instant::now(); //reconnect if nothing for 5 min. Reset counter first though
            let tube_flag = ok_or_continue!(jwrap(&cid, &addr, &bkey, &ctxt.keys, &ctxt.cache));
            flag.store(false, Relaxed); //Turn off old forwarders
            tube = tube_flag.0;
            flag = tube_flag.1;
        }
        //ping meet server if we're missing messages or every 15s to stay alive
        force_ack = force_ack || acks.len() > 1 || (acks.len() == 1 && acks[0].start > 0);
        if force_ack || lastping.elapsed() > secs(15) {
            lastping = Instant::now();
            let ackr = acks.iter().rev().next().map(|a| a.clone()); //ping with the last ack range
            let a = ackr.unwrap_or(-1..-1);
            let ping_pkt = doc! {"ping": binary_bson(&cid), "ack": bson!([a.start, a.end])};
            log_err!(tube.send_vec(bdoc_to_u8vec(&ping_pkt)), "sending ping");
        }
        force_ack = false;
        let rcvd = ok_or_continue!(tube.recv_vec());
        last_rcvd_or_tried = Instant::now(); //tube is a crypto wrapped tube; this is a verified rcv
        let doc = ok_or_continue!(decode_document(&mut Cursor::new(&rcvd)));
        if let (Ok(id), Ok(sid)) = (doc.get_i64("id"), doc.get_i64("res")) {
            let (fid, _, start, len) = ok_or_continue!(stream_opens.remove(&id).ok_or_else(sfnone));
            info!("Syncing file {} in sync convo {}", fid, b64spk(&cid));
            let m = ok_or_continue!(doc.get_binary_generic("meta")); //set metadata
            log_err!(ctxt.cache.insert(&db_key(&cid, fid, b"meta"), &m[..]), "");
            let pathfold = Path::new(&ctxt.workdir).join(b64spk(&cid).as_str());
            let p = format!("{}{:018}", pathfold.to_str().unwrap_or("."), fid);
            let mut o = OpenOptions::new();
            let mut f = o.read(true).write(true).truncate(false).open(&p)?;
            f.seek(io::SeekFrom::Start(start as u64))?; //get ready to write at the offset
            let overlap = fs::metadata(&p).map(|m| m.len()).unwrap_or(0) as i64;
            streams.insert(sid, (fid, len, WriteStream::new(sid, f, overlap, start))); //call done
            continue; //it's a call resp, no more to do for this packet
        } else if let Ok(s) = doc.get_i64("s") {
            if let Some((fid, len, ref mut wstream)) = streams.get_mut(&s) {
                let swr = wstream.stream_write(&tube, None, &doc);
                if let Ok(b) = swr {
                    if b != 0 {
                        snd.send(Sync::SpaceAdjust {
                            cid: cid,
                            size_diff: b as i64,
                        })?;
                        if wstream.offset <= *len {
                            continue; //Good write, more to go but we're done until the next packet
                        }
                    } else {
                        info!("Syncing file {} in sync convo {} done", fid, b64spk(&cid));
                    }
                } else if let Err(SfErr::OutOfOrderErr) = swr {
                    continue; //Normal packet loss. We chill until the next packet
                } else if let Err(e) = swr {
                    info!("Error {} syncing {} in convo {}", e, fid, b64spk(&cid));
                }
                let clsdoc = doc! {"f": "cls", "sid": s, "fid": *fid, "id": rand_i64()};
                log_err!(tube.send(&bdoc_to_u8vec(&clsdoc)), "fid close");
                streams.remove(&s);
            }
            continue;
        }
        let seq = ok_or_continue!(doc.get_i64("q")); //Not a call response, should be normal w/seq #
        let ts = ok_or_continue!(doc.get_i64("t")); // timestamp
        debug!("sync_msg {} bytes chat seq {}", rcvd.len(), seq);
        if !update_acks(&mut acks, seq) {
            force_ack = true; // Duplicate. No need to take further action
            continue;
        }
        let mut msgcur = Cursor::new(Vec::with_capacity(rcvd.len() + 8));
        ok_or_continue!(msgcur.write_all(&ts.to_be_bytes()[..])); //First 8 bytes are timestamp
        ok_or_continue!(msgcur.write_all(&rcvd)); //rest is original/sendable message
        let msg = msgcur.into_inner();
        //Send size update message to master thread
        let size_diff = msg.len() as i64 + MSG_OVERHEAD;
        snd.send(Sync::SpaceAdjust {
            cid: cid.clone(),
            size_diff: size_diff,
        })?; //if err we're dead
        ok_or_continue!(ctxt.cache.insert(&db_key(&cid, seq, b"mesg")[..], msg)); //cache the message
        let key = time_key(&k[0..32], &cid, b"mesg", seq, ts.to_be_bytes()); //prep time log ID
        ok_or_continue!(ctxt.cache.insert(&key[..], b"")); //set time log entry
        let mut convo_locked = ok_or_continue!(convo.lock());
        convo_locked.seq = convo_locked.seq.max(seq + 1); // update our local next sequence number

        //Now see if we this is an actionable file notification
        let e = ok_or_continue!(doc.get_document("e"));
        let op = ok_or_continue!(e.get_str("op"));
        let fid = ok_or_continue!(e.get_i64("fid"));
        if op == "del" {
            snd.send(Sync::Rm {
                cid: cid.clone(),
                fid: fid,
            })?; //call rm_file on the main thread
        } else if op == "fwr" {
            let len = ok_or_continue!(e.get_i64("ln"));
            let start = ok_or_continue!(e.get_i64("st"));
            //sync the specified range of the file (or whole file)
            debug!("syncing {} start {}", fid, start);
            let callid = rand_i64();
            let b = bdoc_to_u8vec(&doc! {"f": "res", "fid": fid, "off": start, "id": callid});
            log_err!(tube.send(&b), "fid open");
            stream_opens.insert(callid, (fid, b, start, len));
        } else if op == "ume" {
            let newfid = ok_or_continue!(e.get_i64("newfid"));
            let meta = ok_or_continue!(e.get_binary_generic("meta")).to_vec();
            let oidorig = ok_or_continue!(leneq(ok_or_continue!(e.get_binary_generic("oid")), 32));
            let oid = copy_to_array(oidorig);
            snd.send(Sync::Move {
                cid: cid.clone(),
                fid: fid,
                newfid: newfid,
                meta: meta,
                oid: oid,
            })?; //call self.mov(convo, fid, newfid, ts) on main thread
        } else if op == "lve" {
            let pid = ok_or_continue!(leneq(ok_or_continue!(e.get_binary_generic("lve")), PIDLEN));
            let prid_key = db_plkey(&cid, b"prid", array_ref![pid, 0, PIDLEN]);
            log_err!(ctxt.cache.remove(&prid_key), "leave sync");
        } else if op == "ent" {
            let pid = ok_or_continue!(leneq(ok_or_continue!(e.get_binary_generic("ent")), PIDLEN));
            let prid_key = db_plkey(&cid, b"prid", array_ref![pid, 0, PIDLEN]);
            log_err!(ctxt.cache.insert(&prid_key, b""), "enter sync");
        }
    }
    flag.store(false, Relaxed); //we were promoted
    info!("sync closed {}", b64spk(&cid));
    Ok(())
}

fn newf(a: SocketAddr, no: usize) -> SfRes<(Tube, Arc<AtomicBool>, Tube, Arc<AtomicBool>)> {
    let (sender, receiver) = Tube::dual_udp_tag(&a, no as u8)?; //get the socket & clone
    let flag = Arc::new(AtomicBool::new(true));
    debug!("fwding {} -> {}", no, a);
    Ok((sender, Arc::clone(&flag), receiver, flag))
}

pub enum Sync {
    SpaceAdjust {
        cid: ConvoId,
        size_diff: i64,
    },
    Rm {
        cid: ConvoId,
        fid: i64,
    },
    Move {
        cid: ConvoId,
        fid: i64,
        newfid: i64,
        meta: Vec<u8>,
        oid: ConvoId,
    },
}
impl Sync {
    fn cid(&self) -> ConvoId {
        match self {
            Sync::SpaceAdjust { cid, size_diff: _ } => cid.clone(),
            Sync::Rm { cid, fid: _ } => cid.clone(),
            Sync::Move {
                cid,
                fid: _,
                newfid: _,
                meta: _,
                oid: _,
            } => cid.clone(),
        }
    }
}

//Node server
pub fn run_node(ctxt: Context, config: &Yaml) -> usize {
    run_tcp_relay(ctxt.addr.clone()); //kick off the TCP forwarder
    let (local_sndr, local_rcvr) = unbounded();
    let sockraw = UdpSocket::bind(&ctxt.addr).expect("Couldn't bind to address"); //fatal
    set_required_sockopts(&sockraw);
    let socket = Arc::new(sockraw);
    let mut sctx = SfSrv::new(&ctxt, Arc::clone(&socket), config, local_sndr);
    info!("Started node server on {}", ctxt.addr);
    let totl_sec = wr_crypto_auth(b"totl", array_ref![&ctxt.keys.sign.sk[..], 0, 32]); //derive key
    (&mut sctx.totl_key[0..32]).copy_from_slice(&totl_sec[..]);
    (&mut sctx.totl_key[32..]).copy_from_slice(b"totl");
    let mut last_trimmed = Instant::now();
    //load all sync conns. Do this by looping over all convos in the DB, and grabbing prim key
    let mut cur_spot = [0; 32];
    while let Ok(dbres) = sctx.db.get_gt(&cur_spot[..]) {
        let (nextk, _nextv) = some_or_break!(dbres);
        let cidlen = nextk.len().min(32);
        (&mut cur_spot[..cidlen]).copy_from_slice(&nextk[..cidlen]);
        if cidlen == 32 {
            if let Ok((false, seq)) = sctx.get_convo_primary_seq(&cur_spot) {
                let c = Arc::clone(&ctxt); //create the chat object and resume syncing
                let cnv = sctx.newchat(&cur_spot, false, seq);
                let totl_key = sctx.totl_key.clone();
                let snd = sctx.local_sndr.clone();
                spawn_thread("chatmirr", move || sync(c, &totl_key[..], cnv, snd));
            }
        } else {
            cur_spot[cidlen..].iter_mut().for_each(|x| *x = 0);
        }
        increment_spkey(&mut cur_spot);
    }
    //crossbeam stuff. A thread to just convert UDP receives to crossbeam sends
    let (packet_sndr, packet_rcvr) = unbounded();
    spawn_thread("udpthwrp", move || {
        let mut buf = [0; 65536];
        let mut rres = socket.recv_from(&mut buf);
        while let Ok((rcvdlen, src)) = rres {
            log_err!(packet_sndr.send((buf[..rcvdlen].to_vec(), src)), "sndr");
            rres = socket.recv_from(&mut buf);
        }
        log_err!(rres, "UDP forward thread died!");
        std::process::exit(1); //kill the whole shebang
    });
    //main packet dispatching loop
    loop {
        if last_trimmed.elapsed() > secs(60) {
            last_trimmed = Instant::now();
            sctx.trim_sessions(); //Trim tunnels/sessions every minute
            sctx.trim_tunnels();
        }
        let rto_timeout_opt = sctx.process_rtos();
        select! {
            recv(packet_rcvr) -> rcvd => {
                log_err!(rcvd, "packet_rcvr"); //if it's fatal, log it first before dying
                let (mut raw_msg, src) = rcvd.expect("packet_rcvr"); //fatal error, shouldn't happen
                debug!("Received {} from {} on {}", raw_msg.len(), src, ctxt.addr);
                let ct = &mut raw_msg[..];
                if sctx.tunnel_msg(&src, ct).is_ok() || sctx.session_msg(&src, ct).is_ok() {
                    continue; //This is a chat message on an established tunnel or connection
                }
                //else see if it's a new anon encrypted RPC call.
                sctx.evaluate_rpc(ct, &src)
                    .and_then(|encreply| Ok(sctx.sock.send_to(&encreply, src).map(|_| ())?))
                    .unwrap_or_else(|e| warn!("RPC err {}", e));
            },
            recv(local_rcvr) -> msg => { //inter-thread comms (backup/sync messages)
                log_err!(msg, "inter thread"); //if it's fatal, log it first before dying
                let m = msg.expect("packet_rcvr"); //fatal error, shouldn't happen
                debug!("got inter-thread packet");
                let s = Arc::clone(ok_or_continue!(sctx.convos.get(&m.cid()).ok_or_else(sfnone)));
                let mut conv = ok_or_continue!(s.lock());
                if let Sync::SpaceAdjust{cid: _, size_diff} = m {
                    log_err!(sctx.update_space(&mut *conv, size_diff), "us");
                } else if let Sync::Rm{cid: _, fid} = m {
                    log_err!(sctx.rm_file(fid, &mut *conv, true), "rm");
                } else if let Sync::Move{cid: _, fid, newfid, meta, oid} = m {
                    let ts = now_as_bin_microseconds();
                    if newfid > conv.fid {
                        conv.fid = newfid + 1;
                    }
                    let oid_key = db_id(&conv.convoid, b"oid_", &oid);
                    if let Ok(Some(_conts)) = sctx.db.get(&oid_key[..]) {
                        debug!("already have it"); //we already moved it probably
                        continue; //ignore
                    }
                    let mut met = Vec::with_capacity(oid.len() + ts.len() + meta.len()); //oid32bytes + timestamp8bytes + meta
                    met.extend_from_slice(&oid[..]);
                    met.extend_from_slice(&ts[..]);
                    met.extend_from_slice(&meta);
                    log_err!(sctx.db.insert(&oid_key[..], &u64_bytes(fid as u64)), "do"); //save oid->fid
                    log_err!(sctx.db.insert(&db_key(&conv.convoid, fid, b"meta")[..], met), "dm"); //save metadata
                    log_err!(sctx.mov(&mut *conv, fid, newfid, ts), "mov"); //move the actual file
                }
            },
            default(rto_timeout_opt.unwrap_or(secs(60))) => continue,
        }
    }
}

//Saves the backups for a given convo; establishes us as primary
fn setup_backups(cid: ConvoId, ctxt: &Context, backups: &[u8], sig: &[u8]) {
    log_err!(ctxt.cache.insert(&db_key(&cid, 0, b"sigh")[..], sig), "");
    let chunksize = CRYPTO_SIGN_PUBLICKEYBYTES + BIN_SOCKADDR_LEN;
    for chunk in backups.chunks_exact(chunksize).take(MAX_BACKUPS) {
        let bkey = wr_crypto_sign_pk_to_box(array_ref![&chunk, 19, 32]);
        if bkey == ctxt.keys.bx.pk {
            warn!("Cannot make ourselves our own backup for {}", b64spk(&cid));
            continue;
        }
        let t = ok_or_continue!(Tube::udp_connect(&debin_addr(array_ref![chunk, 0, 19])));
        let (sig2, p) = (binary_bson(sig), ctxt.addr.port() as i32);
        let rpcdoc = doc! {"fnc": "backupcon", "cid": binary_bson(&cid[..]), "sig": sig2, "np": p};
        let ctxt2 = Arc::clone(ctxt); //bknd key allows backup node to sync
        log_err!(ctxt.cache.insert(&db_id(&cid, b"bknd", &bkey), chunk), "");
        info!("{} {}", b64spk(&cid), debin_addr(array_ref![chunk, 0, 19]));
        spawn_thread("backups1", move || {
            if let Err(e) = do_rpc(rpcdoc, &t, &bkey, &ctxt2.keys) {
                warn!("backuping convo {} failed err {}", b64spk(&cid), e);
            }
        });
    }
}

//Makes a binary path to use as a DB key as an array (no allocation) with a hash or given 32-byte ID
fn db_id(convoid: &ConvoId, ktype: &[u8; 4], hash: &[u8; 32]) -> [u8; 32 + 4 + 32] {
    let mut res = [0; 32 + 4 + 32];
    (&mut res[0..32]).copy_from_slice(&convoid[..]);
    (&mut res[32..(32 + 4)]).copy_from_slice(ktype);
    (&mut res[(32 + 4)..]).copy_from_slice(&hash[..]);
    res
}

//Makes a binary path to use as a DB key as an array (no allocation) with a given PIDLEN ID
fn db_plkey(convoid: &ConvoId, ktype: &[u8; 4], blob: &[u8; PIDLEN]) -> [u8; 32 + 4 + PIDLEN] {
    let mut res = [0; 32 + 4 + PIDLEN];
    (&mut res[0..32]).copy_from_slice(&convoid[..]);
    (&mut res[32..(32 + 4)]).copy_from_slice(ktype);
    (&mut res[(32 + 4)..]).copy_from_slice(&blob[..]);
    res
}

//Adds a sequence of nodes into the given BSON output vector
fn add_nodelist(ge: &SignPKey, lt: &SignPKey, nodesout: &mut Vec<Bson>, c: &SfContext) {
    let r = c.nodes.range(&ge[..]..&lt[..]);
    let mut size_est = 4 + 1; //bson docs start with 4 byte size and end with a null byte
    for node in r.filter_map(|v| Node::load(&v.unwrap().1).ok()) {
        if c.losses.contains_key(&node.key[..]).unwrap_or(false) {
            continue; //don't send ones we failed to reach recently
        } else if size_est > 1200 {
            break; //leave bytes for wrapping and enc overheads for a packet
        }
        let (at, addr) = node.address.deparse();
        size_est += 3 + 60 + addr.len(); //3 for doc type byte, key ('0'-'9'), null, 60 doc w/o addr
        nodesout.push(bson!({"k": binary_bson(&node.key[..]), "t": at, "a": binary_bvec(addr)}));
    }
}

//Handles a nodelist RPC call. Incoming doc can include gt and lt.
fn nodelist(
    context: &Context,
    doc: &Document,
    src_addr: &SocketAddr,
    respkey_s: SignPKey,
    respkey: &BoxPKey,
    resp: &mut Document,
) {
    let mut ge: SignPKey = [0; 32];
    let _a = doc.get_binary_generic("ge").map(|geb| {
        if geb.len() == CRYPTO_SIGN_PUBLICKEYBYTES {
            ge.clone_from_slice(geb);
        }
    });
    let lt: SignPKey = [0xFF; 32];
    let mut nodesout: Vec<Bson> = Vec::new();
    add_nodelist(&ge, &lt, &mut nodesout, &context); // first add all the latest
    if nodesout.len() == 0 {
        add_nodelist(&[0; 32], &lt, &mut nodesout, &context); //wrap around
    }
    *resp = doc! { "rsp": "nodelist", "nodes": nodesout};
    //If they're a node and we don't know about them, spin off a verification thread
    if let Ok(node_port) = doc.get_i32("np") {
        if !context.has_node(&respkey_s) && node_port > 0 && node_port < 65536 {
            let (ctx_clone, resp_skey, resp_bkey) =
                (Arc::clone(context), respkey_s, respkey.clone());
            let verif_addr = SocketAddr::new(src_addr.ip(), node_port as u16);
            debug!("Spawning verifier from nodelist for port {}", node_port);
            spawn_thread("verifier", move || {
                if verify(&ctx_clone, &resp_skey, &resp_bkey, &verif_addr, true) {
                    debug!("found alive node at {}!", verif_addr);
                    let n = Node {
                        key: resp_skey.clone(),
                        bkey: resp_bkey,
                        address: NodeAddr::Sockaddr(verif_addr),
                    };
                    log_err!(ctx_clone.save_node(n), "saving node");
                }
            })
        }
    }
}

//push notice to announce one meet
fn nodeannounce(context: &Context, doc: &Document, resp: &mut Document) {
    let pkr = doc.get_binary_generic("pk").map_err(|e| SfErr::ValErr(e));
    pkr.and_then(|pkb| {
        let k: SignPKey = copy_to_array(leneq(pkb, CRYPTO_SIGN_PUBLICKEYBYTES)?);
        debug!("Learning about node meet for {}", b64spk(&k));
        let n = Node {
            key: k,
            bkey: wr_crypto_sign_pk_to_box(&k),
            address: parse_binaddr(doc.get_binary_generic("ba")?, &k)?,
        };
        log_err!(context.save_node(n), "Can't save node");
        *resp = doc! { "rsp": "nodeannounce", "rsp": "ok"};
        Ok(())
    })
    .unwrap_or_else(|e| error!("ERROR in nodeannounce handler {}", e));
}
