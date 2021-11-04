// Client-only functionality in schadnfreude
use crate::innermain::*;
use smallvec::{smallvec, SmallVec};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::Thread;
use std::time::{Duration, Instant};

use super::apisrv::*;
use super::stream::*;
use crate::*;

pub static PADDING: [u8; 256] = [0x20; 256]; //padding. 0x20 to be easily interpretable as a str

//Chat message, wraps doc, which is the E2E encrypted BSON.
//It may also contain a "midpoint" message from the meet node (not E2E)
pub struct ChatMsg {
    pub doc: Document,
    pub midpoint: Value,
    pub signer: SignPKey,
    pub convoid: Option<ConvoId>,
    pub seq: Option<i64>,
}

pub struct SentMsg {
    pub data: Vec<u8>,
    pub sent: Instant,
    pub resent: bool,
}
impl SentMsg {
    pub fn new(dat: Vec<u8>) -> Self {
        Self {
            data: dat,
            sent: Instant::now(),
            resent: false,
        }
    }
}

pub enum StreamTracker {
    Read(ReadTracker),
    Write(WriteTracker),
    Sync(WriteStream<Vec<u8>>),
}

pub struct ReadTracker {
    pub done: Arc<(Mutex<bool>, Condvar)>,
    pub stream: ReadStream<CryptReader>,
}

pub struct WriteTracker {
    pub stream: WriteStream<Vec<u8>>,
    pub nonce: i64,
    pub handoff: Sender<Vec<u8>>,
}

impl WriteTracker {
    pub fn new(streamid: i64, nonce: i64, handoff: Sender<Vec<u8>>) -> Self {
        Self {
            stream: WriteStream::new(streamid, Vec::new(), 0, 0),
            nonce: nonce,
            handoff: handoff,
        }
    }
}

//CryptReader wraps an ChanReader, adding file block encryption.
pub struct CryptReader {
    pub stream: ChanReader,
    pub offset: usize,
    pub current: [u8; 1024 + CRYPTO_BOX_MACBYTES + 8],
    pub cached: usize,
    pub global: i64,
    pub eof: bool,
    pub conn: Arc<Conn>,
    pub nonce: i64,
    pub rnd: i64,
}

impl CryptReader {
    pub fn new(s: ChanReader, conn: Arc<Conn>, nonce: i64) -> Self {
        Self {
            stream: s,
            offset: 0,
            current: [0; 1024 + CRYPTO_BOX_MACBYTES + 8],
            cached: 0,
            global: 0,
            eof: false,
            conn: conn,
            nonce: nonce,
            rnd: rand_i64(),
        }
    }
}

impl Read for CryptReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("cryptreader read requested len {}", buf.len());
        let mut written = 0;
        if self.cached > 0 {
            written = buf.len().min(self.cached - self.offset);
            let endoff = self.offset + written;
            buf[..written].clone_from_slice(&self.current[self.offset..endoff]);
            self.offset = endoff;
            if self.offset == self.cached {
                self.cached = 0; //none left
                self.offset = 0;
            }
            if written == buf.len() {
                debug!("cryptreader req {} ret {}", buf.len(), written);
                return Ok(written);
            }
            debug!("cryptreader wrote cached {}/{}", written, buf.len());
        } else if self.eof {
            debug!("cryptreader eof");
            return Ok(0); //probably EOF
        }
        let mut rcvbuf = [0; 1024];
        let plainbytes = self.stream.read(&mut rcvbuf)?;
        if plainbytes > 0 {
            debug!("crypt inner read {} off {}", plainbytes, self.global);
            if let Ok(non) = self.conn.fblock_tag(self.nonce, self.rnd, self.global) {
                self.global += plainbytes as i64;
                self.current[..8].copy_from_slice(&self.rnd.to_le_bytes()[..]);
                self.rnd += 1;
                let p = &rcvbuf[0..plainbytes];
                wr_crypto_secretbox_inplace_n(p, &mut self.current[8..], &non, &self.conn.key);
            } else {
                return Err(Error::new(ErrorKind::Other, "Bad offset"));
            }
            self.cached = plainbytes + CRYPTO_BOX_MACBYTES + 8;
            self.offset = 0;
            if written < buf.len() {
                written += self.read(&mut buf[written..])?; //recurse to keep going on
            }
        } else {
            self.eof = true;
            self.cached = 0;
        }
        debug!("cryptreader read req {} ret {}", buf.len(), written);
        Ok(written)
    }
}

//ChanReader wraps a stream of chunks (u8 vecs) into a Read interface. EOF by convention is
//represented on input by an empty vector. Read blocks until it can either fill the buffer or it
//hits the end of the stream and returns the last chunk or zero bytes.
pub struct ChanReader {
    pub stream: Receiver<Vec<u8>>,
    pub offset: usize,
    pub current: Option<Vec<u8>>,
    pub eof: bool,
}

impl ChanReader {
    pub fn new(s: Receiver<Vec<u8>>) -> Self {
        Self {
            stream: s,
            offset: 0,
            current: None,
            eof: false,
        }
    }
}

impl Read for ChanReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug!("Chanreader read requested len {}", buf.len());
        let mut written = 0;
        if let Some(cached) = &self.current {
            written = buf.len().min(cached.len() - self.offset);
            let endoff = self.offset + written;
            buf[..written].clone_from_slice(&cached[self.offset..endoff]);
            self.offset = endoff;
            if self.offset == cached.len() {
                self.current = None;
            }
            if written == buf.len() {
                debug!("Chanreader req len {} ret {}", buf.len(), written);
                return Ok(written);
            }
            debug!("Chanreader wrote cached {}/{}", written, buf.len());
        } else if self.eof {
            debug!("Chanreader eof");
            return Ok(0); //probably EOF
        }
        if let Ok(data) = self.stream.recv() {
            debug!("Chanreader inner read {}", data.len());
            if data.len() == 0 {
                self.eof = true;
                self.current = None;
            } else {
                self.current = Some(data);
            }
            self.offset = 0;
            if written < buf.len() {
                written += self.read(&mut buf[written..])?; //recurse to keep going on
            }
        } else {
            self.eof = true;
            self.current = None;
        }
        debug!("Chanreader req {} ret {}", buf.len(), written);
        Ok(written)
    }
}

pub type Backup = (Tube, Hop, f64, PubNode);

//Represents one individual connection in a Conn; either the main or a backup. \
pub struct ConnInfo {
    pub tube: Tube,
    pub hop: Hop,
    pub rtt: f64,
    pub node: PubNode,
    pub recvd: Instant,
    pub pinged: Instant,
    pub failed: Instant,
    pub flag: Option<Arc<AtomicBool>>,
    pub state: NodeState,
}
impl ConnInfo {
    pub fn new(b: Backup, start: Instant) -> Self {
        Self {
            tube: b.0,
            hop: b.1,
            rtt: b.2,
            node: b.3,
            recvd: start,
            pinged: start,
            failed: start,
            flag: None,
            state: Chill,
        }
    }

    //Sets self in the received-proposal state for this round and creates a new concurring proposal
    pub fn prop(&mut self, r: i32, k: &SignPKey, a: SocketAddr, old: Option<SignPKey>) -> Document {
        info!("Round {} new nodeprop {} -> {}", r, self.node.address, a); //old round's gone
        let ourv = binary_bson(&addrkey(&a, k)); //prep our vote (first received)
        let bp = binary_bson(&self.node.key); //the original node we're replacing
        let mut vote = doc! {"rolp": "nodeprop", "rolk": bp, "newb": ourv, "round": r};
        if let Some(ok) = old {
            vote.insert("oldb", binary_bson(&ok[..]));
        }
        self.state.rcv_prop(r, k.clone(), a, old); //bump to newly received
        vote
    }

    //Makes a connection almost to the new node and closes the old one
    pub fn swap_backup(&mut self, k: SignPKey, newaddr: SocketAddr, c: &Context) {
        debug!("swap_backup {} {}", newaddr, b64spk(&k));
        let pubnode = PubNode::new(k, wr_crypto_sign_pk_to_box(&k), newaddr);
        let (mut tube, mut hop) = hop_to(&pubnode.address, c, c.hops, 0);
        if let Some(flag) = &self.flag {
            debug!("swap_backup {} {} exiting old", newaddr, b64spk(&k));
            log_err!(self.tube.send_vec(bdoc_to_u8vec(&doc! {"exit": true})), ""); //close old session if there
            flag.store(false, Relaxed);
        }
        mem::swap(&mut tube, &mut self.tube);
        mem::swap(&mut hop, &mut self.hop);
        self.node = pubnode;
        self.rtt = 1000.0; //kind of ignoring RTT right now since we aren't interrogating the far end yet
        self.recvd = Instant::now();
        self.pinged = self.recvd;
        self.flag = None;
        self.state = Chill; //reset state
        close_wad_conn(hop); //close old hops
    }
}

//Chat endpoint
pub struct Conn {
    pub ci: Mutex<ConnInfo>,   //gonna be held continously by the monitor thread
    pub stube: RwLock<Tube>,   //other threads can send things simultaneously without bugging ci
    pub meet: RwLock<PubNode>, //other threads can send things simultaneously without bugging ci
    pub key: SecKey,
    pub idkeys: Keys,
    pub cachepath: PathBuf,
    pub participants: Mutex<HashSet<SignPKey>>,
    pub queued: Mutex<BTreeMap<Sha256Hash, SentMsg>>,
    pub host_seq: AtomicIsize,
    pub rttest: AtomicUsize,
    pub ctflag: AtomicBool,
    pub calls: Mutex<BTreeMap<i64, Thread>>,
    pub resps: Mutex<BTreeMap<i64, Document>>,
    pub streamies: Mutex<BTreeMap<i64, Arc<RwLock<StreamTracker>>>>,
    pub backups: Mutex<Vec<ConnInfo>>,
    pub running: Mutex<Option<JoinHandle<()>>>,
    pub acks: Mutex<Vec<ops::Range<i64>>>,
}

impl Conn {
    fn register_new(
        idkeys: Keys,
        tube: Tube,
        chatkey: SecKey,
        participants: HashSet<SignPKey>,
        flag: Arc<AtomicBool>,
        wad: Hop,
        context: &Context,
        meet_host: PubNode,
        host_seq: i64,
        rtt: f64,
        nsender: &ChatSnd,
        backups: &mut [(Option<(Tube, Hop, f64)>, PubNode)],
        sync: bool,
    ) -> SfRes<Arc<Conn>> {
        let cd = dirs::cache_dir()
            .and_then(|d| d.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| ".".to_string());
        let pstr = context.addr.port().to_string();
        let cstr = b64spk(&idkeys.sign.pk);
        let (m, b) = (&meet_host.address, backups.iter().map(|v| v.1.address)); //for info print
        info!("R {} at {} b {:?}", cstr, m, Vec::from_iter(b));
        //cachepath = ~/.cache/schadnfreude/port/cid where .cache is an appdata fold on windows
        let cpath: PathBuf = [&cd, "schadnfreude", &pstr, &cstr].iter().collect();
        fs::create_dir_all(&cpath)?; // make sure our cache dir is present for this cid
        let mut justus = false;
        if participants.len() == 1 {
            if let Some(p1) = participants.iter().next() {
                justus = *p1 == context.keys.sign.pk;
            }
        }
        let started = Instant::now();
        let mut backs = Vec::with_capacity(backups.len().min(MAX_BACKUPS));
        for (opt, nod) in backups.iter_mut().take(MAX_BACKUPS) {
            let ci = if let Some(conninfo) = opt.take() {
                conninfo
            } else if let Ok(ci) = conn_hops(&nod.address, context, &nod.bkey) {
                ci //it worked and backup is alive. ci is (Tube, Hop, f64)
            } else {
                let (cli, hop) = hop_to(&nod.address, context, context.hops, 0); // get tube
                (cli, hop, 1.0) //fake RTT, since node is not healthy. We'll figure it out later
            };
            backs.push(ConnInfo::new((ci.0, ci.1, ci.2, nod.clone()), started));
        }
        let backups_pub = backs.iter().map(|b| b.node.clone()).collect();
        let mhnode = meet_host.clone();
        let stube = tube.clone_sender()?;
        let mut ci = ConnInfo::new((tube, wad, rtt, meet_host), started);
        ci.flag = Some(flag);
        let sync_stream = StreamTracker::Sync(WriteStream::new(0, Vec::with_capacity(2048), 0, 0));
        let mut streamiez = BTreeMap::new();
        streamiez.insert(0, Arc::new(RwLock::new(sync_stream)));
        send_ack(0, &stube, None, Vec::new(), 0, 0)?; //prompt remote side to start sync stream
        let conn = Arc::new(Conn {
            stube: RwLock::new(stube),
            meet: RwLock::new(ci.node.clone()), //needs to be accessible
            ci: Mutex::new(ci),
            idkeys: idkeys.clone(),
            key: chatkey,
            cachepath: cpath,
            participants: Mutex::new(participants),
            queued: Mutex::new(BTreeMap::new()),
            host_seq: AtomicIsize::new(host_seq as isize),
            rttest: AtomicUsize::new(rtt as usize),
            ctflag: AtomicBool::new(true),
            calls: Mutex::new(BTreeMap::new()),
            resps: Mutex::new(BTreeMap::new()),
            streamies: Mutex::new(streamiez),
            backups: Mutex::new(backs),
            running: Mutex::new(None),
            acks: Mutex::new(Vec::new()),
        });
        let mut conmap = context.convos.lock()?; //Grab convos lock
        if conmap.contains_key(&idkeys.sign.pk) {
            drop(conmap); //Release lock
            info!("Already joined {}", b64spk(&idkeys.sign.pk));
            conn.close(); //tell the remote side to exit
            spawn_thread("nopejoin", move || close_conn_channel(conn)); // Then close our hop
            return Err(SfErr::AlreadyJoinedErr);
        }
        conmap.insert(idkeys.sign.pk.clone(), Arc::clone(&conn)); //Add to convos on context
        drop(conmap); //Release lock then notify the user
        let cm = ChatMsg {
            doc: doc! {"newcon": ""},
            midpoint: json!({}),
            signer: context.keys.sign.pk.clone(),
            convoid: Some(idkeys.sign.pk.clone()),
            seq: None,
        };
        log_err!(nsender.send(cm), "con not");
        //Spawn the monitor and save the join handle in the connection
        let (a, c, s) = (Arc::clone(&conn), Arc::clone(context), nsender.clone());
        let n = "chatconn".to_string();
        let j = thread::Builder::new().name(n).spawn(move || cmon(a, c, s)); //Chat monitor thread
        log_err!(&j, ""); //error log if you can't start it
        if let (Ok(jh), Ok(mut r)) = (j, conn.running.lock()) {
            debug!("spawn {:08X} chatconn", hash(&jh.thread().id()) as u32);
            *r = Some(jh); //save the join handle
        }
        if sync && !justus {
            if let Ok(mss) = context.meetstate_sender.lock() {
                debug!("Notify meetstate about {}", b64spk(&conn.idkeys.sign.pk));
                if let Err(_e) = mss.send(MeetStateMsg {
                    opening: true,
                    idkeys: conn.idkeys.clone(),
                    key: conn.key.clone(),
                    meet_host: mhnode, //Notify other devices of the new convo
                    backups: backups_pub,
                }) {
                    notify_err("Err saving convo - send", nsender, context)
                }
            } else {
                notify_err("Err saving convo - lock", nsender, context)
            }
        }
        Ok(conn)
    }

    //Rolls the primary node to a backup. Next you should swap out the backup
    pub fn roll_prim(&self, ci: &mut ConnInfo, mc: &mut ConnInfo, seq: i64) -> SfRes<()> {
        let new_main_stube_clone = ci.tube.clone_sender()?;
        let new_seq = isize::try_from(seq)?;
        let mut stwr = self.stube.write()?;
        let mut meetn = self.meet.write()?;
        //FINAL PROMOTION CONFIRMATION HAS BEEN VERIFIED so make this backup conn the main conn
        warn!("Rolling primary {} -> {}", mc.node.address, ci.node.address);
        mem::swap(mc, ci);
        *stwr = new_main_stube_clone;
        *meetn = mc.node;
        self.host_seq.store(new_seq, Relaxed);
        Ok(())
    }

    //Checks whether we were told to roll our primary node, verifies, and does so if instructed
    pub fn roll_poll_check(
        &self,
        mpm: &Document,
        backups: &mut Vec<ConnInfo>,
        i: usize,
        main: &mut ConnInfo,
        c: &Context,
    ) -> SfRes<()> {
        if mpm.get_str("op")? == "promote" {
            info!("Promotion message from {}", backups[i].node.address);
            let innerd = mpm.get_document("inner")?;
            let promo = innerd.get_binary_generic("promote")?;
            let sig_opened = wr_crypto_sign_open_inplace(&promo, &self.idkeys.sign.pk)?;
            let sig = leneq(sig_opened, DBK_LEN)?;
            //TODO: accept promo messages on behalf of another backup or node, not just sender
            if &sig[..36] != &db_key(&backups[i].node.key, 0, b"host")[..36] {
                return Err(SfErr::BadSignatureErr); //Signed message must say they are host
            }
            let host_seq = i64::from_be_bytes(*array_ref![sig, 36, 8]); //now check sequence
            if host_seq <= self.host_seq.load(Relaxed) as i64 {
                return Err(SfErr::OutOfOrderErr);
            }
            let bblob = innerd.get_binary_generic("backups")?; //swap our standby backup and main
            self.roll_prim(&mut backups[i], main, mpm.get_i64("q")?)?;
            //Now swap out the old dead main with a new backup.
            let chunksize = CRYPTO_SIGN_PUBLICKEYBYTES + BIN_SOCKADDR_LEN;
            'bbloop: for chunk in bblob.chunks_exact(chunksize).take(MAX_BACKUPS) {
                let addr = debin_addr(array_ref![chunk, 0, 19]);
                let k = *array_ref![&chunk, 19, 32];
                if backups.iter().filter(|b| b.node.key == k).next().is_some() {
                    continue 'bbloop; //skip previously-valid nodes
                }
                backups[i].swap_backup(k, addr, c); //this is the new backup
                break;
            }
        }
        Ok(())
    }

    //Polls a backup and executes the roll protocol when appropriate
    pub fn poll_backup(
        &self,
        mut backups: &mut Vec<ConnInfo>,
        i: usize,
        c: &Context,
        main: &mut ConnInfo,
        nodeaddrs: &HashSet<SocketAddr>,
    ) -> SfRes<()> {
        if let Some(_flag) = &backups[i].flag {
            log_err!(backups[i].tube.set_timeout(Duration::from_millis(1)), "to"); // poll, don't wait
            while let Ok(p) = backups[i].tube.recv_vec() {
                backups[i].recvd = Instant::now();
                if let Chill = &backups[i].state {
                } else {
                    let nkey = binary_bson(&backups[i].node.key); //Tell them it's up right away
                    self.broadcast(doc! {"nodeisup": nkey}, &c, backups, None);
                    backups[i].state = Chill;
                }
                debug!("Got backup msg {} bytes", p.len());
                let mut doc1 = ok_or_continue!(decode_document(&mut Cursor::new(&p)));
                if let Ok(mpm) = doc1.get_document("e") {
                    log_err!(self.roll_poll_check(&mpm, backups, i, main, c), "rollpc");
                }
                let u = ok_or_continue!(doc1.get_binary_generic_mut("u")); // we only handle ephemeral
                let s = ok_or_continue!(wr_crypto_secretbox_open(u, &self.key)); // decrypt E2E layer
                if s.len() < CRYPTO_SIGN_PUBLICKEYBYTES + CRYPTO_SIGN_BYTES {
                    return Err(SfErr::BadSignatureErr);
                }
                let (frombin, smsg) = s.split_at(CRYPTO_SIGN_PUBLICKEYBYTES);
                let signer: SignPKey = copy_to_array(frombin); //get & verify the sig
                let valmsg = ok_or_continue!(wr_crypto_sign_open_inplace(smsg, &signer));
                //Now that that's done, let's parse the inner message
                let doc2 = ok_or_continue!(decode_document(&mut Cursor::new(valmsg)));
                debug!("backup msg is {}", doc2);
                ok_or_continue!(self.rollcheck(&doc2, &c, &mut backups)); //handle received rolls
            }
        }
        let good = main.recvd.elapsed() < secs(20) && main.failed.elapsed() > secs(300);
        if let Some(msg) = self.poll_roll(&mut backups[i], &c, good, nodeaddrs, None) {
            self.broadcast(msg, &c, &mut backups, Some(i));
        }
        Ok(())
    }

    pub fn poll_roll(
        &self,
        mut b: &mut ConnInfo,
        c: &Context,
        net_good: bool,
        nodeaddrs: &HashSet<SocketAddr>,
        other: Option<(&mut ConnInfo, &[u8])>,
    ) -> Option<Document> {
        let cid = &self.idkeys.sign.pk;
        let mut to_broadcast = None;
        //start roll if it's been 5 min since this backup's up but others've been working for 5m
        if b.recvd.elapsed() > Duration::new(35 * 8, 0) && net_good {
            if b.state.received_prop_expired() {
                // An uncontested proposal expired - could have been a resolved conflict
                if let ReceivedProposal { when, round, prop } = &b.state {
                    warn!("Uncontested round {:?} {} expired", when.elapsed(), round);
                    if *round > 1 {
                        if let Some(_) = &other {
                            warn!("Uncontested proposal was for primary but not ours. Ignoring");
                        } else if let None = prop.oldb {
                            info!("ROLL {}-{} cid {}", b.node.address, prop.addr, b64spk(cid));
                            //SEND FINAL ROLL NOTIFICATION
                            if let Err(e) = self.conn_roll(&b.node.key, &prop.key, &prop.addr) {
                                error!("Err sending new backup roll {}", e);
                                b.state = Chill; //it's really messed up. Reset
                            } else {
                                let (k, a) = (prop.key.clone(), prop.addr.clone());
                                b.swap_backup(k, a, c); //ROLL
                            }
                        }
                    }
                }
                b.state = Chill; //Reset; if it's bad we'll soon start re-rolling
            } else if b.state.is_chill() {
                //PHASE 1: send out a "down for u?" message over all channels. Wait 15 s
                info!("Downed node {} notifying {}", b.node.address, b64spk(cid));
                to_broadcast = Some(doc! {"rolk": binary_bson(&b.node.key), "rolp": "nodedown"});
                b.state = SentNodedown(Instant::now());
            } else if b.state.sent_nodedown_time_elapsed() {
                //PHASE 2: We haven't received any nopes and it's been another 15 seconds
                //Propose new backup node that isn't any of the primary or secondary nodes
                info!("Proposing roll {} for {}", b.node.address, b64spk(cid));
                let bp = binary_bson(&b.node.key); //the original node we're replacing
                let roll = rand_other_conn(c, &nodeaddrs); //tube, wad, rtt, node will be new backup
                let newb = binary_bson(&addrkey(&roll.3.address, &roll.3.key));
                let r = 0 as i32;
                let mut roldc = doc! {"rolk": bp, "rolp": "nodeprop", "newb": newb, "round": r};
                if let Some((ref standby, _)) = other {
                    roldc.insert("oldb", binary_bson(&standby.node.key[..]));
                }
                info!("Advertising {} for {} r {}", roll.3.address, b64spk(cid), r);
                to_broadcast = Some(roldc);
                b.state = Proposed {
                    when: Instant::now(),
                    rollover: roll,
                    round: 0,
                    count: 1,
                    prev: other.map(|(o, _)| o.node.key.clone()),
                };
            } else if b.state.proposed_time_elapsed() {
                //PHASE 3: we're all agreed. Send the final rollover message.
                if let Proposed {
                    when: _,
                    rollover: r,
                    round: _,
                    count: _,
                    prev,
                } = &b.state
                {
                    info!("New node {} rolling for {}", r.3.address, b64spk(cid));
                    //otherb will be the ConnInfo we're swapping - b or standby if rolling primary
                    //if it's rolling primary and the proposal has a new backup
                    let mut otherb: &mut ConnInfo = if let Some((standby, bblob)) = other {
                        if let Some(prv) = prev {
                            if *prv == standby.node.key {
                                //make new backup info blob with r, the new backup for the server
                                let mut bblob2 = [0; (32 + 19) * MAX_BACKUPS];
                                bblob2[..32 + 19].copy_from_slice(&addrkey(&r.3.address, &r.3.key));
                                bblob2[32 + 19..32 + 19 + bblob.len()].copy_from_slice(bblob);
                                let res = self.roll_prim(standby, b, self.seq()).and_then(
                                    |_| self.send_prim_roll(&bblob2[..]), //PRIMARY (b) ROLLING TO HOT STANDBY
                                );
                                log_err!(res, "roll primary");
                                standby
                            } else {
                                error!("Primary roll wrong standby?!"); //messed up, shouldn't happen
                                b.state = Chill; //Reset state and bail outta here
                                return None;
                            }
                        } else {
                            error!("Primary roll no prev?!"); //really messed up
                            b.state = Chill; //Reset state and bail outta here
                            return None;
                        }
                    //otherwise this is a backup that's ready to roll, so roll it if you can.
                    } else if let Err(e) = self.conn_roll(&b.node.key, &r.3.key, &r.3.address) {
                        error!("Err sending new backup roll {}", e);
                        b.state = Chill; //our state's messed up. Reset & bail outta here
                        return None;
                    } else {
                        b
                    };
                    //THE BELOW CODE SWAPS rol WITH b AND MARKS IT CHILL
                    let mut temp_bs = Chill; // dummy value
                    mem::swap(&mut temp_bs, &mut otherb.state); //allows us to drop mut ref to state
                    if let Proposed {
                        when: _,
                        rollover: rlo,
                        round: _,
                        count: _,
                        prev: _,
                    } = temp_bs
                    {
                        debug!("Swapping backup conn and making it chill");
                        let mut newbackinfo = ConnInfo::new(rlo, Instant::now()); //makes a chill CI
                        mem::swap(&mut newbackinfo, &mut otherb); //now swap in the new tube
                    } else {
                        error!("this shouldn't happen");
                    }
                }
            } else if b.state.conflict_expired() {
                if let Conflict {
                    when: _,
                    rollovers: rolls,
                    round,
                } = &b.state
                {
                    //Time for a new round. Maybe change your vote.
                    let num_votes = rolls.iter().map(|r| r.count).sum(); //# of all voting clients
                    let with_us = rolls[0].count; //number of clients that voted with us
                    let n = (num_votes as f64 / with_us as f64).ceil() as usize;
                    // n = ceil(num_votes / num_votes_that_voted_with_you)
                    //if we're in the minority or tied, flip for whether to switch votes
                    // n of course must be >= 2 since less than half the clients voted with you, so the dice
                    // will always flip at least 1/2 the time if you are tied or in the minority
                    // Note: always switching your vote isn't an option otherwise tie votes would flip flop forever
                    // And unreliable messages are used so they can be lost, and some of the time you might be wrong
                    // Also, if you have > 2 nodes to choose from, this and other failure modes are easier to happen
                    let newvote = if with_us * 2 <= num_votes && thread_rng().gen_range(0, n) > 0 {
                        rolls.iter().max_by_key(|r| r.count).unwrap().clone() //must unwrap; has > 0 elements
                    } else {
                        rolls[0].clone() //same as original
                    };
                    debug!("Conflict {} {} - {}", round, rolls[0].addr, newvote.addr);
                    let oldb = other.map(|(standby, _)| standby.node.key.clone());
                    let rnd = round + 1;
                    to_broadcast = Some(b.prop(rnd, &newvote.key, newvote.addr, oldb));
                    //and act like we just got it
                }
            }
        //just reconnect if we haven't gotten anything for 35+ sec
        } else if b.recvd.elapsed() > secs(35) && b.pinged.elapsed() > secs(1) {
            warn!("Back {} cid {} reconn", b.node.address, b64spk(cid));
            let (cli, mut hop) = hop_to(&b.node.address, &c, c.hops, 0); // get tube
            if let Some(flag) = &b.flag {
                log_err!(b.tube.send_vec(bdoc_to_u8vec(&doc! {"exit": true})), "bx"); //close old session if there
                flag.store(false, Relaxed);
            }
            //Reconnect connection
            mem::swap(&mut b.hop, &mut hop);
            close_wad_conn(hop); //close old hops
            b.tube = cli;
            b.rtt = 1000.0; //fake RTT
            b.flag = None; //new hop not joined yet. It will be joined next iteration
        } else if b.recvd.elapsed() > secs(15) && b.pinged.elapsed() > secs(1) {
            b.pinged = Instant::now(); //send a normal ping, every second for 15s
            let r = self.acks.lock().ok()?.iter().nth_back(0).map(|a| a.clone());
            let a = r.unwrap_or(-1..-1);
            let pkt = doc! {"ping": binary_bson(&cid[..]), "ack": bson!([a.start, a.end])};
            log_err!(b.tube.send_vec(bdoc_to_u8vec(&pkt)), "sending ping");
        }
        to_broadcast
    }

    fn chat_client_monitor_inner(&self, c: Context, snd: ChatSnd) -> SfRes<()> {
        let cid = &self.idkeys.sign.pk;
        let mut core = self.ci.lock()?;
        log_err!(core.tube.set_timeout(secs(1)), "ccm TO"); //timeout for a dedicated thread
        if let Err(e) = self.get_cached_acks(&c) {
            let msg = format!("Error loading cached messages {}", e);
            notify_err(&msg, &snd, &c)
        }
        let mut force_ack = true; //on first start, always send ping
        let mut retransed = false;
        while self.ctflag.load(Relaxed) {
            //ping meet server if we didn't just send something, we're missing messages, or every 15s
            if let Ok(acks) = self.acks.lock() {
                if force_ack
                    || !retransed
                        && (((acks.len() > 1 || (acks.len() == 1 && acks[0].start > 0))
                            && dur_millis(&core.pinged.elapsed())
                                > self.rttest.load(Relaxed) as f64)
                            || (core.recvd.elapsed() > secs(15)
                                && core.pinged.elapsed() > secs(15)))
                {
                    core.pinged = Instant::now();
                    //Send a ping with the last few ack ranges for the meet server
                    debug!("chat {} {} ping acks", b64spk(cid), acks.len());
                    let ackr = acks.iter().rev().next().map(|a| a.clone());
                    let a = ackr.unwrap_or(-1..-1);
                    let ping = doc! {"ping": binary_bson(&cid[..]), "ack": bson!([a.start, a.end])};
                    log_err!(core.tube.send_vec(bdoc_to_u8vec(&ping)), "ping");
                }
            }
            retransed = false; //reset flags
            force_ack = false;
            //TODO use select! to wait on all the backups and main self
            if let Ok(rcvbuf) = core.tube.recv_vec() {
                core.recvd = Instant::now();
                if let Ok(doc) = decode_document(&mut Cursor::new(&rcvbuf)) {
                    match self.pmsg(&c, &rcvbuf, doc, &snd, &mut core.tube) {
                        Ok(ack) => force_ack = ack,
                        Err(e) => info!("chat {} hrecv error {} closing?", b64spk(cid), e),
                    }
                }
            } else {
                if core.recvd.elapsed() > secs(20) {
                    core.failed = Instant::now(); //detected a failure. Even if it comes back, remember this
                }
                //No main server message this time, poll backups and do roll checks
                let mut backups = self.backups.lock()?;
                let mut addrs = HashSet::from_iter(backups.iter().map(|b| b.node.address.clone()));
                addrs.insert(core.node.address.clone());
                //roll check main vs backup 0
                if backups.len() > 1 {
                    let mut bblob = [0; (32 + 19) * (MAX_BACKUPS - 1)]; //skip [0], our roll
                    for (i, back) in backups.iter().skip(1).enumerate() {
                        let ak = addrkey(&back.node.address, &back.node.key);
                        bblob[(i * (32 + 19))..((i + 1) * (32 + 19))].copy_from_slice(&ak[..]);
                    }
                    let good = backups[0].recvd.elapsed() < secs(20)
                        && backups[0].failed.elapsed() > secs(300);
                    let bl = backups.len();
                    let opts = Some((&mut backups[0], &bblob[..(32 + 19) * (bl - 1)])); //the backup and slice we want to use
                    if let Some(msg) = self.poll_roll(&mut core, &c, good, &addrs, opts) {
                        self.broadcast(msg, &c, &mut backups, None);
                    }
                }
                for i in 0..backups.len() {
                    log_err!(self.check_backup_reconn(&mut backups[i], i, &c), "");
                    log_err!(self.poll_backup(&mut backups, i, &c, &mut core, &addrs), "");
                }
                trace!("chat {} client recv nothing", b64spk(cid));
            }
            //do we need to retransmit something?
            for (hsh, mut qd) in ok_or_continue!(self.queued.lock()).iter_mut() {
                let (ms, rtt) = (dur_millis(&qd.sent.elapsed()), self.rttest.load(Relaxed));
                if ms > rtt as f64 * 2.0 {
                    qd.resent = true; //time > RTT * 2 then resend the message
                    core.pinged = Instant::now();
                    qd.sent = core.pinged;
                    info!("RTO {} {} {} {}", ms, rtt, qd.data.len(), b64sk(&hsh));
                    log_err!(self.stube.read()?.send(&qd.data), "Error resending data");
                    retransed = true;
                    break;
                }
            }
        }
        Ok(())
    }

    fn check_backup_reconn(&self, b: &mut ConnInfo, i: usize, c: &Context) -> SfRes<()> {
        if let None = b.flag {
            debug!("Trying to join backup {} {}", i, b.node.address);
            b.pinged = Instant::now();
            let mk = &c.keys.sign.pk; //my pubkey
            let (doc, _) = jn(mk, &self.idkeys, &b.tube, &b.node, &self.key, b.rtt, c)?;
            let ckey = leneq(doc.get_binary_generic("chatkey")?, 32)?; //try to join
            b.recvd = Instant::now(); //join response is a received packet
            let (mut btube_temp, _dumm2) = Tube::pair(false); //dummy tube to swap out and back the backup tube
            mem::swap(&mut btube_temp, &mut b.tube); //btube_temp = b.tube
            let (mut wtube, flag) = wrapping_tubepair(copy_to_array(ckey), btube_temp)?;
            mem::swap(&mut wtube, &mut b.tube); //backup tube = wrapped tube
            b.flag = Some(flag); //TODO ensure no "backups" in doc
        }
        Ok(())
    }

    //Reads up to 10 cached chats in descending order starting at seq, adding them to the send queue
    pub fn get_msgs(&self, seqo: Option<i64>, c: &Context, snd: &ChatSnd) -> usize {
        let mut count = 0;
        let mut to_handle = Vec::with_capacity(10);
        if let Ok(acks) = self.acks.lock() {
            let mut myseq = prev_acked(&*acks, seqo.unwrap_or(i64::max_value()));
            while myseq.is_some() && count < 10 {
                let seq = myseq.unwrap();
                let ckey = c.cache.get(&db_key(&self.idkeys.sign.pk, seq, b"mesg")[..]);
                if let Err(e) = ckey.map_err(|e| SfErr::from(e)).and_then(|enc| {
                    debug!("Reading msgs; count {}", count);
                    let d = decode_document(&mut Cursor::new(&*enc.ok_or_else(sfnone)?))?;
                    if d.get_document("e").and_then(|e| e.get_str("op").map(|op| op != "del" && op != "ume" && op != "fwr")).unwrap_or(true) {
                        count += 1;
                        to_handle.push((d, seq)); //handle after you release lock
                    }
                    Ok(())
                }) {
                    error!("Could not get {}: {}", seq, e)
                }
                myseq = prev_acked(&*acks, seq);
            }
        } else {
            error!("Error locking acks");
        }
        for (d, seq) in to_handle {
            if let Err(e) = self.encmsg(d, c, snd, seq) {
                error!("Could not handle {}: {}", seq, e)
            }
        }
        count
    }

    //mix of a file ID, offset, and convoid saves us from sending/storing different nonces per chunk
    pub fn fblock_tag(&self, fnonce: i64, rand: i64, offset: i64) -> SfRes<Nonce> {
        trace!("fbt fnonce {} rnd {} offset {}", fnonce, rand, offset);
        if offset % 1024 != 0 {
            return Err(SfErr::BadOffset);
        }
        let mut buf = [0; 32];
        buf[..8].copy_from_slice(b"fbloktag");
        buf[8..16].copy_from_slice(&u64_bytes(fnonce as u64)[..]);
        buf[16..24].copy_from_slice(&u64_bytes(offset as u64)[..]);
        buf[24..].copy_from_slice(&u64_bytes(rand as u64)[..]);
        let authfull = wr_crypto_auth(&buf[..], &self.key);
        Ok(*array_ref![authfull, 0, 24])
    }

    //Figures out which acks we have already cached by enumerating DB keys
    fn get_cached_acks(&self, c: &SfContext) -> SfRes<()> {
        let start = db_key(&self.idkeys.sign.pk, 0, b"mesg");
        let mut acks = self.acks.lock()?;
        for ckey_res in c.cache.scan_prefix(&start[..36]).keys() {
            let dbk = ok_or_continue!(ckey_res);
            if dbk.len() == 32 + 8 + 4 && dbk[40..44] == *b"mesg" {
                update_acks(&mut acks, bytes_to_u64(&dbk[32..40]) as i64);
            }
        }
        Ok(())
    }

    //Make an RPC call on a session (usually file RPC) to the meet node, which sees the BSON doc
    //That means you need to manually encrypt your E2E bits first. Also, the BSON must have an ID
    fn conn_call(&self, bd: &Document) -> SfRes<Document> {
        let bytes = bdoc_to_u8vec(bd);
        let id = bd.get_i64("id")?;
        let sent = Instant::now();
        for tri in 0..5 {
            let l = if tri > 0 { Level::Info } else { Level::Debug }; //retransmits make info log
            log!(l, "{:?} {:X} {} #{}", bd.get_str("f"), id, bytes.len(), tri);
            let mut callk = self.calls.lock()?; //hold lock until calls insert to prevent race
            log_err!(self.stube.read()?.send(&bytes), "sending");
            callk.insert(id, std::thread::current());
            drop(callk);
            let rttest = self.rttest.load(Relaxed);
            let dur = Duration::from_millis((100 + rttest * (3 + tri) / 2) as u64);
            let start = Instant::now();
            loop {
                std::thread::park_timeout(dur); //Not a race since park after unpark doesn't block
                if let Some(doc) = self.resps.lock()?.remove(&id) {
                    self.calls.lock()?.remove(&id);
                    if tri == 0 {
                        update_rtt(&self.rttest, &Instant::now().duration_since(sent));
                    }
                    debug!("{:?} {:X} response (try {})", bd.get_str("f"), id, tri);
                    return Ok(doc);
                } else if start.elapsed() >= dur {
                    break; //max 1.5 * rtt + 100ms has elapsed
                }
            }
        }
        self.calls.lock()?.remove(&id);
        self.resps.lock()?.remove(&id);
        Err(SfErr::NoneErr) //none found
    }

    pub fn seq(&self) -> i64 {
        let l = self.acks.lock().ok();
        l.and_then(|a| a.iter().nth_back(0).map(|a| a.end))
            .unwrap_or(1)
    }

    //Roll a backup to a different node on the meet node (just tells them, doesn't swap ours)
    pub fn conn_roll(&self, old_key: &SignPKey, key: &SignPKey, addr: &SocketAddr) -> SfRes<()> {
        info!("conn_roll {} to {}", b64spk(&self.idkeys.sign.pk), addr);
        let (oldb, newb) = (binary_bson(old_key), binary_bson(key));
        let (newa, id) = (binary_bson(&sockaddr_to_bin(addr)), rand_i64());
        let d = doc! {"roll": oldb, "newb": newb, "newa": newa, "id": id};
        let bin = bdoc_to_u8vec(&d);
        let hsh = wr_crypto_hash_sha256(&bin);
        debug!("cr {} bytes hsh {}", bin.len(), b64sk(&hsh));
        self.stube.read()?.send(&bin)?;
        self.queued.lock()?.insert(hsh, SentMsg::new(bin));
        Ok(())
    }

    //Tell server it's promoted by sending {"promote": <signedpromo>, "backups": ...}}
    //Note we do NOT wait for it to acknowledge this though to avoid deadlocks
    pub fn send_prim_roll(&self, bblob: &[u8]) -> SfRes<()> {
        info!("prim_roll to backup for {}", b64spk(&self.idkeys.sign.pk));
        let host_msg = db_key(&self.meet.read()?.key, self.seq(), b"host");
        let sig = wr_crypto_sign(&host_msg[..], &self.idkeys.sign.sk);
        let hsh = wr_crypto_hash_sha256(&sig);
        let (backs, id) = (binary_bson(&bblob[..]), rand_i64());
        let bin = bdoc_to_u8vec(&doc! {"promote": binary_bvec(sig), "backups": backs, "id": id});
        debug!("spr {} bytes hsh {}", bin.len(), b64sk(&hsh));
        self.stube.read()?.send(&bin)?;
        self.queued.lock()?.insert(hsh, SentMsg::new(bin));
        Ok(())
    }

    //Tells server to wipe our participant ID from the active client list - we're out
    pub fn conn_leave(&self, ctxt: &Context) -> SfRes<Document> {
        debug!("conn_leave leaving");
        let nonce = array_ref![self.idkeys.sign.pk, 0, 24]; //fixed nonce for participant ID
        let p = wr_crypto_secretbox_easy_n(&ctxt.keys.sign.pk, nonce, &self.key); //encrypted part ID
        self.conn_call(&doc! {"f": "lve", "id": rand_i64(), "lve": binary_bvec(p)})
    }

    //Make a new file on the meet node, returning the file ID
    pub fn conn_fnew(&self, path: &str, nonce: i64, locked: bool) -> SfRes<i64> {
        let oid = if locked {
            wr_randomkey()
        } else {
            wr_crypto_auth(path.as_bytes(), &self.key)
        }; // file unique ID = HMAC of path to avoid duplication
        let pad = binary_bson(&PADDING[..(64 - (path.as_bytes().len() % 64)) % 64]);
        let bd = bdoc_to_u8vec(&doc! { "path": path, "nonce": nonce, "pad": pad });
        let metaenc = wr_crypto_secretbox_easy(&bd, &self.key); //metadata including real path.
        let b = doc! {
            "f": "new",
            "id": rand_i64(),
            "meta": binary_bvec(metaenc),
            "fidoid": binary_bson(&oid[..]), //dummy fidoid
            "origid": binary_bson(&oid[..]),
            "locked": locked
        };
        Ok(self.conn_call(&b)?.get_i64("fid")?)
    }

    pub fn conn_newfold(&self, path: &str) -> SfRes<i64> {
        let pad = binary_bson(&PADDING[..(64 - (path.as_bytes().len() % 64)) % 64]);
        let metabin = bdoc_to_u8vec(&doc! { "path": path, "type": "fold", "pad": pad });
        let metaenc = wr_crypto_secretbox_easy(&metabin, &self.key); //metadata including real path
        let b = doc! {
            "f": "new",
            "id": rand_i64(),
            "meta": binary_bvec(metaenc),
            "fidoid": binary_bson(&[0; 32][..]), //dummy fidoid
            "origid": binary_bson(&wr_crypto_auth(path.as_bytes(), &self.key)),
            "locked": false
        };
        Ok(self.conn_call(&b)?.get_i64("fid")?)
    }

    //Delete an encrypted file on the meet node
    pub fn conn_fdel(&self, fid: i64) -> SfRes<i64> {
        debug!("conn_fdel deleting {}", fid);
        self.conn_call(&doc! {"f": "del", "fid": fid, "id": rand_i64(), "pad": 0i64})
            .and_then(|doc| Ok(doc.get_i64("dls")?))
    }

    //Truncate an encrypted file on the meet node. Must be 1024 byte aligned.
    pub fn conn_ftrc(&self, fid: i64, size: i64) -> SfRes<i64> {
        debug!("conn_ftrc truncating {} to {} plain bytes", fid, size);
        let off = (size / 1024) * (1024 + CRYPTO_BOX_MACBYTES as i64 + 8); //Calc new size
        self.conn_call(&doc! {"f": "trc", "fid": fid, "len": off, "id": rand_i64()})
            .and_then(|doc| Ok(doc.get_i64("trc")?))
    }

    //List active FID's starting at fid
    pub fn conn_fact(&self, fid: i64) -> SfRes<Vec<u8>> {
        debug!("conn_fact listing active fids >= {}", fid);
        let mut d = self.conn_call(&doc! {"f": "act", "fid": fid, "id": rand_i64()})?;
        if let Bson::Binary(_, v) = d.remove("res").ok_or(SfErr::NoneErr)? {
            return Ok(v);
        }
        Err(SfErr::NodeError(("fail".to_string(), d)))
    }

    //Get encrypted metadata about a file on the meet node. Returns inner and outer metadata.
    pub fn conn_fmeta(&self, fid: i64) -> SfRes<(Document, Document, u64)> {
        debug!("conn_fmeta getting {}", fid);
        let mut doc =
            self.conn_call(&doc! {"f": "met", "fid": fid, "id": rand_i64(), "pad": 0i64})?;
        if doc.get_bool("del").unwrap_or(false) {
            return Ok((doc! {}, doc, 0)); //deleted
        }
        let plaintext_len = if let Ok(reportedsize) = doc.get_i64("size") {
            let macbytes = CRYPTO_BOX_MACBYTES as i64 + 8;
            let blocks = reportedsize / (1024 + macbytes);
            let last_chunk_encrypted_len = reportedsize % (1024 + macbytes);
            let trailer = if last_chunk_encrypted_len < macbytes {
                0
            } else {
                last_chunk_encrypted_len - macbytes
            };
            (blocks * 1024 + trailer) as u64 //figure out real size
        } else {
            0
        };
        let metaenc = doc.get_binary_generic_mut("meta")?;
        let plain = wr_crypto_secretbox_open(metaenc, &self.key)?;
        let pd = decode_document(&mut Cursor::new(plain))?;
        debug!("meta {} {} {}", pd, doc, plaintext_len);
        Ok((pd, doc, plaintext_len))
    }

    //Set encrypted metadata about a file on the meet node to rename the file and get a new fid
    pub fn conn_frename(&self, srcpath: &str, nonce: i64, path: &str) -> SfRes<i64> {
        debug!("conn_frename moving {} to {}", srcpath, path);
        let oid = wr_crypto_auth(path.as_bytes(), &self.key); //orig ID = HMAC of path; avoids dups
        let pad = binary_bson(&PADDING[..(64 - (path.as_bytes().len() % 64)) % 64]);
        let mvec = bdoc_to_u8vec(&doc! {"path": path, "nonce": nonce, "pad": pad });
        let metaenc = wr_crypto_secretbox_easy(&mvec, &self.key); //metadata including real path.
        let b = doc! {
            "f": "ume",
            "id": rand_i64(),
            "fidoid": binary_bson(&wr_crypto_auth(srcpath.as_bytes(), &self.key)),
            "meta": binary_bvec(metaenc),
            "origid": binary_bson(&oid[..]),
            "locked": false
        };
        Ok(self.conn_call(&b)?.get_i64("fid")?)
    }

    //Lock an encrypted file on the meet node
    pub fn conn_flock(&self, fid: i64) -> SfRes<i64> {
        debug!("conn_flock locking {}", fid);
        self.conn_call(&doc! {"f": "lck", "fid": fid, "id": rand_i64(), "pad": 0i64})
            .and_then(|doc| Ok(doc.get_i64("lck")?))
    }

    //Lock an encrypted file on the meet node by path
    pub fn conn_fpathlock(&self, path: &str) -> SfRes<i64> {
        debug!("conn_fpathlock locking {}", path);
        let fidoid = wr_crypto_auth(path.as_bytes(), &self.key);
        let bd = doc! {"f": "lck", "fidoid": binary_bson(&fidoid[..]), "id": rand_i64()};
        self.conn_call(&bd).and_then(|doc| Ok(doc.get_i64("lck")?))
    }

    //Unlock an encrypted file on the meet node
    pub fn conn_funlock(&self, fid: i64) -> SfRes<i64> {
        debug!("conn_funlock unlocking {}", fid);
        self.conn_call(&doc! {"f": "ulk", "fid": fid, "id": rand_i64(), "pad": 0i64})
            .and_then(|doc| Ok(doc.get_i64("ulk")?))
    }

    //Start reading an encrypted file on the meet node as a stream, return the stream id
    pub fn conn_sread(&self, fid: i64, offset: i64) -> SfRes<i64> {
        let remote_offset = (offset / 1024) * (1024 + CRYPTO_BOX_MACBYTES as i64 + 8); //Calc new offset
        debug!("conn_sread {} off {} ({})", fid, offset, remote_offset);
        let b = doc! {"f": "res", "fid": fid, "off": remote_offset, "id": rand_i64()};
        self.conn_call(&b).and_then(|doc| {
            doc.get_i64("res")
                .map_err(|_| SfErr::StreamFail(doc.get_str("err").unwrap_or("").to_string()))
        })
    }

    //Start writing an encrypted file on the meet node as a stream
    pub fn conn_swrite(&self, fid: i64, offset: i64) -> SfRes<i64> {
        let remote_offset = (offset / 1024) * (1024 + CRYPTO_BOX_MACBYTES as i64 + 8); //Calc new offset
        debug!("swrite {} off {} ({})", fid, offset, remote_offset);
        let b = doc! {"f": "wrs", "fid": fid, "off": remote_offset, "id": rand_i64()};
        self.conn_call(&b).and_then(|doc| {
            doc.get_i64("wrs")
                .map_err(|_| SfErr::StreamFail(doc.get_str("err").unwrap_or("").to_string()))
        })
    }

    //Close encrypted file stream on the meet node
    pub fn conn_sclose(&self, sid: i64, fid: i64) -> SfRes<()> {
        debug!("conn_sclose {}", sid);
        let bd = doc! {"f": "cls", "sid": sid, "fid": fid, "id": rand_i64()};
        self.conn_call(&bd).and_then(|doc| {
            doc.get_i64("cls")
                .map(|_| ())
                .map_err(|_| SfErr::StreamFail(doc.get_str("err").unwrap_or("").to_string()))
        })
    }

    //send an empty message to notify everybody else we've joined, with our display name.
    pub fn send_display(&self, ctxt: &Context) -> SfRes<Sha256Hash> {
        info!("Telling connection our name");
        let dn = ctxt.display_name();
        let pad = binary_bson(&PADDING[..137 - (dn.as_bytes().len() % 137)]); //inner send to 343
        let bd = doc! {"text": "", "timestamp": epoch_timestamp(), "dname": dn, "pad": pad};
        self.send_conn(&ctxt.keys, &bdoc_to_u8vec(&bd), true)
    }

    //Sends a signed, encrypted message over a tube, returns the message and its inner hash
    pub fn tube_msg(&self, k: &Keys, blob: &[u8], re: bool) -> SfRes<(Vec<u8>, Sha256Hash)> {
        const PKLEN: usize = CRYPTO_SIGN_PUBLICKEYBYTES;
        let smsglen = PKLEN + blob.len() + CRYPTO_SIGN_BYTES;
        const SYM_ENC_BYTES: usize = CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES;
        let mut buf: SmallVec<[_; 4096]> = smallvec![0; smsglen * 2 + SYM_ENC_BYTES];
        let (smsg, data) = buf.split_at_mut(smsglen); // (spk smsg) (encmsg)
        (&mut smsg[..PKLEN]).copy_from_slice(&k.sign.pk[..]); //1st 32 bytes = sign pubkey
        wr_crypto_sign_inplace(blob, &mut smsg[PKLEN..], &k.sign.sk)?; //rest = signed msg
        wr_crypto_secretbox_inplace(smsg, data, &self.key); // encmsg = encrypt(spk, smsg)
        let code = if re { "m" } else { "u" }; // m for message u for unreliable message
        let res = bdoc_to_u8vec(&doc! { code: binary_bson(&data) });
        let h = if re {
            wr_crypto_hash_sha256(data)
        } else {
            [0; 32]
        };
        Ok((res, h))
    }

    //Sends a signed, encrypted message over a connection, can cache to enable "reliable" delivery.
    pub fn send_conn(&self, k: &Keys, blob: &[u8], reliable: bool) -> SfRes<Sha256Hash> {
        let (bin, hsh) = self.tube_msg(k, blob, reliable)?;
        debug!("sci {} bytes hsh {}", bin.len(), b64sk(&hsh));
        self.stube.read()?.send(&bin)?;
        if reliable {
            self.queued.lock()?.insert(hsh, SentMsg::new(bin));
        }
        Ok(hsh)
    }

    // bug out
    pub fn close(&self) {
        info!("Exiting connection {}", b64spk(&self.idkeys.sign.pk));
        self.ctflag.store(false, Relaxed); // continue = false
        let b = bdoc_to_u8vec(&doc! {"exit": true});
        if let Ok(stb) = self.stube.read() {
            log_err!(stb.send_vec(b), "sending exit");
        }
    }

    //participants (base64key -> (display_name, verified))
    pub fn participants_map(&self, ctxt: &SfContext) -> BTreeMap<KeyString, (String, bool)> {
        let mut partsypants = BTreeMap::new();
        debug!("participants locking");
        if let Ok(p) = self.participants.lock() {
            for partsy in p.iter() {
                partsypants.insert(b64spk(&partsy), ("".to_string(), false));
            }
        } else {
            error!("Couldn't lock participants!");
        }
        debug!("contacts locking");
        if let Ok(c) = ctxt.contacts.lock() {
            //get display name for each participant if known
            for (b64, name_holder) in partsypants.iter_mut() {
                if let Some(tact) = c.get(b64) {
                    *name_holder = (tact.name.clone(), tact.verified.is_some());
                }
            }
        }
        debug!("participants done");
        partsypants
    }

    fn broadcast(&self, d: Document, c: &SfContext, bs: &mut Vec<ConnInfo>, skip: Option<usize>) {
        let blob = bdoc_to_u8vec(&d);
        //No special err msg since err is only if keys are bad (already checked)
        let pkt = match self.tube_msg(&c.keys, &blob, false) {
            Ok((pkt, _)) => pkt,
            Err(_e) => return,
        };
        for i in 0..bs.len() {
            if skip.map(|s| i != s).unwrap_or(true) {
                log_err!(bs[i].tube.send(&pkt), "b broadcast"); //also send messages through backups
            }
        }
        if let Ok(stb) = self.stube.read() {
            log_err!(stb.send_vec(pkt), "sending broadcast");
        }
    }

    fn inner_rollcheck(&self, doc: &Document, mut b: &mut ConnInfo) -> SfRes<Option<Document>> {
        let rolp = doc.get_str("rolp")?;
        if rolp == "nodedown" {
            //It's up if we've received stuff from it and in the prev minute so let them know
            if b.flag.is_some() && b.recvd.elapsed() < secs(60) {
                info!("nodedown but {} is up", b.node.address);
                let nup = doc! {"rolk": binary_bson(&b.node.key), "rolp": "nodeisup"};
                return Ok(Some(nup));
            } else if let Chill = b.state {
                info!("received new nodedown"); //A possibly legit backup down message
                let when = Instant::now();
                b.state = ReceivedNodedown(when);
            } else {
                info!("received new nodedown in unexpected state");
            }
        } else if rolp == "nodeisup" {
            if let Chill = b.state {
                return Ok(None);
            }
            debug!("{} is apparently up, resetting roll state", b.node.address);
            if let SentNodedown(time_sent) = b.state {
                //Somebody saw it in the past 60 seconds from receiving our message, so at least sent - 60s
                if let Some(subbed) = time_sent.checked_sub(secs(60)) {
                    b.recvd = subbed;
                }
            } else if let Proposed {
                when,
                round: _,
                ref mut rollover,
                count: _,
                prev: _,
            } = b.state
            {
                if let Some(subbed) = when.checked_sub(secs(60)) {
                    b.recvd = subbed;
                }
                let mut dummyhop = None; //leave nothing behind
                mem::swap(&mut rollover.1, &mut dummyhop); //swap out so we own it so we can close it
                close_wad_conn(dummyhop);
            }
            b.state = Chill; //Reset its state to be cool again
        } else if rolp == "nodeprop" {
            let newb = leneq(doc.get_binary_generic("newb")?, 19 + 32)?; //roll proposal received.
            let round = doc.get_i32("round")?;
            let ob = doc.get_binary_generic("oldb").ok();
            let oldk: Option<SignPKey> =
                ob.and_then(|bin| leneq(bin, 32).map(|b| copy_to_array(b)).ok());
            let newaddr = debin_addr(array_ref![newb, 0, 19]);
            let newkey = array_ref![newb, 19, 32];
            if b.flag.is_some() && b.recvd.elapsed() < secs(60) {
                info!("nodeprop but {} is up", b.node.address);
                let rolp = doc! {"rolp": "nodeisup", "rolk": binary_bson(&b.node.key)};
                return Ok(Some(rolp));
            } else if let ReceivedProposal {
                when: _,
                round: r,
                prop,
            } = &mut b.state
            {
                if *r < round {
                    return Ok(Some(b.prop(round, newkey, newaddr, oldk)));
                } else if *r > round {
                    warn!("Node rollover spurious round prop? {} vs {}", *r, round);
                    return Ok(None); //packet from a previous round? Ignore
                } else if *newkey != prop.key {
                    let na = &b.node.address;
                    info!("Conflict {} {} - {}", na, b64spk(newkey), b64spk(&prop.key));
                    let newprop = RollProp::new(newkey.clone(), newaddr, oldk);
                    let (now, rolls) = (Instant::now(), vec![*prop, newprop]);
                    b.state = Conflict {
                        when: now,
                        round: *r,
                        rollovers: rolls,
                    };
                } else {
                    info!("Another concurring proposal for {} received", prop.addr);
                    prop.count += 1; // Increment count of proposal
                }
            } else if let Conflict {
                when: _,
                round: r,
                rollovers: ref mut rolls,
            } = &mut b.state
            {
                if *r < round {
                    return Ok(Some(b.prop(round, newkey, newaddr, oldk)));
                } else if *r > round {
                    warn!("conflict {} bad round {} vs {}", &b.node.address, *r, round);
                    return Ok(None); //packet from a previous round? Ignore
                }
                for ref mut prop in rolls.iter_mut().filter(|p| p.key == *newkey) {
                    prop.count += 1; //Look for this proposal; increment count if found
                    return Ok(None);
                }
                rolls.push(RollProp::new(*newkey, newaddr, oldk)); //otherwise add a new proposal
            } else if let Proposed {
                when: _,
                round: ref mut r,
                rollover,
                ref mut count,
                prev,
            } = &mut b.state
            {
                if *r < round {
                    warn!("new round-missed conflict? {} > {}", round, *r); //old round's gone
                    let ourv = binary_bson(&addrkey(&rollover.3.address, &rollover.3.key)); //prep our vote (first received)
                    let bp = binary_bson(&b.node.key); //the original node we're replacing
                    let vote = doc! {"rolp": "nodeprop", "rolk": bp, "newb": ourv, "round": round};
                    if rollover.3.key == *newkey {
                        *count += 1;
                        *r = round;
                    } else {
                        //different proposed backup
                        let mut dummyhop = None; //take ownership over the hop by swapping with
                        mem::swap(&mut rollover.1, &mut dummyhop); //None so we can close it
                        close_wad_conn(dummyhop); //then bump
                        b.state.rcv_prop(round, *newkey, newaddr, oldk); //to newly received
                    }
                    return Ok(Some(vote));
                } else if *r > round {
                    warn!("Rollover proposed spurious round prop? {} vs {}", *r, round);
                    return Ok(None); //packet from a previous round? Ignore
                } else if *newkey != rollover.3.key {
                    let bnad = &b.node.address;
                    info!("conflict {} {}-{}", bnad, newaddr, rollover.3.address);
                    //different proposed backup
                    let mut dummyhop = None; //take ownership over the hop by swapping with
                    mem::swap(&mut rollover.1, &mut dummyhop); //an empty one so we can close it
                    close_wad_conn(dummyhop); //then bump
                    let mut ours =
                        RollProp::new(rollover.3.key.clone(), rollover.3.address.clone(), *prev);
                    ours.count = *count;
                    b.state = Conflict {
                        when: Instant::now(),
                        round: *r,
                        rollovers: vec![ours, RollProp::new(*newkey, newaddr, oldk)],
                    };
                } else {
                    info!("Concurring proposal for {} received", rollover.3.address);
                    *count += 1; // Increment count of proposal
                }
            } else {
                return Ok(Some(b.prop(round, newkey, newaddr, oldk)));
            }
        }
        Ok(None)
    }

    //Checks for whether a message is a rollover and handles if so.
    fn rollcheck(&self, doc: &Document, c: &SfContext, backups: &mut Vec<ConnInfo>) -> SfRes<()> {
        if let Ok(rolk) = doc.get_binary_generic("rolk") {
            let k = leneq(rolk, 32)?;
            for b in backups.iter_mut().filter(|b| &b.node.key[..] == k) {
                match self.inner_rollcheck(doc, b) {
                    Ok(Some(to_broadcast)) => {
                        self.broadcast(to_broadcast, &c, backups, None);
                        break;
                    }
                    Err(e) => warn!("Bad roll doc {}", e),
                    _ => break,
                }
            }
        }
        Ok(())
    }

    //Handles a plaintext (decrypted) chat by parsing, validating, and notifying the user
    fn handle(&self, p: &[u8], c: &Context, snd: &ChatSnd, seq: i64) -> SfRes<()> {
        if p.len() < CRYPTO_SIGN_PUBLICKEYBYTES + CRYPTO_SIGN_BYTES {
            return Err(SfErr::BadSignatureErr);
        }
        let (frombin, smsg) = p.split_at(CRYPTO_SIGN_PUBLICKEYBYTES);
        let signer: SignPKey = copy_to_array(frombin); //Now let's get & verify the sig
        let valmsg = wr_crypto_sign_open_inplace(smsg, &signer)?;
        //Now that that's done, let's decode the inner message; see if it has a display name update
        let docin = decode_document(&mut Cursor::new(valmsg))?;
        if let Ok(dname) = docin.get_str("dname") {
            log_err!(add_tact(dname.to_string(), frombin, None, &c), "tact");
        }
        //check if it's a rollover/failure status message.
        log_err!(self.rollcheck(&docin, &c, &mut *self.backups.lock()?), "");
        // sync log connection notification
        if signer != c.keys.sign.pk || self_conn_notif(&docin, c, snd, seq).is_err() {
            if let Ok(mut parts) = self.participants.lock() {
                parts.insert(signer.clone()); //ensure the sender is in our participants list
            }
            let a = self.acks.lock()?;
            if a.iter().rev().next().map(|c| c.end > seq + 1) == Some(true)
                && docin.get_bool("shared") == Ok(true)
            {
                return Ok(()); //Don't resend old shared file notifications
            }
            info!("{} msg {}", b64spk(&self.idkeys.sign.pk), b64spk(&signer));
            snd.send(ChatMsg {
                doc: docin,
                midpoint: json!({}),
                signer: signer,
                convoid: Some(self.idkeys.sign.pk.clone()),
                seq: Some(seq),
            })?;
        }
        Ok(())
    }

    //processes an encrypted message
    fn encmsg(&self, mut d: Document, c: &Context, s: &ChatSnd, seq: i64) -> SfRes<()> {
        if let Ok(encmsg) = d.get_binary_generic_mut("m") {
            let decrypted = wr_crypto_secretbox_open(encmsg, &self.key)?;
            self.handle(decrypted, c, s, seq)
        } else if let Ok(encmsg) = d.get_binary_generic_mut("u") {
            let decrypted = wr_crypto_secretbox_open(encmsg, &self.key)?;
            self.handle(decrypted, c, s, seq)
        } else {
            debug!("getting e from {}", d); //Midpoint server notice/extra info? Should have "e"
            let mut e = if let Some(Bson::Document(e)) = d.remove("e") {
                e
            } else {
                return Err(SfErr::BadMessage);
            };
            let innermeta = if let Ok(met) = e.get_binary_generic_mut("meta") {
                let plain = wr_crypto_secretbox_open(met, &self.key)?;
                let d = decode_document(&mut Cursor::new(plain))?;
                debug!("Decrypted inner {}", d);
                e.remove("meta");
                e.remove("oid"); //Also remove OID if present (it's another binary one)
                d
            } else {
                doc! {}
            };
            if let Ok(op) = e.get_str("op") {
                if op == "del" {
                    if let Ok(id) = e.get_i64("fid") {
                        let metakey = db_key(&self.idkeys.sign.pk, id, b"meta");
                        log_err!(c.cache.remove(&metakey[..]), "file meta cache prune");
                    }
                }
                if op == "del" || op == "ume" || op == "fwr" {
                    let a = self.acks.lock()?;
                    if a.iter().rev().next().map(|c| c.end > seq + 1) == Some(true) {
                        return Ok(()); //Don't resend old shared file notifications
                    }
                } else if op == "roll" {
                    //{"e":{"op":"roll", "oldb":ob, "newb":nb, "newa":na}, "q":c.seq}
                    let oldb = leneq(e.get_binary_generic("oldb")?, 32)?;
                    let newb = leneq(e.get_binary_generic("newb")?, 32)?; //signpkey of new node
                    let newa = leneq(e.get_binary_generic("newa")?, 19)?; //address of new node
                    let newaddr = debin_addr(array_ref![newa, 0, 19]);
                    let mut baks = self.backups.lock()?;
                    for b in baks.iter_mut().filter(|b| &b.node.key[..] == oldb) {
                        //FINAL ROLL CONFIRMATION so close this backup conn and open the new one
                        b.swap_backup(copy_to_array(newb), newaddr, c);
                    }
                } else if op == "lve" {
                    let part = leneq(e.get_binary_generic("lve")?, PIDLEN)?; //{"op":"lve", "lve": p}
                    let n = array_ref![&self.idkeys.sign.pk, 0, CRYPTO_BOX_NONCEBYTES];
                    let p_verified = wr_crypto_secretbox_open_easy_n(part, n, &self.key)?;
                    let verif_key: SignPKey = copy_to_array(&p_verified);
                    self.participants.lock()?.remove(&verif_key);
                    let left_member = b64spk(&verif_key).to_string();
                    debug!("{} left", left_member);
                    e.insert("lve", left_member);
                } else if op == "ent" {
                    let part = leneq(e.get_binary_generic("ent")?, PIDLEN)?; //{"op":"ent", "ent": p}
                    let n = array_ref![&self.idkeys.sign.pk, 0, CRYPTO_BOX_NONCEBYTES];
                    let p_verified = wr_crypto_secretbox_open_easy_n(part, n, &self.key)?;
                    self.participants.lock()?.insert(copy_to_array(&p_verified));
                    let new_member = b64spk(&copy_to_array(&p_verified)).to_string();
                    debug!("{} entered", new_member);
                    e.insert("ent", new_member);
                }
            }
            let jsmsg: Value = bson::from_bson(bson::Bson::Document(e))?;
            debug!("hce jsmsg {}", jsmsg);
            Ok(s.send(ChatMsg {
                doc: innermeta,
                midpoint: jsmsg,
                signer: [0; 32],
                convoid: Some(self.idkeys.sign.pk.clone()),
                seq: Some(seq),
            })?)
        }
    }

    // Parses out  all the different kinds of messages you can have. Returns whether we need to ack
    fn pmsg(&self, c: &Context, b: &[u8], d: Document, s: &ChatSnd, t: &mut Tube) -> SfRes<bool> {
        let doc = d;
        debug!("pmsg {} bytes: {:?}", b.len(), doc.keys().next());
        //if it has a sequence, it is a normal "reliable" message
        if let Ok(seq) = doc.get_i64("q") {
            debug!("encrypted chat seq {} received", seq);
            if !update_acks(&mut *self.acks.lock()?, seq) {
                debug!("Duplicate seq {}", seq); // no need to take further action
                return Ok(true);
            }
            c.cache
                .insert(&db_key(&self.idkeys.sign.pk, seq, b"mesg")[..], b)?; //cache it
            self.encmsg(doc, c, s, seq).map(|_| true)
        } else if doc.contains_key("u") {
            self.encmsg(doc, c, s, 0).map(|_| false) // A/V so skip cache
        } else if let Ok(abg) = doc.get_binary_generic("a") {
            // no m, not a message. Hopefully an ack of one of ours?
            let ackbin = array_ref![leneq(abg, 32)?, 0, 32]; // hash of our acked packet
            debug!("ack for {}", b64sk(ackbin));
            let ack = doc.get_i64("n")?; //new sequence
            let qremov = self.queued.lock()?.remove(ackbin);
            let sent = qremov.ok_or_else(|| SfErr::UnexpectedAckErr(ackbin.clone()))?;
            update_acks(&mut *self.acks.lock()?, ack); // mark our message as being accepted
            debug!("Received ack for our msg: {}", ack);
            let cm = ChatMsg {
                doc: doc! {},
                midpoint: json!({ "ack": b64spk(ackbin).as_str() }),
                signer: c.keys.sign.pk.clone(),
                convoid: Some(self.idkeys.sign.pk.clone()),
                seq: Some(ack),
            };
            log_err!(s.send(cm), "sending ack"); //Notify client
            if !sent.resent {
                let ds = Instant::now().duration_since(sent.sent);
                let new_rto = update_rtt(&self.rttest, &ds) as f64 * 1.5; //update our RTT
                let to = 1f64.min(0.1f64.max(new_rto as f64 / 1000.0)); // 1s > rto > 0.1s
                let to_dur = Duration::new(to as u64, (to.fract() * 1000000000f64) as u32);
                log_err!(t.set_timeout(to_dur), "Error setting RTO"); //couldn't set to
            }
            c.cache
                .insert(&db_key(&self.idkeys.sign.pk, ack, b"mesg")[..], sent.data)?; //cache
            Ok(true)
        } else if doc.contains_key("pingack") || doc.contains_key("exited") {
            Ok(false) //good for them
        } else if let Ok(sid) = doc.get_i64("s") {
            let g = Arc::clone(self.streamies.lock()?.get_mut(&sid).ok_or_else(sfnone)?);
            debug!("Got stream {}", sid);
            match &mut *g.write()? {
                StreamTracker::Sync(ref mut sstream) => {
                    //stream_write will write to buffer, or cache and return err if out-of-order
                    if sstream.stream_write(&*self.stube.read()?, None, &doc)? == 0 {
                        debug!("Sync stream done.");
                        self.streamies.lock()?.remove(&sid);
                        return Ok(false);
                    }
                    let mut i = 0;
                    debug!("sstream.f.len() {} i {}", sstream.f.len(), i);
                    let mut docs = Vec::new();
                    while sstream.f.len() > 2 + i {
                        let mlen = sstream.f[i] as usize + sstream.f[i + 1] as usize * 256; // 16 bit le len
                        debug!("Got mlen {} at {}/{}", mlen, i, sstream.f.len());
                        if sstream.f.len() < 2 + i + mlen {
                            break; //not enough bytes
                        }
                        let mut slc = Cursor::new(&sstream.f[i + 2..i + 2 + mlen]);
                        log_err!(decode_document(&mut slc).map(|d| docs.push(d)), "decode");
                        i = i + 2 + mlen;
                    }
                    sstream.f.drain(..i);
                    drop(sstream); //release the lock before recursing
                    for inner_doc in docs {
                        if let Err(e) = self.pmsg(c, b, inner_doc, s, t) {
                            info!("chat stream {} hrecv error {}", sid, e);
                        }
                    }
                }
                StreamTracker::Write(ref mut w) => {
                    w.stream.f.clear(); //clear buffer
                    let offset = w.stream.offset;
                    //stream_write will write to buffer, or cache and return err if out-of-order
                    let rdlen = w.stream.stream_write(&*self.stube.read()?, None, &doc)?;
                    if rdlen > 0 {
                        let stepby = 1024 + CRYPTO_BOX_MACBYTES + 8;
                        for chunko in (0..w.stream.f.len()).step_by(stepby) {
                            let endo = (chunko + stepby).min(w.stream.f.len());
                            debug!("chunk {}-{}/{} {}", chunko, endo, rdlen, w.stream.f.len());
                            if endo - chunko < CRYPTO_BOX_MACBYTES + 8 {
                                error!("got chunk len {} - too short", endo - chunko);
                                break; //hopefully doesn't happen
                            }
                            let rnd = i64::from_le_bytes(*array_ref![w.stream.f, chunko, 8]);
                            let chnk = &w.stream.f[chunko + 8..endo];
                            let fbo = (offset + chunko as i64) * 1024 / stepby as i64;
                            let n = self.fblock_tag(w.nonce, rnd, fbo)?; //nonce. Shouldn't fail.
                            let res = wr_crypto_secretbox_open_easy_n(chnk, &n, &self.key);
                            if let Err(e) = res.and_then(|plaint| Ok(w.handoff.send(plaint)?)) {
                                error!("stream send {}", e);
                                log_err!(w.handoff.send(Vec::new()), "stream err eof");
                            }
                        }
                    } else {
                        debug!("rdlen {} sfl {}", rdlen, w.stream.f.len()); //done. EOF
                        log_err!(w.handoff.send(Vec::new()), "stream eof send");
                    }
                    debug!("handoff sent sfl {}", w.stream.f.len());
                }
                StreamTracker::Read(ref mut rst) => {
                    if let Err(e) = rst.stream.stream_read(&*self.stube.read()?, None, &doc) {
                        info!("StreamTracker stream_read upload EOF? {}", e); //we're done
                        if let Ok(mut done) = rst.done.0.lock() {
                            *done = true; //we're done!
                            rst.done.1.notify_one();
                        }
                        self.streamies.lock()?.remove(&sid);
                    }
                }
            }
            Ok(false)
        } else {
            let id = doc.get_i64("id")?;
            debug!("Got session ID reply for {:X}", id); //if there is a waiting thread, save results
            if let Some(thrd) = self.calls.lock()?.remove(&id) {
                self.resps.lock()?.insert(id, doc);
                thrd.unpark(); //unpark the waiting thread. They'll get data or exit
            }
            Ok(false)
        }
    }
}

//jsonize convos (for saving or sending to client)
pub fn json_convos(convos: &HashMap<ConvoId, Arc<Conn>>, ctxt: &SfContext) -> String {
    let mut convos_out = HashMap::new();
    for (convoid, ct) in convos.iter() {
        let ackz = if let Ok(acks) = ct.acks.lock() {
            acks.iter().map(|a| [a.start, a.end].to_vec()).collect()
        } else {
            Vec::new()
        };
        let jdoc = json!({ "participants": ct.participants_map(ctxt), "acks": ackz });
        convos_out.insert(b64spk(&convoid), jdoc);
    }
    serde_json::to_string(&json!({ "convos": convos_out })).unwrap_or_else(|_| {
        warn!("Bad json_convos");
        "{}".to_string()
    })
}

//Given one seq, what was the last we received?
fn prev_acked(acks: &Vec<ops::Range<i64>>, seq: i64) -> Option<i64> {
    for i in 0..acks.len() {
        if seq > acks[i].end {
            if i == acks.len() - 1 {
                return Some(acks[i].end - 1); //grab last one
            }
            continue; //not yet there
        }
        if seq <= acks[i].start {
            if i > 0 {
                return Some(acks[i - 1].end - 1);
            }
            return None;
        } else if seq > acks[i].start {
            return Some(seq - 1);
        }
    }
    None
}

//Sends an error notification message to the user from another thread
fn notify_err(errtxt: &str, sndr: &ChatSnd, context: &SfContext) {
    warn!("{}", errtxt);
    sndr.send(ChatMsg {
        doc: doc! {"notice": errtxt, "timestamp": epoch_timestamp()},
        midpoint: json!({}),
        signer: context.keys.sign.pk.clone(),
        convoid: None,
        seq: None,
    })
    .unwrap_or_else(|e| error!("Couldn't send meet server contact failure message: {}", e));
}

// contacts.json is just json serialized contacts
fn get_my_contacts(context: &Context) -> SfRes<()> {
    let mut cv: Vec<Contact> = Vec::new();
    match File::open(context.workdir.join("contacts.json")) {
        Ok(f) => cv = serde_json::from_reader(f)?,
        Err(e) => warn!("No contacts yet? {}", e),
    }
    if let Ok(mut tax) = context.contacts.lock() {
        for c in cv.drain(..) {
            tax.insert(b64spk(&c.spkey), c); //insert them all
        }
    }
    Ok(())
}

// Saves contacts.json
pub fn save_my_contacts(context: &SfContext, contacts: &BTreeMap<KeyString, Contact>) -> SfRes<()> {
    let f = File::create(context.workdir.join("contacts.json"))?;
    let cv: Vec<&Contact> = contacts.values().collect();
    Ok(serde_json::to_writer(f, &cv)?)
}

// send message to a conversation. If you send a taco to someone in San Antonio, it's a Tex-Mexage.
pub fn sendmsg(tgt: &ConvoId, text: &str, ctxt: &Context) -> SfRes<Sha256Hash> {
    let con = Arc::clone(ctxt.convos.lock()?.get(tgt).ok_or_else(sfnone)?);
    debug!("sending {} over connection", text); //next we pad so inner send is 343 bytes
    let pad = str::from_utf8(&PADDING[..149 - (text.as_bytes().len() % 149)]).unwrap();
    let bd = bdoc_to_u8vec(&doc! {"text":text, "timestamp": epoch_timestamp(), "pad": pad});
    con.send_conn(&ctxt.keys, &bd, true)
}

// send invite for one convo to another. Specifically asking the other end of tgt into to_be_joined
pub fn send_invite(tgt: &ConvoId, to_be_joined: &ConvoId, c: &Context) -> SfRes<Sha256Hash> {
    info!("Inviting {} to join {}", b64spk(tgt), b64spk(to_be_joined));
    let convos = c.convos.lock()?; // Arc<Mutex<HashMap<ConvoId, Arc<Conn>>>>
    let con = Arc::clone(convos.get(tgt).ok_or_else(sfnone)?);
    let sc = Arc::clone(convos.get(to_be_joined).ok_or_else(sfnone)?);
    drop(convos);
    let nome = |p: &&ConvoId| **p != c.keys.sign.pk;
    if sc.participants.lock()?.iter().filter(nome).nth(1).is_some() {
        Err(SfErr::TooManyErr) // multiple people
    } else {
        let nd = sc.meet.read()?.clone(); //Get sc's meet_host
        let madd = format!("{}", &nd.address);
        let b = bdoc_to_u8vec(&doc! {
            "invitecid": binary_bson(&sc.idkeys.sign.pk),
            "seed": binary_bson(&sc.idkeys.sign.sk[..32]),
            "meetkey": binary_bson(&nd.key[..]),
            "sesskey": binary_bson(&sc.key[..]),
            "meetaddr": madd,
            "timestamp": epoch_timestamp()
        });
        con.send_conn(&c.keys, &b, true)
    }
}

// Find a meet node (or direct) return the E2E box pubkey, and meet node info
// This function only looks at cached info and does not block or make network requests
pub fn meet_node(k: &SignPKey, c: &SfContext) -> SfRes<(BoxPKey, PubNode)> {
    //look for the tgt directly or via discovery key blind, then clone the address, sign, & box keys
    let (nodeaddrobj, bpk, sign_pkey) = c
        .get_node(k)
        .map(|nod| (nod.address.clone(), nod.bkey.clone(), nod.key.clone()))
        .or_else(|_| {
            c.get_node(&disc_blind(k))
                .map(|bn| (bn.address.clone(), wr_crypto_sign_pk_to_box(k), k.clone()))
        })?; // Blinded?
    match nodeaddrobj {
        NodeAddr::Sockaddr(nodeaddr) => {
            debug!("Got address to {} {}", b64spk(&k), nodeaddr);
            Ok((bpk.clone(), PubNode::new(sign_pkey, bpk, nodeaddr)))
        }
        NodeAddr::Meet(maddr) => {
            debug!("Meet {} for tgt {}", b64spk(&maddr.meet_host), b64spk(&k));
            if let Ok(node) = c.get_node(&maddr.meet_host) {
                if let NodeAddr::Sockaddr(s) = node.address {
                    Ok((bpk, PubNode::new(node.key.clone(), node.bkey.clone(), s)))
                } else {
                    warn!("can't find {} for {}", b64spk(&maddr.meet_host), b64spk(&k));
                    Err(SfErr::BadMeet)
                }
            } else {
                warn!("can't find {} for {}", b64spk(&maddr.meet_host), b64spk(&k));
                Err(SfErr::BadMeet)
            }
        }
    }
}

//Same thing as meet_node, but returns an err if it doesn't have an IP address
pub fn meet(k: &SignPKey, c: &Context) -> SfRes<(BoxPKey, PubNode)> {
    let (boxk, meet_pubnode) = meet_node(k, c)?; //Find the address
    if meet_pubnode.key != *k {
        return Err(SfErr::BadMeet); //If using a meet server, return an error
    }
    Ok((boxk, meet_pubnode))
}

//add a tubepair to en/decrypt a session key. Spawns up and down threads
pub fn wrapping_tubepair(sk: SecKey, mut cli: Tube) -> SfRes<(Tube, Arc<AtomicBool>)> {
    let (newcli, mut tub2) = Tube::pair(true); //writes to s2 show up on newcli and vice versa
    let flag = Arc::new(AtomicBool::new(true));
    let fl1 = Arc::clone(&flag);
    let fl2 = Arc::clone(&flag);
    let sk_clone = sk.clone();
    let s_r = tub2.split_off_recv()?; //Split off the recv end of the tubes
    let c_r = cli.split_off_recv()?; //send from tub2 to cli, wrapping data in the session key
    spawn_thread("sfwdwrap", move || tube_wrap(s_r, cli, &sk_clone, fl1));
    spawn_thread("sfwdunwr", move || tube_unwrap(c_r, tub2, &sk, fl2, false));
    Ok((newcli, flag))
}

//assumes you've already checked k, adds new contact or updates existing one
pub fn add_tact(n: String, k: &[u8], trusted: Option<u64>, c: &SfContext) -> SfRes<bool> {
    debug!("add_tact new {}", &n);
    let bk = b64spk(array_ref![k, 0, 32]);
    let mut tax = c.contacts.lock()?;
    if !trusted.is_some() {
        if let Some(c) = tax.get(&bk) {
            if c.verified.is_some() {
                return Ok(true); //don't let unverified update overwrite verified
            }
        }
    }
    let ct = Contact {
        spkey: copy_to_array(&k),
        name: n.clone(),
        verified: trusted,
    };
    let mut same = false;
    if let Some(oldtact) = tax.insert(bk, ct) {
        debug!("add_tact old {}", &oldtact.name);
        same = oldtact.name == n;
    }
    save_my_contacts(&c, &tax)?;
    Ok(same)
}

//ask nodes with just-higher keys, who should be the first targets of meet info propagation
fn interrogate_for_node(ctxt: &Context, dkey: &SignPKey, nsender: &ChatSnd) {
    if let Some(mut node) = ctxt.nextnode_wrap(&dkey) {
        let mut tries = 0;
        while tries < 5 && !ctxt.has_node(&dkey) {
            let qres = query_nodelist(&node, &dkey, ctxt, false, true); //query the node
            debug!("LOOKUP learned anything? {}", qres.0.is_some());
            increment_spkey(&mut node.key);
            if let Some(node2) = ctxt.nextnode_wrap(&node.key) {
                node = node2;
            } else {
                notify_err("Lost nodes!", nsender, ctxt);
                break; //shouldn't fail but could if a node is dropped in between the 2 calls
            }
            tries += 1;
        }
    } else {
        notify_err("We don't know about any nodes?", nsender, ctxt)
    }
}

//Performs a second-stage lookup, with blocking interrogation if needed
fn meet_2(nd: Node, n: &ChatSnd, c: &Arc<SfContext>, tgt: &SignPKey) -> SfRes<(BoxPKey, PubNode)> {
    if let NodeAddr::Meet(maddr) = nd.address {
        if let Err(_) = c.get_node(&maddr.meet_host) {
            let er = format!("LOOKUP 2 {}", b64spk(&maddr.meet_host));
            notify_err(&er, n, c); //let the user know there's some problems
            interrogate_for_node(c, &maddr.meet_host, n); //look for it
        }
        meet_node(tgt, c) // we found it maybe? Now finish the key derivation etc.
    } else {
        Err(SfErr::BadMeet) //not a node lookup failure? Then wrong type of node
    }
}

//make a chat connection to a tgt via a meet node and E2E key chatkey
pub fn get_connection(
    tgt: &SignPKey,
    ctxt: &Context,
    chatkey: SecKey,
    idkeys: Keys,
    nsender: &ChatSnd,
) -> SfRes<Arc<Conn>> {
    //calculate meet & discovery blinded keys so the meet node doesn't know who we or they are
    let mkey = wr_crypto_blind_ed25519_public_key(tgt, "meet");
    let dkey = wr_crypto_blind_ed25519_public_key(&mkey, "disc");
    debug!("get_conn {} cid {}", b64spk(&mkey), b64spk(&idkeys.sign.pk));
    let (bk, meet) = meet_node(tgt, ctxt).or_else(|e| {
        //meet_node failed, maybe it's a node lookup failure and we just don't know about it yet
        //First, see if the first lookup succeeded, but had an error in the second part (meet->IP)
        if let Ok(node) = ctxt.get_node(&dkey) {
            return meet_2(node, nsender, ctxt, tgt);
        }
        //otherwise interrogate for first part, then re-check second
        let er = format!("LOOKUP {} {}", b64spk(&tgt), b64spk(&dkey));
        notify_err(&er, nsender, ctxt); //let the user know there's some problems
        interrogate_for_node(ctxt, &dkey, nsender); //see if we can find it by querying net
        if let Ok(node) = ctxt.get_node(&dkey) {
            debug!("meet now has a node. We learned it!");
            return meet_2(node, nsender, ctxt, tgt);
        }
        warn!("get_connection failed to {}", b64spk(&tgt));
        Err(e)
    })?;
    debug!("Found meet {} for tgt {}", meet.address, b64spk(&tgt));
    let (cli, wad, rtt_nl) = conn_hops(&meet.address, ctxt, &meet.bkey)?; //Connect to the server
    let mut addrs = HashSet::new(); //Now pick 2 backup meet nodes for the convo
    addrs.insert(meet.address.clone()); //Pick random distinct nodes for the backups
    debug!("getting rand other conn");
    let (c1, w1, r1, bknode1) = rand_other_conn(ctxt, &addrs); //client tube, wad, rtt, node
    addrs.insert(bknode1.address.clone());
    debug!("getting rand other conn2");
    let (c2, w2, r2, bknode2) = rand_other_conn(ctxt, &addrs); //client tube, wad, rtt, node
    debug!("got rand other conns {:?}", addrs);
    let nonce = array_ref![idkeys.sign.pk, 0, 24]; //fixed nonce for participant ID
    let p = wr_crypto_secretbox_easy_n(&ctxt.keys.sign.pk, nonce, &chatkey); //encrypted part ID
    let h = &bdoc_to_u8vec(&doc! {
        "chatkey": binary_bson(&chatkey[..]),
        "seed": binary_bson(&idkeys.sign.sk[..32]), //all chat members share the chat ID secret key
        "sender": binary_bson(&ctxt.keys.sign.pk),
        "ds": binary_bvec(display_name_blob(ctxt)), //send your display name to them
    });
    let mut backups_blob = [0; 19 + 32 + 19 + 32]; // b1 address + b1 key + b2 address + b2 key
    backups_blob[..19].copy_from_slice(&sockaddr_to_bin(&bknode1.address)); //b1 address
    backups_blob[19..19 + 32].copy_from_slice(&bknode1.key[..]); //b1 key
    backups_blob[19 + 32..19 + 32 + 19].copy_from_slice(&sockaddr_to_bin(&bknode2.address)); //b2 ad
    backups_blob[19 + 32 + 19..].copy_from_slice(&bknode2.key[..]); //b2 key
    let rpcdoc = doc! {
        "fnc":"openchat",
        "cid": binary_bson(&idkeys.sign.pk[..]),
        "sig": binary_bvec(wr_crypto_sign(&db_key(&meet.key, 0, b"host")[..], &idkeys.sign.sk)),
        "tgt": binary_bson(&mkey[..]),
        "backups": binary_bson(&backups_blob[..]),
        "partid": binary_bvec(p),
        "rtt": rtt_nl as i32,
        "handshake": binary_bvec(wr_crypto_box_seal(h, &bk))
    };
    let (mut doc, rtt) = do_rpc(rpcdoc, &cli, &meet.bkey, &rand_keys())?; // if we get a valid response
    let sesskey: SecKey = copy_to_array(leneq(doc.get_binary_generic("k")?, 32)?); //Key
    let disp_name_enc = doc.get_binary_generic_mut("disp_name_enc")?;
    let disp_name_key = wr_crypto_auth(b"displayname", &tgt); //derive key for disp name
    if let Ok(plain) = wr_crypto_secretbox_open(disp_name_enc, &disp_name_key) {
        verify_disp(plain, &tgt, ctxt);
    }
    debug!("Completing openchat to cid {}", b64spk(&idkeys.sign.pk));
    let (newcli, flag) = wrapping_tubepair(sesskey, cli)?; // Wrap this tube up in E2E crypto
    let mut hset = HashSet::new();
    hset.insert(tgt.clone());
    hset.insert(ctxt.keys.sign.pk.clone());
    let mut bs = [(Some((c1, w1, r1)), bknode1), (Some((c2, w2, r2)), bknode2)]; //backups
    Conn::register_new(
        idkeys, newcli, chatkey, hset, flag, wad, ctxt, meet, 0, rtt, nsender, &mut bs, true,
    )
}

//backup info
pub fn addrkey(add: &SocketAddr, key: &SignPKey) -> [u8; 19 + 32] {
    // address + key
    let mut buf = [0; 19 + 32];
    buf[..19].copy_from_slice(&sockaddr_to_bin(&add)); // address
    buf[19..19 + 32].copy_from_slice(key); // key
    buf
}

//Auto-accepts sync connection notifications and joins the respective convos
fn self_conn_notif_inner(doc: &Document, c: &Context, snd: &ChatSnd, seq: i64) -> SfRes<()> {
    let idkeys = seed_keys(copy_to_array(leneq(doc.get_binary_generic("seed")?, 32)?));
    let cid = &idkeys.sign.pk; //conversation ID
    let sk = copy_to_array(leneq(doc.get_binary_generic("skey")?, 32)?); //E2E key
    let spk = copy_to_array(leneq(doc.get_binary_generic("mpk")?, 32)?); //meet server's public key
    if !doc.get_bool("op")? {
        //TODO: see if there's a > seq join
        c.cache.insert(&db_key(cid, seq, b"leav")[..], b"")?; //Store exit at this seq
        if let Some(con) = c.convos.lock()?.get(cid).map(|c| Arc::clone(c)) {
            debug!("Sending conn leave msg"); //Leave if we're in it now
            log_err!(con.conn_leave(c), "Conn leave function call");
            con.close(); //sends exit
        }
        return Err(SfErr::NoneErr); //not opening, closing. TODO: exit if we're in it from lower seq
    } else {
        let r = &db_key(cid, seq, b"leav")[..]..&db_key(cid, -1, b"leav")[..]; //Is there a > seq leave?
        if let Some(Ok(_)) = c.cache.range(r).keys().next() {
            debug!("NOT sync joining {} - left it", b64spk(cid));
            return Err(SfErr::NoneErr);
        }
    }
    info!("Got sync for convo {}", b64spk(cid));
    let backblob = doc.get_binary_generic("backups").map(|b| b.to_vec()).ok();
    let (nod, ctx, snd2) = (c.get_node(&spk)?, Arc::clone(c), snd.clone());
    if let NodeAddr::Sockaddr(saddr) = nod.address {
        let n = PubNode::new(nod.key, nod.bkey, saddr);
        spawn_thread("join_cid", move || {
            while let Err(e) = join_cid(idkeys, n, sk, &ctx, snd2.clone(), false) {
                if let SfErr::AlreadyJoinedErr = e {
                    break;
                }
                warn!("join fail {} {}: {}", b64spk(&idkeys.sign.pk), n.address, e);
                let chunksize = CRYPTO_SIGN_PUBLICKEYBYTES + BIN_SOCKADDR_LEN;
                if let Some(bblob) = &backblob {
                    for chunk in bblob.chunks_exact(chunksize).take(MAX_BACKUPS) {
                        let add = debin_addr(array_ref![chunk, 0, 19]);
                        info!("Trying {} backup {}", b64spk(&idkeys.sign.pk), n.address);
                        let spk = array_ref![&chunk, 19, 32];
                        let bpk = wr_crypto_sign_pk_to_box(spk);
                        let bnode = PubNode::new(spk.clone(), bpk, add.clone());
                        if let Err(e) = join_cid(idkeys, bnode, sk, &ctx, snd2.clone(), true) {
                            warn!("bad join {} b {}: {}", b64spk(&idkeys.sign.pk), add, e);
                        } else {
                            break;
                        }
                    }
                }
                error!("Could not join cid {} at all", b64spk(&idkeys.sign.pk));
                thread::sleep(secs(20)); //retry every 20 seconds
                                         //TODO: Issue #13 - if we exit chat, this should die
            }
        });
        Ok(())
    } else {
        Err(SfErr::BadMeet)
    }
}
fn self_conn_notif(doc: &Document, c: &Context, snd: &ChatSnd, seq: i64) -> SfRes<()> {
    let res = self_conn_notif_inner(doc, c, snd, seq);
    if let Err(SfErr::ValErr(_ve)) = &res { //normal, not roll message
    } else {
        log_err!(&res, "Could not resume chat connection!");
    }
    res
}

//Updates an RTT value with a new measured value.
fn update_rtt(rttmsest: &AtomicUsize, ds: &Duration) -> usize {
    //RTT, as a running estimate doesn't need thread safety, it's OK if it drops a few updates
    let re = rttmsest.load(Relaxed) as f64;
    let new_rtt = (0.7f64 * re + 0.3f64 * dur_millis(ds)) as usize;
    rttmsest.store(new_rtt, Relaxed);
    new_rtt
}

//Inner setup and call joinchat over a given connected client
fn jn(
    c: &SignPKey,
    v: &Keys,
    t: &Tube,
    m: &PubNode,
    k: &SecKey,
    r: f64,
    ctxt: &Context,
) -> SfRes<(Document, f64)> {
    let n = array_ref![v.sign.pk, 0, CRYPTO_BOX_NONCEBYTES];
    let p = binary_bvec(wr_crypto_secretbox_easy_n(&c[..], n, k)); //encrypt ur ID
    let cid = binary_bson(&v.sign.pk);
    let meetjoin = db_key(&m.bkey, 0, b"join");
    let s = binary_bvec(wr_crypto_sign(&meetjoin[..36], &v.sign.sk)); //sig
    let mut data = doc! {"fnc": "joinchat", "cid": cid, "partid": p, "sig": s, "rtt": r as i32};
    //find last cached sequence if present in our DB
    let start = db_key(c, 0, b"mesg");
    if let Some(Ok(dbk)) = ctxt.cache.scan_prefix(&start[..36]).keys().next_back() {
        data.insert("seq", be_to_i64(&dbk[(32 + 4)..]));
    }
    do_rpc(data, &t, &m.bkey, &rand_keys())
}

//Accept a received invite, should create a new Conn
pub fn join_cid(
    tgt: Keys,
    m: PubNode,
    skey: SecKey,
    ctxt: &Context,
    snd: ChatSnd,
    sync: bool,
) -> SfRes<Arc<Conn>> {
    info!("Attempting to join {}", b64spk(&tgt.sign.pk));
    if ctxt.convos.lock()?.contains_key(&tgt.sign.pk) {
        info!("Already joined.");
        return Err(SfErr::AlreadyJoinedErr);
    }
    let (cli, wad, rtt) = conn_hops(&m.address, ctxt, &m.bkey)?; //connect to the host
    let (doc, rtt2) = jn(&ctxt.keys.sign.pk, &tgt, &cli, &m, &skey, rtt, ctxt)?;
    let ck = doc.get_binary_generic("chatkey")?;
    let ckey = leneq(ck, CRYPTO_SECRETBOX_KEYBYTES)?;
    let participantsarr = doc.get_array("participants")?;
    let sig_unverified = doc.get_binary_generic("sig")?;
    let host_signed = wr_crypto_sign_open_inplace(sig_unverified, &tgt.sign.pk)?;
    let sig = leneq(host_signed, DBK_LEN)?;
    if &sig[..36] != &db_key(&m.key, 0, b"host")[..36] {
        error!("Wrong host signature joining {}", b64spk(&tgt.sign.pk));
        return Err(SfErr::BadSignatureErr); //either not for us or not a signed host message
    }
    let hid = i64::from_be_bytes(*array_ref![sig, 36, 8]); //at what sequence are they host?
    let mut parts = HashSet::new();
    for partbson in participantsarr {
        if let bson::Bson::Binary(_bt, vu8enc) = partbson {
            let n = array_ref![tgt.sign.pk, 0, CRYPTO_BOX_NONCEBYTES];
            if &vu8enc[..] == &[0; PIDLEN][..] {
            } else if let Ok(vu8) = wr_crypto_secretbox_open_easy_n(vu8enc, n, &skey) {
                if vu8.len() == CRYPTO_SIGN_PUBLICKEYBYTES {
                    parts.insert(copy_to_array(&vu8));
                } else {
                    notify_err("Invalid participant", &snd, ctxt);
                }
            } else {
                notify_err("Participant ID decryption failed", &snd, ctxt);
            }
        } else {
            notify_err("Bad data from meet node", &snd, ctxt)
        }
    }
    let bcks = doc.get_array("backups")?.iter().filter_map(|backbson| {
        if let bson::Bson::Binary(_, backbin) = backbson {
            if backbin.len() == BIN_SOCKADDR_LEN + CRYPTO_SIGN_PUBLICKEYBYTES {
                let key = array_ref![backbin, BIN_SOCKADDR_LEN, CRYPTO_SIGN_PUBLICKEYBYTES];
                let bkey = wr_crypto_sign_pk_to_box(key);
                let add = debin_addr(array_ref![backbin, 0, BIN_SOCKADDR_LEN]);
                return Some((None, PubNode::new(key.clone(), bkey, add))); //TODO: look up & verify
            }
        }
        None
    });
    //Now you need an unwrapping pair for the new skey encryption layer
    let (cli2, flag) = wrapping_tubepair(copy_to_array(ckey), cli)?;
    debug!("join_cid cid {}", b64spk(&tgt.sign.pk));
    let mut b = bcks.collect::<Vec<(Option<(Tube, Hop, f64)>, PubNode)>>();
    Ok(Conn::register_new(
        tgt, cli2, skey, parts, flag, wad, ctxt, m, hid, rtt2, &snd, &mut b, sync,
    )?)
}

fn close_conn_channel(mut conn: Arc<Conn>) {
    let mut tries = 0;
    while tries < 20 {
        match Arc::try_unwrap(conn) {
            Ok(ctunwr) => {
                let connid = ctunwr.idkeys.sign.pk.clone();
                if let Ok(mut cl) = ctunwr.ci.lock() {
                    if let Some(f) = &cl.flag {
                        f.store(false, Relaxed);
                    }
                    if let Some(ht) = close_wad_conn(cl.hop.take()) {
                        // wait for them
                        if let Err(e) = ht.join() {
                            error!("panicked thread {:?}", e);
                        }
                    }
                }
                info!("conn {} closed.", b64spk(&connid));
                return;
            }
            Err(old) => {
                tries += 1;
                let h = Arc::strong_count(&old) - 1;
                warn!("Waiting on {} handles {}", h, b64spk(&old.idkeys.sign.pk));
                conn = old;
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    warn!("ERR conn {} never closed", b64spk(&conn.idkeys.sign.pk));
}

// Thread to sits on the local end of a chat conn and forward to browser
fn cmon(conn: Arc<Conn>, c: Context, snd: ChatSnd) {
    info!("chat monitor {}", b64spk(&conn.idkeys.sign.pk));
    log_err!(conn.chat_client_monitor_inner(c, snd), "chat monitor err");
    info!("conn {} closing.", b64spk(&conn.idkeys.sign.pk));
    close_conn_channel(conn);
}

#[derive(Clone, Copy)]
pub struct RollProp {
    key: SignPKey,
    addr: SocketAddr,
    count: usize,
    oldb: Option<SignPKey>,
}
impl RollProp {
    pub fn new(key: SignPKey, ad: SocketAddr, oldb: Option<SignPKey>) -> Self {
        Self {
            key: key,
            addr: ad,
            count: 1,
            oldb: oldb,
        }
    }
}

pub enum NodeState {
    Chill,                     //no faults/failovers detected
    SentNodedown(Instant),     //we're claiming need to fail over
    ReceivedNodedown(Instant), //somebody else is claiming fail over
    //Proposed: We proposed a failover node. Rollover will be the new backup.
    //If this is a primary rollover, prev will be the old backup to be promoted
    Proposed {
        when: Instant,
        round: i32,
        rollover: Backup,
        count: usize,
        prev: Option<SignPKey>,
    },
    ReceivedProposal {
        when: Instant,
        round: i32,
        prop: RollProp,
    },
    Conflict {
        when: Instant,
        round: i32,
        rollovers: Vec<RollProp>,
    }, //diff props
}
use NodeState::*;
impl NodeState {
    pub fn is_chill(&self) -> bool {
        if let Chill = self {
            return true;
        }
        false
    }
    pub fn sent_nodedown_time_elapsed(&self) -> bool {
        if let SentNodedown(time_sent) = self {
            return time_sent.elapsed() > secs(15);
        }
        false
    }
    pub fn proposed_time_elapsed(&self) -> bool {
        if let Proposed {
            when: sent,
            rollover: _,
            round: _,
            count: _,
            prev: _,
        } = self
        {
            return sent.elapsed() > secs(15);
        }
        false
    }
    pub fn conflict_expired(&self) -> bool {
        if let Conflict {
            when: time_sent,
            rollovers: _,
            round: _,
        } = self
        {
            return time_sent.elapsed() > secs(15);
        }
        false
    }
    pub fn received_prop_expired(&self) -> bool {
        if let ReceivedProposal {
            when: w,
            round: _,
            prop: _,
        } = self
        {
            return w.elapsed() > secs(20);
        }
        false
    }
    pub fn rcv_prop(&mut self, round: i32, key: SignPKey, ad: SocketAddr, oldb: Option<SignPKey>) {
        let prop = RollProp::new(key, ad, oldb);
        *self = ReceivedProposal {
            when: Instant::now(),
            round: round,
            prop: prop,
        };
    }
}

fn display_name_blob(c: &SfContext) -> Vec<u8> {
    let mut bytes = c.display_name().into_bytes();
    if bytes.len() < 64 {
        bytes.reserve(65 - bytes.len());
    }
    bytes.insert(0, bytes.len() as u8); //store length at beginning
    while bytes.len() < 65 {
        bytes.push(0); //pad with 0's
    }
    wr_crypto_sign(&bytes, &c.keys.sign.sk) //sign it
}
//Inverse of the blob function. "Validates", parses, and adds the display name
//(only verifies the remote end vouches for the display name, not whether we trust them)
fn verify_disp(signed: &[u8], pubkey: &SignPKey, context: &SfContext) {
    if let Ok(plain) = wr_crypto_sign_open_inplace(signed, pubkey) {
        if plain.len() > 1 && plain.len() >= plain[0] as usize + 1 {
            if let Ok(strng) = String::from_utf8(plain[1..(1 + plain[0] as usize)].to_vec()) {
                log_err!(add_tact(strng, &pubkey[..], None, context), "add contact");
            }
        }
    }
}

//polling of self sync chat
fn self_mon(c: Context, snd: ChatSnd, mnode: PubNode, mut recvr: Option<MSMRecv>) {
    let (skey, idkeys) = derive_self_chat_keys(&c, &mnode.key);
    spawn_thread("self_mon", move || {
        while recvr.is_some() {
            info!("Setting up encrypted sync {}", b64spk(&idkeys.sign.pk));
            let (skc, sndc) = (skey.clone(), snd.clone()); //clone keys, sender
            match join_cid(idkeys.clone(), mnode.clone(), skc, &c, sndc, false).or_else(|e| {
                info!("No sync {}; need to start {}", e, b64spk(&idkeys.sign.pk));
                get_connection(&c.keys.sign.pk, &c, skey, idkeys.clone(), &snd)
            }) {
                Ok(conn) => {
                    let rcv = some_or_break!(recvr.take());
                    notify_err("Encrypted sync running", &snd, &c); //run until shutdown (ctflag is false)
                    while conn.ctflag.load(Relaxed) {
                        let msmsg = match rcv.recv_timeout(Duration::from_millis(200)) {
                            Ok(msg) => msg,
                            Err(e) => {
                                if let RecvTimeoutError::Disconnected = e {
                                    error!("Error receiving meet state message");
                                    return;
                                }
                                continue; //RecvTimeoutError::Timeout
                            }
                        };
                        info!("Sync logging conn notice {}", b64spk(&msmsg.idkeys.sign.pk));
                        let mut backups = Vec::with_capacity(msmsg.backups.len() * (19 + 32));
                        for b in msmsg.backups {
                            backups.extend_from_slice(&addrkey(&b.address, &b.key)[..]);
                        }
                        let bv = bdoc_to_u8vec(&doc! {
                            "seed": binary_bson(&msmsg.idkeys.sign.sk[..32]),
                            "skey": binary_bson(&msmsg.key[..]),
                            "mpk": binary_bson(&msmsg.meet_host.key[..]),
                            "op": msmsg.opening,
                            "backups": binary_bvec(backups),
                            "timestamp": epoch_timestamp(),
                            "pad": "............................" //pad so inner send is 343 bytes
                        });
                        log_err!(conn.send_conn(&c.keys, &bv, true), "new conn notice")
                    }
                    info!("Encrypted sync closing {}", b64spk(&conn.idkeys.sign.pk));
                }
                Err(e) => {
                    notify_err(&format!("Couldn't open sync log {}", e), &snd, &c);
                }
            }
        }
        error!("Recvr broke?");
    });
}

//The client end of the meet listener thread
fn meet_mon(c: &Context, snd: ChatSnd, spk: &SignPKey, msr: MSMRecv) {
    info!("meet_mon starting {} meet node {}", c.addr, b64spk(spk));
    //Get a connection to our meet server. We'll keep the same connection the whole time we're open
    let mut meet_infos = meet(spk, c); //Find the address of our meet node (with key spk)
    while meet_infos.is_err() {
        if let Err(e) = meet_infos {
            let msg = format!("Couldn't find meet node {}! {}", b64spk(spk), e);
            notify_err(&msg, &snd, c);
        }
        thread::sleep(Duration::from_secs(1));
        meet_infos = meet(spk, c);
    }
    let interval = secs(3600); // Restart meet listener every hour
    let mut refreshed: Instant;
    let (_box_pkey, mnode) = if let Ok(mi) = meet_infos {
        mi
    } else {
        error!("This should never happen-meet_mon");
        return;
    };
    let (mut cli, mut wad, rtt) = conn_hops_block(&mnode.address, c, &mnode.bkey); //blocks until it works
    let mut recvr = Some(msr);
    let disp_name_key = wr_crypto_auth(b"displayname", &c.keys.sign.pk); //derive key for disp name
    let disp_enc = wr_crypto_secretbox_easy(&display_name_blob(c), &disp_name_key); //encrypt name
    let notice = sign_meet_nodeaddr_bin(&c.disco, spk); //discovery, not real pubkey
    let nod = Node {
        key: c.disco.sign.pk.clone(),
        bkey: c.disco.bx.pk.clone(),
        address: parse_binaddr(&notice, &c.disco.sign.pk).unwrap(), //we can trust ours
    };
    log_err!(c.set_node(&c.disco.sign.pk, nod), "saving own discovery");
    let meetkey: SecKey = wr_randomkey();
    while c.shutting_down.load(Relaxed) == false {
        refreshed = Instant::now(); //reset timer
        let bsonk = binary_bson(&meetkey[..]);
        let not = binary_bvec(sign_meet_nodeaddr_bin(&c.disco, spk)); // sign new notice
        let denc = binary_bvec(disp_enc.clone());
        //start meet listener
        let d = doc! {"fnc": "listen", "notice": not, "key": bsonk, "de": denc, "rtt": rtt};
        match do_rpc(d, &cli, &mnode.bkey, &c.meet_keys) {
            Ok((_d, rtt)) => {
                //If this is the first time, start the polling of self sync chat
                if recvr.is_some() {
                    self_mon(Arc::clone(c), snd.clone(), mnode.clone(), recvr.take());
                }
                log_err!(cli.set_timeout(secs(10)), "set_timeout"); //wait up to 10s
                while refreshed.elapsed() < interval {
                    if let Err(e) = cli.recv_vec().and_then(|mut v| {
                        // A pending connection? Get ConvoId and join it!
                        let dec = if let Ok(d) = wr_crypto_secretbox_open(&mut v, &meetkey) {
                            d //meetkey encrypted means it's for us
                        } else {
                            warn!("Bad encrypted meet notice?");
                            return Ok(()); //ignore bad packets (RPC resends?) still alive so ok
                        };
                        let mpd = decode_document(&mut Cursor::new(dec))?;
                        let cidb = leneq(mpd.get_binary_generic("cid")?, 32)?;
                        let cid: &ConvoId = array_ref![cidb, 0, 32];
                        let handshake = mpd.get_binary_generic("h")?;
                        let decrypted = wr_crypto_box_seal_open(handshake, &c.keys.bx)?;
                        let h = decode_document(&mut Cursor::new(decrypted))?;
                        let seedb = h.get_binary_generic("seed")?;
                        let idkeys = seed_keys(copy_to_array(leneq(seedb, 32)?));
                        let ckb = h.get_binary_generic("chatkey")?;
                        let ck = leneq(ckb, CRYPTO_SECRETBOX_KEYBYTES)?;
                        let senderb = h.get_binary_generic("sender")?;
                        let s = leneq(senderb, CRYPTO_SIGN_PUBLICKEYBYTES)?;
                        if *s != c.keys.sign.pk {
                            verify_disp(h.get_binary_generic("ds")?, array_ref![s, 0, 32], c);
                        }
                        info!("Pending conn {}", b64spk(cid));
                        let ca = copy_to_array(ck); //Join conversation
                        let snd2 = snd.clone();
                        let joinres = join_cid(idkeys, mnode.clone(), ca, c, snd2, true);
                        if let Err(e) = &joinres {
                            if let SfErr::AlreadyJoinedErr = e {
                            } else {
                                return Err(joinres.err().unwrap());
                            }
                        } else if let Ok(conn) = joinres {
                            conn.send_display(&c)?;
                        }
                        let mad = doc! {"fnc": "meetack", "cid": binary_bson(cidb) }; //ack it
                        do_rpc_timeout(mad, &cli, &mnode.bkey, &c.meet_keys, (rtt * 2.0) as u64)?;
                        cli.set_timeout(secs(10)) //and reset your timeout
                    }) {
                        if let SfErr::TimeoutErr(te) = e {
                            if te.is_timeout() {
                                break; //expected timeout, don't spam log
                            }
                        }
                        debug!("Listen or meet receive error {}", e);
                        break; //back to listen with short RTO; verifies server/hop alive
                    }
                }
                log_err!(cli.set_timeout(Duration::from_millis(rtt as u64 * 2)), "TO");
            }
            Err(e) => {
                info!("Reconnecting to {}, dropping tube {}", mnode.address, cli);
                let (mut cli2, mut wad2, _rtt) = conn_hops_block(&mnode.address, c, &mnode.bkey);
                std::mem::swap(&mut cli, &mut cli2);
                std::mem::swap(&mut wad, &mut wad2);
                close_wad_conn(wad2); //teardown old wad, now wad2
                if let SfErr::NodeError((emsg, errdoc)) = e {
                    if let Ok(time) = errdoc.get_binary_generic("time") {
                        let mut theirtime = [0; 8];
                        for i in 0..8.min(time.len()) {
                            theirtime[i] = time[i];
                        }
                        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
                        let tdiff = i64::from_le_bytes(theirtime) - now as i64;
                        let m = format!("Time error. Server {} is {}s ahead", mnode.address, tdiff);
                        notify_err(&m, &snd, c); //Check your time?
                    } else {
                        let msg = format!("Meet server {} error {} Retrying.", mnode.address, emsg);
                        notify_err(&msg, &snd, c); //Meet server side error
                    }
                } else {
                    let msg = format!("Can't reach meet server {}. {} Retrying.", mnode.address, e);
                    notify_err(&msg, &snd, c); //Reconnect unresponsive connection, maybe change hop
                }
                thread::sleep(secs(1))
            }
        }
    }
    close_wad_conn(wad); //teardown old hops, now hops2
}

//Runs extra thread for polling meet server if using that
pub fn launch_meetmon(c: Context, nsender: &ChatSnd, recvr: MSMRecv) {
    let (maddr, nsender) = if let Ok(ma) = c.meet_info.lock() {
        if let MeetInfo::Address(meet_addr) = *ma {
            (meet_addr.clone(), nsender.clone())
        } else {
            warn!("Not spawning meet monitor");
            return;
        }
    } else {
        error!("Couldn't lock meet_addr");
        return;
    };
    spawn_thread("meet_mon", move || meet_mon(&c, nsender, &maddr, recvr));
}

//Runs the client, including kicking off the meet monitor and running the HTTP server.
pub fn run_cli(c: Context, mro: Option<MSMRecv>, s: ChatSnd, nr: Receiver<ChatMsg>) -> usize {
    debug!("Discovery blinded key {}", b64spk(&c.disco.sign.pk));
    debug!("Meet blinded key {}", b64spk(&c.meet_keys.sign.pk));
    log_err!(get_my_contacts(&c), "Getting contacts"); //load up contacts from contacts.json

    //Info passing (chat messages), usually to alert the client(s)
    if let Some(mrecv) = mro {
        launch_meetmon(Arc::clone(&c), &s, mrecv);
    }

    run_apisrv(nr, c, s) //And finally the localhost HTTP server
}
