//API server for the client in schadnfreude
use crate::innermain::*;
use bit_field::BitArray;
use std::fs::*;
use std::sync::{Arc, Mutex};

use super::stream::*;
use super::SfErr::*;
use super::*;

//A schadnfreude download stream. Downloads kb-sized chunks
struct Download {
    conn: Arc<Conn>,
    streamid: Option<i64>,
    fid: i64,
    cache: Option<File>,
    cached: bool,
    rcv: Receiver<Vec<u8>>,
}
impl Download {
    fn end_stream(&self, msg: &str) -> Option<Vec<u8>> {
        debug!("end_stream {} stream id {:?}", msg, self.streamid);
        if let Some(sid) = self.streamid {
            log_err!(self.conn.streamies.lock().map(|mut s| s.remove(&sid)), "");
            log_err!(self.conn.conn_sclose(sid, self.fid), "download conn_sclose");
            log_err!(self.conn.conn_funlock(self.fid), "download funlock");
        } else {
            warn!("Download aborted - no stream");
        }
        None
    }
    pub fn new(con: Arc<Conn>, fid: i64, n: i64, cash: Option<File>, cached: bool, o: i64) -> Self {
        let (s, r) = bounded(16);
        let mut c = cash;
        let mut sid = None;
        if !cached || !c.is_some() {
            match con.conn_sread(fid, o) {
                Ok(id) => {
                    sid = Some(id);
                    if let Ok(stuber) = con.stube.read() {
                        if let Err(e) = send_ack(id, &stuber, None, Vec::new(), 0, 0) {
                            error!("Error sending ack: {}", e);
                            log_err!(s.send(Vec::new()), ""); //EOF? Socket disconnected?
                        } else if let Ok(mut strm) = con.streamies.lock() {
                            let wstrm = StreamTracker::Write(WriteTracker::new(id, n, s));
                            strm.insert(id, Arc::new(RwLock::new(wstrm))); //Normal case
                        } else {
                            log_err!(s.send(Vec::new()), ""); //lock failed - shouldn't happen
                        }
                    } else {
                        log_err!(s.send(Vec::new()), ""); //other lock failed - shouldn't happen
                    }
                }
                Err(e) => {
                    info!("Download failed {}", e);
                    c.take(); //Close file
                    s.send(Vec::new()).unwrap_or_else(|e| error!("{}", e)); //EOF signal
                }
            }
        }
        Self {
            conn: con,
            streamid: sid,
            cache: c,
            cached: cached,
            rcv: r,
            fid: fid,
        }
    }
}

//wraps downloading chunks from a stream with caching
impl Iterator for Download {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Vec<u8>> {
        debug!("Download next {}", self.streamid.unwrap_or(-1));
        if self.cached {
            let mut buf = [0; 1024];
            let cr = self.cache.as_ref();
            return cr.and_then(|mut c| c.read(&mut buf).ok()).and_then(|len| {
                if len > 0 {
                    Some(buf[0..len].to_vec())
                } else {
                    None
                }
            });
        }
        let res = if let Ok(dat) = self.rcv.recv_timeout(time::Duration::from_secs(60)) {
            if dat.len() > 0 {
                dat //we downloaded more data
            } else {
                return self.end_stream("End of stream");
            }
        } else {
            return self.end_stream("Stream timeout"); //not much else we can do
        };
        let cr = self.cache.as_ref();
        cr.map(|mut c| c.write_all(&res).unwrap_or_else(|e| error!("{}", e)));
        debug!("Download next res {}", self.streamid.unwrap_or(-1));
        Some(res)
    }
}

//A schadnfreude file enum stream. Downloads file descriptors one at a time
struct FileEnum {
    conn: Arc<Conn>,
    cache: Arc<Db>,
    fid: i64,
    act: Option<Vec<u8>>,
    idx: usize,
}
impl FileEnum {
    fn new(conn: Arc<Conn>, cash: Arc<Db>) -> Self {
        Self {
            conn: conn,
            cache: cash,
            fid: 0,
            act: None,
            idx: 0,
        }
    }
}
impl Iterator for FileEnum {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Vec<u8>> {
        if self.act.is_none() || self.act.as_ref().unwrap().len() < (self.idx + 1) * 8 {
            let factbuf = match self.conn.conn_fact(self.fid) {
                Err(e) => {
                    info!("fact failed {}", e);
                    return None;
                }
                Ok(f) => f,
            };
            if factbuf.len() < 8 {
                return None;
            }
            self.act = Some(factbuf);
            self.idx = 0;
        }
        self.fid = be_to_i64(array_ref![self.act.as_ref().unwrap(), self.idx * 8, 8]); //just verified above
        self.idx += 1;
        let dbk = db_key(&self.conn.idkeys.sign.pk, self.fid, b"meta");
        if let Some(cached) = self.cache.get(&dbk[..]).ok().and_then(|r| r) {
            self.fid += 1;
            return Some(cached.to_vec());
        }
        let (mut inner, outer, len) = match self.conn.conn_fmeta(self.fid) {
            Ok(meta) => meta,
            Err(e) => {
                info!("File enum exited at {} reason {}", self.fid, e);
                return None;
            }
        };
        inner.remove("pad"); //if present, which doesn't need to be sent down
        let sval: Value =
            bson::from_bson(bson::Bson::Document(inner)).unwrap_or_else(|_| json!({}));
        let mut res = json!({"id": self.fid, "met": sval, "len": len});
        res.as_object_mut().map(|o| {
            let l = outer.get("lock").and_then(|l| l.as_bool()).unwrap_or(false);
            o.insert("lock".to_string(), Value::Bool(l));
            let d = outer.get("del").and_then(|d| d.as_bool()).unwrap_or(false);
            o.insert("deleted".to_string(), Value::Bool(d));
        });
        let resb = format!("{}\n", res).into_bytes();
        debug!("FileEnum returning {}", str::from_utf8(&resb).unwrap());
        if let Err(e) = self.cache.insert(&dbk[..], resb.clone()) {
            error!("FileEnum caching err {}", e);
        }
        self.fid += 1;
        Some(resb)
    }
}

//Grabs a string from a serde JSON value
fn sjson_str<'a>(sj: &'a Value, name: &str) -> SfRes<&'a str> {
    sj.get(name).and_then(|p| p.as_str()).ok_or(NoneErr)
}

const CID_STR_LEN: usize = 43;
fn b64_to_cid(cid: &str) -> SfRes<ConvoId> {
    let mut bcid = [0; 32];
    if cid.len() != CID_STR_LEN {
        warn!("cid len {} should be 43", cid.len());
        return Err(SfErr::BadLen);
    }
    base64::decode_config_slice(cid, URL_SAFE_NO_PAD, &mut bcid)?;
    Ok(bcid)
}

//Helper for lots of methods to look up a Conn from a base64'd CID
fn b64_cid_to_convo(ctxt: &Context, cid: &str) -> SfRes<Arc<Conn>> {
    let (lck, cid) = (ctxt.convos.lock()?, b64_to_cid(cid)?);
    Ok(Arc::clone(lck.get(&cid).ok_or(NoneErr)?))
}

//handler for /download (download by FID)
fn download_req(stream: &mut TcpStream, path: &str, context: &Context) -> SfRes<()> {
    let (conn, fid) = match path.split("?").nth(1).ok_or(SfErr::NotFound).and_then(|q| {
        let mut splitter = q.split('.');
        let conn = b64_cid_to_convo(context, splitter.next().ok_or(NoneErr)?)?;
        Ok((conn, splitter.next().ok_or(NoneErr)?.parse()?))
    }) {
        Ok(fid) => fid,
        Err(e) => {
            let tp = "Content-Type: text/plain\r\n";
            return code_reply(stream, 400, tp, format!("{}", e).as_bytes());
        }
    };
    download_fid(conn, stream, fid, 0)
}
fn download_fid(conn: Arc<Conn>, stream: &mut TcpStream, fid: i64, off: i64) -> SfRes<()> {
    match conn.conn_fmeta(fid).and_then(|(innermet, met, siz)| {
        info!("fmeta {} inn {} original size {}", met, innermet, siz);
        if met.get_bool("del").unwrap_or(false) {
            return Err(SfErr::DeletedError);
        }
        let (cachefile, cached) = if met.get_bool("lock").unwrap_or(false) {
            let path = conn.cachepath.join(format!("f_{}", fid));
            let mut opts = OpenOptions::new();
            let setup_opts = opts.write(true).read(true).truncate(false).create(true);
            let f = setup_opts.open(path)?;
            let has_data = f.metadata()?.len() > 0;
            (Some(f), has_data)
        } else {
            (None, false)
        };
        let nonce = innermet.get_i64("nonce")?;
        Ok(Download::new(conn, fid, nonce, cachefile, cached, off))
    }) {
        Err(e) => {
            let tp = "Content-Type: text/plain\r\n";
            code_reply(stream, 400, tp, format!("{}", e).as_bytes())
        }
        Ok(rstream) => {
            let octets = "Content-Type: application/octet-stream\r\n";
            stream_resp(stream, octets, rstream)
        }
    }
}

//handler for /nodes returns the entire set of relays (but not users)
fn nodes_req(_headers: &Headers, _uri: &str, context: &Context) -> SfRes<Vec<u8>> {
    let mut res = serde_json::map::Map::new();
    for node_bin_r in context.nodes.iter().values() {
        if let Ok(node_bin) = node_bin_r {
            if let Ok(node) = Node::load(&node_bin) {
                if let NodeAddr::Sockaddr(s) = node.address {
                    res.insert(b64spk(&node.key).to_string(), json!(format!("{}", s)));
                }
            }
        }
    }
    Ok(Value::Object(res).to_string().into_bytes())
}

//handler for /listfiles
fn listfiles_req(stream: &mut TcpStream, uri: &str, c: &Context) -> SfRes<()> {
    let u = uri.split("?").nth(1).ok_or(SfErr::NoneErr);
    match u.and_then(|q| Ok(FileEnum::new(b64_cid_to_convo(c, q)?, Arc::clone(&c.cache)))) {
        Err(e) => {
            let tp = "Content-Type: text/plain\r\n";
            code_reply(stream, 400, tp, format!("{}", e).as_bytes())
        }
        Ok(rstream) => stream_resp(stream, "Content-Type: text/plain\r\n", rstream),
    }
}

fn do_reply(stream: &mut TcpStream, extra_headers: &str, body: &[u8]) -> SfRes<()> {
    crate::httpsrv::do_reply::<SfErr>(stream, extra_headers, body)
}

fn code_reply(stream: &mut TcpStream, code: u16, heads: &str, bod: &[u8]) -> SfRes<()> {
    crate::httpsrv::code_reply::<SfErr>(stream, code, heads, bod)
}

//handler for /nextmsg
fn nextmsg_req(
    stream: &mut TcpStream,
    headers: &Headers,
    csrftoken: &Mutex<KeyString>,
    rclone: &Mutex<Receiver<ChatMsg>>,
) -> SfRes<()> {
    //gotta match CSRF here too so other sites don't steal our chats
    if headers.get("csrftoken") != Some(&csrftoken.lock()?.as_str()) {
        let tp = "Content-Type: text/plain\r\n";
        return code_reply(stream, 400, tp, "Bad CSRF token".as_bytes());
    }
    let r = rclone.lock()?.recv_timeout(Duration::from_secs(30));
    match r.map_err(|e| SfErr::TimeoutErr(e)).and_then(|mut chbin| {
        if let Ok(audbin) = chbin.doc.get_binary_generic("audio") {
            let hdrs = format!(
                "Content-Type: application/octet-stream\r\n\
X-Convo-Id: {}\r\n\
X-Media: 16bitaud\r\n\
X-Timestamp: {}\r\n\
X-From: {}\r\n",
                b64spk(&chbin.convoid.unwrap_or([0; 32])),
                chbin.doc.get_i64("ts").unwrap_or(0),
                b64spk(&chbin.signer)
            );
            do_reply(stream, &hdrs, audbin)
        } else if let Ok(vidbin) = chbin.doc.get_binary_generic("video") {
            let sid = if let Ok(s) = chbin.doc.get_binary_generic("s") {
                encode_config(&s[..], URL_SAFE_NO_PAD)
            } else {
                "".to_string()
            };
            let hdrs = format!(
                "Content-Type: application/octet-stream\r\n\
X-Convo-Id: {}\r\n\
X-Media: vid\r\n\
X-Packet: {}\r\n\
X-Offset: {}\r\n\
X-Total: {}\r\n\
X-Stream: {}\r\n\
X-From: {}\r\n",
                b64spk(&chbin.convoid.unwrap_or([0; 32])),
                chbin.doc.get_i32("p").unwrap_or(0),
                chbin.doc.get_i32("o").unwrap_or(0),
                chbin.doc.get_i32("t").unwrap_or(0),
                sid,
                b64spk(&chbin.signer)
            );
            do_reply(stream, &hdrs, vidbin)
        } else {
            chbin.doc.remove("pad"); //no need to send garbage down
            let mut robj = json!({
                "from": b64spk(&chbin.signer),
                "msg": chbin.doc,
                "midpoint": chbin.midpoint,
            });
            if let Some(rmap) = robj.as_object_mut() {
                if let Some(cid) = chbin.convoid {
                    rmap.insert("convoid".to_string(), json!(b64spk(&cid)));
                }
                chbin.seq.map(|s| rmap.insert("seq".to_string(), json!(s)));
            }
            let aj = "Content-Type: application/json\r\n";
            do_reply(stream, aj, robj.to_string().as_bytes())
        }
    }) {
        Err(e) => {
            let tp = "Content-Type: text/plain\r\n";
            code_reply(stream, 400, tp, format!("{}", e).as_bytes())
        }
        Ok(resp) => Ok(resp),
    }
}

//handler for /msghistory?convoid.seq
fn msghistory_req(uri: &str, c: &Context, snd: &ChatSnd) -> SfRes<Vec<u8>> {
    let q = uri.split("?").nth(1).ok_or(NoneErr)?;
    let mut splitter = q.split('.');
    let con = b64_cid_to_convo(c, splitter.next().ok_or(NoneErr)?)?;
    let seq: Option<i64> = splitter.next().and_then(|s| s.parse().ok());
    let j = json!(con.get_msgs(seq, c, snd));
    Ok(j.to_string().into_bytes())
}

//Handle posts to /contacts
fn contacts_p(_: &Headers, bod: &[u8], c: &Context) -> SfRes<&'static [u8]> {
    let sj: Value = serde_json::from_slice(bod)?;
    let name = sjson_str(&sj, "name")?.to_string();
    let t = sjson_str(&sj, "good").ok().and_then(|s| {
        if s == "true" {
            Some(SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs())
        } else {
            None
        }
    });
    add_tact(name, &b64_to_cid(sjson_str(&sj, "ct")?)?, t, c)?;
    Ok(b"ok")
}

//Handle posts to /proxy
fn proxy_p(_: &Headers, bod: &[u8], c: &Context) -> SfRes<&'static [u8]> {
    let sj: Value = serde_json::from_slice(bod)?;
    let sa: SocketAddr = sjson_str(&sj, "proxy")?.parse()?; //validate proxy address
    let mut config = yml(&c.workdir.join("config.yml")).into_hash().unwrap(); //get config.yml
    if sjson_str(&sj, "ver")? == "4" {
        let socks4 = Yaml::String("socks4".to_string());
        config.insert(socks4, Yaml::String(format!("{}", sa)));
    } else {
        let socks5 = Yaml::String("socks5".to_string());
        config.insert(socks5, Yaml::String(format!("{}", sa)));
    }
    save_yaml(&c.workdir, &Yaml::Hash(config));
    restart();
    Ok(b"ok")
}

//Rust is dumb sometimes. This is all just to add AsRef<[u8]> to KeyWrap
struct KeyWrap {
    k: KeyString,
}
impl KeyWrap {
    fn new(k: KeyString) -> Self {
        Self { k: k }
    }
}
impl AsRef<[u8]> for KeyWrap {
    fn as_ref(&self) -> &[u8] {
        self.k.as_str().as_bytes()
    }
}
//Handles POST's to /sendmsg to send a message
fn send_inner(_: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<KeyWrap> {
    let sj: Value = serde_json::from_slice(bod)?;
    let ptxt = sjson_str(&sj, "text")?;
    let binconvoid = b64_to_cid(sjson_str(&sj, "cid")?)?;
    Ok(KeyWrap::new(b64spk(&sendmsg(&binconvoid, ptxt, ctxt)?)))
}

//Handles POST's to /truncate to truncate a shared file
fn truncate_post(_headers: &Headers, uri: &str, context: &Context) -> SfRes<Vec<u8>> {
    let q = uri.split("?").nth(1).ok_or(NoneErr)?;
    let mut splitter = q.split('.');
    let conn = b64_cid_to_convo(context, splitter.next().ok_or(NoneErr)?)?;
    let fid: i64 = splitter.next().ok_or(NoneErr)?.parse()?;
    let len: i64 = splitter.next().ok_or(NoneErr)?.parse()?;
    if len % 1024 != 0 {
        return Err(SfErr::BadLen);
    }
    conn.conn_flock(fid)?;
    let res = format!("{}", conn.conn_ftrc(fid, len)? == len);
    conn.conn_funlock(fid)?; //and let it free
    Ok(res.into_bytes())
}

//Thread to pump an upload stream in the absence of packets from the other side
fn streamup(c: Arc<Conn>, donevc: Arc<(Mutex<bool>, Condvar)>, rttmsf: f64, sid: i64) {
    let mut delay_dead = (Duration::from_millis((rttmsf * 2.0) as u64), false);
    debug!("streamup starting {}", b64spk(&c.idkeys.sign.pk));
    while {
        let d = &sid;
        if let Ok(Some(t)) = c.streamies.lock().map(|s| s.get(d).map(|t| Arc::clone(t))) {
            if let Ok(mut trck) = t.write() {
                if let StreamTracker::Read(ref mut rd) = &mut *trck {
                    if let Ok(tub) = c.stube.read() {
                        delay_dead = rd.stream.check_rto(&*tub, None);
                    }
                }
            }
        }
        if delay_dead.1 {
            debug!("streamup rto dead");
            log_err!(c.streamies.lock().map(|mut s| s.remove(&sid)), ""); //drops the receiver, triggering an upload thread SendError
            if let Ok(mut d) = donevc.0.lock() {
                *d = true; //we're done
                donevc.1.notify_one();
            }
        } else {
            thread::sleep(delay_dead.0); //wait for the delay
        }
        donevc.0.lock().map(|d| !*d).unwrap_or(false) //while condition
    } {}
    debug!("streamup rto thread {} done", b64spk(&c.idkeys.sign.pk));
}

//microphone noise POST handler
fn audio_inner(h: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<&'static [u8]> {
    let con = b64_cid_to_convo(ctxt, h.get("cid").ok_or(NoneErr)?)?;
    let b = bdoc_to_u8vec(&doc! {"audio": binary_bson(bod), "ts": epoch_timestamp()});
    con.send_conn(&ctxt.keys, &b, false)?;
    Ok(b"ok")
}

fn send_vid_chunk(bod: &[u8], sid: &str, p: i32, con: &Conn, ctxt: &Context) -> SfRes<()> {
    const VID_CHUNK_LEN: usize = 1188;
    let t = bod.len() as i32; //total
    let mut offset = 0;
    while offset < bod.len() {
        let v = binary_bson(&bod[offset..bod.len().min(offset + VID_CHUNK_LEN)]);
        let bs = binary_bson(&base64::decode_config(sid, URL_SAFE_NO_PAD)?);
        let b = bdoc_to_u8vec(&doc! {"video": v, "s": bs, "p": p, "o": offset as i32, "t": t});
        debug!("Sending video p {} o {} t {}", p, offset, t);
        con.send_conn(&ctxt.keys, &b, false)?;
        offset += VID_CHUNK_LEN;
    }
    Ok(())
}
//video POST handler
fn video_inner(h: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<&'static [u8]> {
    let con = b64_cid_to_convo(ctxt, h.get("cid").ok_or(NoneErr)?)?;
    let sid = h.get("sid").ok_or(NoneErr)?;
    let mut p: i32 = h.get("p").ok_or(NoneErr)?.parse()?; //packet ID
    let mut offset = 0;
    let splits = h.get("splits").ok_or(NoneErr)?.split(",");
    for split_parse in splits.map(|s| s.parse::<usize>()) {
        if let Ok(split_len) = split_parse {
            let next_offset = offset + split_len;
            send_vid_chunk(&bod[offset..next_offset], sid, p, &con, ctxt)?;
            p += 1;
            offset = next_offset;
        }
    }
    Ok(b"ok")
}

//video request; sends a first-chunk request (to get webm header with various params)
fn vid_request(h: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<&'static [u8]> {
    let con = b64_cid_to_convo(ctxt, h.get("cid").ok_or(NoneErr)?)?;
    let streamid = std::str::from_utf8(bod)?;
    let b = bdoc_to_u8vec(&doc! {"vid_request": streamid, "ts": epoch_timestamp()});
    con.send_conn(&ctxt.keys, &b, false)?;
    Ok(b"ok")
}

//Announce that you're stopping your video stream
fn vid_stop(h: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<&'static [u8]> {
    let con = b64_cid_to_convo(ctxt, h.get("cid").ok_or(NoneErr)?)?;
    let streamid = std::str::from_utf8(bod)?;
    let b = bdoc_to_u8vec(&doc! {"vid_stop": streamid, "ts": epoch_timestamp() });
    con.send_conn(&ctxt.keys, &b, false)?;
    Ok(b"ok")
}

//invite sending POST handler
fn sendinvite(_head: &Headers, bod: &[u8], ctxt: &Context) -> SfRes<KeyWrap> {
    let sj: Value = serde_json::from_slice(bod)?;
    let cid = b64_to_cid(sjson_str(&sj, "cid")?)?; //convoid asked to join
    let sbci = b64_to_cid(sjson_str(&sj, "scid")?)?; //convoid to be joined
    Ok(KeyWrap::new(b64spk(&send_invite(&cid, &sbci, ctxt)?)))
}

//Accepts an invite
fn accept_inv(bod: &[u8], ctxt: &Context, nsender: &ChatSnd) -> SfRes<Vec<u8>> {
    let sj: Value = serde_json::from_slice(bod)?;
    let mkey = b64_to_cid(sjson_str(&sj, "meetkey")?)?;
    let binskey = b64_to_cid(sjson_str(&sj, "sesskey")?)?;
    let idkeys = seed_keys(b64_to_cid(sjson_str(&sj, "seed")?)?);
    let madd = sjson_str(&sj, "meetaddr")?;
    let meetnode = match ctxt.get_node(&mkey) {
        Ok(node) => node,
        Err(_e) => {
            let mkey_box = wr_crypto_sign_pk_to_box(&mkey);
            let node = PubNode::new(mkey.clone(), mkey_box, madd.parse()?);
            query_nodelist(&node, &mkey, ctxt, false, true); // verify before joining
            ctxt.get_node(&mkey)?
        }
    };
    let p = if let NodeAddr::Sockaddr(saddr) = meetnode.address {
        let mnode = PubNode::new(meetnode.key, meetnode.bkey, saddr);
        let snd = nsender.clone();
        let conn = join_cid(idkeys, mnode, binskey, ctxt, snd, true)?;
        conn.send_display(ctxt)?;
        conn.participants_map(ctxt)
    } else {
        return Err(SfErr::BadMeet);
    };
    let j = json!({ "participants": p });
    Ok(j.to_string().into_bytes())
}

//Starts a new conversation
fn newconv(bod: &[u8], ctxt: &Context, nsender: &ChatSnd) -> SfRes<Vec<u8>> {
    let sj: Value = serde_json::from_slice(bod)?;
    let bk = b64_to_cid(sjson_str(&sj, "tgt")?)?;
    let chatgt = get_connection(&bk, ctxt, wr_randomkey(), rand_keys(), nsender)?;
    chatgt.send_display(ctxt)?;
    let ctx = ctxt.contacts.lock()?;
    let cm = ctx.get(&b64spk(&bk)).map(|c| (c.name.clone(), c.verified));
    let (dn, v) = cm.unwrap_or_else(|| ("".to_string(), None));
    let j = json!({"convoid": b64spk(&chatgt.idkeys.sign.pk).as_str(), "disp": dn, "verified": v});
    Ok(j.to_string().into_bytes())
}

//Leaves the conversation
fn leave(_headers: &Headers, ciduri: &str, ctxt: &Context) -> SfRes<&'static [u8]> {
    let tgt = b64_to_cid(ciduri)?;
    let con = Arc::clone(ctxt.convos.lock()?.get(&tgt).ok_or_else(sfnone)?);
    log_err!(con.conn_leave(ctxt), "Conn leave call");
    con.close(); //sends exit
    //Send closing msg to sync; notify other devices of the new convo and don't auto-rejoin
    if let Ok(mss) = ctxt.meetstate_sender.lock() {
        debug!("Notify closing {}", b64spk(&con.idkeys.sign.pk));
        let msres = mss.send(MeetStateMsg {
            opening: false,
            idkeys: con.idkeys.clone(),
            key: con.key.clone(),
            meet_host: con.meet.read()?.clone(),
            backups: Vec::new(),
        });
        log_err!(msres, "MeetStateMsg send");
    }
    Ok(b"\"leaving\"")
}

//Shuts down schadnfreude
fn shutdown_post(stream: &mut TcpStream, uri: &str, ctx: &Context) -> SfRes<()> {
    info!("schadnfreude exiting");
    let mut c = ctx.convos.lock()?;
    for (_k, conn) in c.iter() {
        conn.close();
    }
    ctx.shutting_down.store(true, Relaxed); //Trigger meetmonitor quit
    let mut jhs = Vec::with_capacity(c.len());
    loop {
        let k = match c.keys().next() {
            Some(k1) => k1.clone(),
            None => break,
        };
        let mut myjh = None;
        if let Some(ca) = c.remove(&k) {
            if let Ok(mut jh) = ca.running.lock() {
                myjh = jh.take(); //grab the thread to wait on later
            } else {
                error!("Couldn't lock running");
            }
            debug!("Closing {} {} arcs", b64spk(&k), Arc::strong_count(&ca));
        } else {
            break; // no convos left
        }
        myjh.map(|jh| jhs.push(jh));
    }
    for jh in jhs {
        debug!("Waiting on {:08X}", hash(&jh.thread().id()) as u32);
        jh.join().unwrap_or_else(|_| error!("thread panicked")); //wait for client thread to die
    }
    while let Ok(circuits) = ctx.circuits.lock() {
        let c = if let Some(kv) = circuits.iter().next() {
            Arc::clone(kv.1)
        } else {
            break;
        };
        drop(circuits); //release the circuits lock hopefully
        debug!("Closing control channel");
        c.close_idx(0); //close control channel (and all inner ones)
    }
    info!("Done cleaning up");
    //Restart?
    if let Some(q) = uri.split("?").nth(1) {
        if q == "restart" {
            restart();
        }
    }
    do_reply(stream, "Content-Type: text/plain\r\n", b"ok")?;
    process::exit(0);
}

//Sets your display name
fn pname(b: &[u8], ctxt: &Context) -> SfRes<&'static [u8]> {
    let display_name = String::from_utf8(b.to_vec())?;
    let ver = Some(SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs());
    if !add_tact(display_name, &ctxt.keys.sign.pk[..], ver, ctxt)? {
        let c = ctxt.convos.lock()?; //display name changed. Update convos
        for (_k, conn) in c.iter() {
            conn.send_display(ctxt)?;
        }
    }
    Ok(b"ok")
}

//PROPPATCH for WebDAV writes. stream will include a body like:
//<?xml version="1.0" encoding="utf-8" ?><D:propertyupdate xmlns:D="DAV:"
//xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop>
//<Z:Win32CreationTime>Fri, 11 Dec 2020 21:09:55 GMT</Z:Win32CreationTime>
//<Z:Win32FileAttributes>00000020</Z:Win32FileAttributes></D:prop></D:set></D:propertyupdate>
//Schadnfreude FS doesn't actually support file properties, so we just no-op but reply with XML
fn proppatch(_: &Context, s: &mut TcpStream, uri: &str, b: &[u8], h: &Headers) -> SfRes<()> {
    get_full_body!(s, h, b, full_body); //read full HTTP body in to get props requested
    let mut respbody = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
     <D:prop xmlns:D=\"DAV:\"><D:response><D:href>"
        .to_string();
    respbody.push_str(uri);
    respbody.push_str("</D:href>\n");
    //loop over each prop again to write them out
    for pos in 0..full_body.len() - 8 {
        if &full_body[pos..pos + 8] == b"<D:prop>" {
            let off = if let Some(open) = full_body[pos + 8..].iter().position(|&b| b == b'<') {
                open + pos + 8
            } else {
                continue;
            };
            let eoff = if let Some(close) = full_body[off + 1..].iter().position(|&b| b == b'>') {
                close + off + 1
            } else {
                continue;
            };
            respbody.push_str("<D:propstat><D:prop>");
            respbody.push_str(str::from_utf8(&full_body[off..eoff])?);
            if full_body[eoff - 1] != b'/' {
                respbody.push_str("/");
            }
            respbody.push_str("></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>");
        }
    }
    respbody.push_str("</D:response></D:multistatus>");
    let xmlct = "Content-Type: application/xml\r\n";
    code_reply(s, 207, xmlct, respbody.as_bytes()) //send resp as 207
}

//Problem: directly accessing a UNC path on Windows will fail unless the shell has 1st triggered it
//to be accessed by the WebDAV mini-redirector. Solution: call a simple Shell32 function to do so.
//We use SHParseDisplayName since it's one of the few that works and doesn't make us use COM (yuck!)
fn uncprime(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let (_conn, _path) = match uri_to_path(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //must be of form cid/path/...
        Ok(c) => c,
    };
    #[cfg(windows)]
    {
        let mut shell_path = format!("\\\\{}", ctxt.addr.ip());
        if ctxt.addr.port() != 80 {
            shell_path.push_str(&format!("@{}", ctxt.addr.port()));
        }
        shell_path.push_str(uri);
        info!("Priming UNC path {}", shell_path);
        use std::os::windows::ffi::OsStrExt; //allows us to use encode_wide
        let uncpath = std::ffi::OsString::from(shell_path); //but first convert to OsString
        let mut utf16le: Vec<u16> = uncpath.encode_wide().collect(); //Then convert to LPWSTR
        utf16le.push(0); //gotta add null terminator
        type ILFreeFunc = unsafe fn(usize); //Define func types to resolve
        type SHPDNFunc = unsafe fn(*const u16, usize, *mut usize, usize, *mut usize);
        let mut thepointer = 0; //It'll be an item ID list, but we don't really care. We free it.
        let mut dontcare = 0; //also really don't care. But it gets written to.
        use libloading::Symbol;
        let (shpdn_str, ilf_str) = (b"SHParseDisplayName", b"ILFree"); //Func names must be binary
        if let Ok(shell32) = libloading::Library::new("shell32.dll") {
            unsafe {
                if let (Ok(s), Ok(f)) = (shell32.get(shpdn_str), shell32.get(ilf_str)) {
                    #[allow(non_snake_case)]
                    let SHParseDisplayName: Symbol<SHPDNFunc> = s; //they loaded correctly
                    #[allow(non_snake_case)]
                    let ILFree: Symbol<ILFreeFunc> = f; //Now we can call them by their proper names
                    SHParseDisplayName(&utf16le[0], 0, &mut thepointer, 0, &mut dontcare);
                    ILFree(thepointer); //if it is successful, frees the ITEMIDLIST structure
                }
            }
        }
    }
    code_reply(stream, 204, "", b"") //send 204 (OK no content, no extra headers needed)
}

//UNLOCK for WebDAV writes. Will have URL path and Lock-Token: <...> header but we ignore token
fn http_unlock(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let (conn, fid) = match uri_to_fid(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //404 not found
        Ok(c) => c,
    };
    if let Err(_e) = conn.conn_funlock(fid) {
        return code_reply(stream, 403, "", b""); //403 not allowed? probably won't happen
    }
    code_reply(stream, 204, "", b"") //send 204 (OK no content, no extra headers needed)
}

//LOCK for WebDAV writes. stream will include a body like:
//<?xml version="1.0" encoding="utf-8" ?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:
//lockscope><D:locktype><D:write/></D:locktype><D:owner><D:href>user</D:href></D:owner></D:lockinfo>
fn lock(ct: &Context, s: &mut TcpStream, uri: &str, bod: &[u8], hed: &Headers) -> SfRes<()> {
    get_full_body!(s, hed, bod, _full_body); //read full HTTP body in (although we ignore it)
    let (_conn, fid) = match uri_to_fid(ct, uri) {
        Err(_e) => return code_reply(s, 423, "", b""), //423 - already locked TODO: return 404 if so?
        Ok(c) => c,
    };
    //Create lock token and hexify
    let mut tokenb = [0x20; 16];
    let mut c = Cursor::new(&mut tokenb[..]);
    write!(c, "{}", fid)?;
    let end = c.position() as usize;
    let token = str::from_utf8(&tokenb[..end])?;

    const PRE: &str = "Content-Type: application/xml\r\nLock-Token: <schadnlock:";
    const POST: &str = ">\r\n";
    const BUFLEN: usize = PRE.len() + 16 + POST.len();
    stack_or_vec_cursor!(BUFLEN, PRE.len() + token.len() + POST.len(), cur); //get right len slice
    write!(cur, "{}{}{}", PRE, token, POST)?; //write it

    //Create lock response body
    let start = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
     <D:prop xmlns:D=\"DAV:\">\n\
       <D:lockdiscovery>\n\
         <D:activelock>\n\
           <D:locktype><D:write/></D:locktype>\n\
           <D:lockscope><D:exclusive/></D:lockscope>\n\
           <D:depth>0</D:depth>\n\
           <D:timeout>Second-604800</D:timeout>\n\
           <D:locktoken>\n\
             <D:href>schadnlock:";
    let mid = "</D:href>\n\
           </D:locktoken>\n\
           <D:lockroot>\n\
             <D:href>";
    let end = "</D:href>\n\
           </D:lockroot>\n\
         </D:activelock>\n\
       </D:lockdiscovery>\n\
     </D:prop>";
    let body_len = start.len() + 16 + mid.len() + uri.len() + end.len();
    stack_or_vec_cursor!(1024, body_len, body); //get hlen-byte slice from 1k stack buf or allocate
    write!(body, "{}{}{}{}{}", start, token, mid, uri, end)?;

    //TODO: Save Lock-Token. Unsure if needed?
    do_reply(s, str::from_utf8(cur.into_inner())?, body.into_inner()) //send contents
}

//PUT for WebDAV writes - uploads a file
fn put(
    ctxt: &Context,
    bod: &[u8],
    st: &mut TcpStream,
    uri: &str,
    h: &Headers,
    nsender: &ChatSnd,
) -> SfRes<()> {
    let (conn, filename) = match uri_to_path(ctxt, uri) {
        Err(e) => {
            code_reply(st, 404, "", b"")?; //must be of form cid/path/...
            return Err(e);
        }
        Ok(c) => c,
    };
    let filename: &str = &filename;
    let locked = h
        .get("x-lock")
        .and_then(|h| h.parse().ok())
        .unwrap_or(false); //get shared
    debug!("Putting file. Locked? {}", locked);
    let body_len = match h.get("content-length").and_then(|h| h.parse().ok()) {
        Some(contlen) => contlen, //parsed into a number fine
        None => {
            code_reply(st, 400, "", b"Bad content-length")?; //Bad or missing header
            return Err(SfErr::NoneErr);
        }
    };
    info!("Starting file upload for {}", filename);
    let mut n = rand_i64(); //nonce
    let rttmsf = conn.rttest.load(Relaxed) as f64;
    let fid = match conn.conn_fpathlock(filename).and_then(|fid|{
            conn.conn_ftrc(fid, 0)?; // overwrite - so truncate to 0 bytes
            n = conn.conn_fmeta(fid)?.0.get_i64("nonce")?;
            debug!("Using nonce {}", n); //If you edit a file only the edited parts change
            Ok(fid)
        }).or_else(|_| conn.conn_fnew(&filename, n, locked)) //new upload
     {
        Err(e) => {
            error!("Error starting upload {}", e);
            code_reply(st, 404, "", b"")?; //must be of form cid/path/...
            return Err(e);
        }
        Ok(ret) => ret,
    };
    let mut buf = [0; 16 * 1024];
    if body_len > 0 {
        let sid = match conn.conn_swrite(fid, 0) {
            Err(e) => {
                error!("Error starting upload stream {}", e);
                code_reply(st, 404, "", b"")?;
                return Err(e); //kill the upload so data doesn't get read in by next
            }
            Ok(s) => s,
        };
        let (sender, r) = bounded(0); //ordered with no buffer
        let creader = CryptReader::new(ChanReader::new(r), Arc::clone(&conn), n);
        let donevar = Arc::new((Mutex::new(false), Condvar::new())); //shared done condvar
        let rstr = ReadTracker {
            done: Arc::clone(&donevar),
            stream: ReadStream::new(sid, creader, rttmsf),
        };
        let rtrackr = Arc::new(RwLock::new(StreamTracker::Read(rstr)));
        conn.streamies.lock()?.insert(sid, rtrackr);
        debug!("PUT stream start fid {} sid {} bl {}", fid, sid, bod.len());
        let (c, donevc) = (Arc::clone(&conn), Arc::clone(&donevar));
        spawn_thread("streamup", move || streamup(c, donevc, rttmsf, sid)); //encrypting up stream
        let mut sent_bytes = 0;
        if bod.len() > 0 {
            log_err!(sender.send(bod.to_vec()), "Chunk bod send"); //blocking send.
            sent_bytes += bod.len(); //as long as the chunks >= 1 byte, exact sizes don't matter.
        }
        //SEND BYTES LOOP
        while sent_bytes < body_len {
            let next_chunk_len = buf.len().min(body_len - sent_bytes); //read buf sized chunks until end
            st.read_exact(&mut buf[..next_chunk_len])?;
            let chunk = &buf[..next_chunk_len];
            debug!("chunk len {}", chunk.len()); //more data from client in this file
            log_err!(sender.send(chunk.to_vec()), "Chunk loop"); //blocking send.
            sent_bytes += chunk.len();
        }
        //CLOSE STREAM
        debug!("end of upload");
        log_err!(sender.send(Vec::new()), "Chunk end"); //0 bytes = EOF
        let mut l = donevar.0.lock()?; //wait for ack from remote side
        while !*l {
            l = match donevar.1.wait(l) {
                Ok(l) => l,       //loop since we have to retry on spurious wakeup
                Err(_e) => break, //err only happens if the other thread panics. No need to log here
            }
        }
        debug!("File upload acked. Closing stream and unlocking.");
        log_err!(conn.conn_sclose(sid, fid), "upload sclose");
    }
    log_err!(conn.conn_funlock(fid), "upload unlock");
    //Let everybody know about the posted file, pad so inner send is 343 bytes
    let pad = binary_bson(&PADDING[..127 - (filename.as_bytes().len() % 127)]);
    let ts = epoch_timestamp();
    let b = doc! {"path": filename, "fid": fid, "timestamp": ts, "shared": !locked, "pad": pad};
    let msg = bdoc_to_u8vec(&b);
    let mut resp_headers = "";
    match conn.send_conn(&ctxt.keys, &msg, true) {
        Ok(hsh) => {
            let mut b64 = [0; 43];
            base64::encode_config_slice(hsh, URL_SAFE_NO_PAD, &mut b64);
            let mut cur = Cursor::new(&mut buf[..]);
            write!(cur, "X-Hash: {}\r\n", str::from_utf8(&b64)?)?; //prep response header with hash in it
            write!(cur, "X-FID: {}\r\n", fid)?; //prep response header with hash in it
            let spot = cur.position() as usize;
            resp_headers = str::from_utf8(&buf[..spot])?;
        }
        Err(e) => error!("sending err {}", e),
    }
    //If it wasn't browser-initiated, tell the browser about it.
    if h.get("user-agent").map(|u| u.contains("DAV")) == Some(true) {
        let nsres = nsender.send(ChatMsg {
            doc: b,
            midpoint: json!({}),
            signer: ctxt.keys.sign.pk.clone(),
            convoid: Some(conn.idkeys.sign.pk.clone()),
            seq: None,
        });
        log_err!(nsres, "");
    }
    debug!("Done with file upload for {}", filename);
    code_reply(st, 204, resp_headers, b"") //send 204 (OK no content, no extra headers needed)
}

//MKCOL for WebDAV (mkdir)
fn http_mkcol(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let (conn, path) = match uri_to_path(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //must be of form cid/path/...
        Ok(c) => c,
    };
    let path: &str = &path;
    let res = match conn.conn_newfold(path) {
        Err(_e) => return code_reply(stream, 403, "", b""), //Pretend auth error. Or maybe no room?
        Ok(c) => c,
    };
    let pad = binary_bson(&PADDING[..112 - (path.as_bytes().len() % 112)]); //gets inner send to 343
    let b = doc! {
        "path": path,
        "fid": res,
        "type": "fold",
        "timestamp": epoch_timestamp(),
        "shared": true,
        "pad": pad,
    };
    log_err!(conn.send_conn(&ctxt.keys, &bdoc_to_u8vec(&b), true), "md");
    let mut buf = [0; 32];
    let mut cur = Cursor::new(&mut buf[..]);
    write!(cur, "X-FID: {}\r\n", res)?; //prep response header with hash in it
    let spot = cur.position() as usize;
    let resp_headers = str::from_utf8(&buf[..spot])?;
    code_reply(stream, 204, resp_headers, b"") //send 204 (OK no content, no extra headers needed)
}

//     MOVE /abc/def.html HTTP/1.1
//     Destination: http://www.example/users/f/fielding/def.html
// Response
//     HTTP/1.1 201 Created
//     Location: http://www.example.com/users/f/fielding/index.html
fn http_move(ctxt: &Context, stream: &mut TcpStream, uri: &str, h: &Headers) -> SfRes<()> {
    let prerequsities = match h.get("destination").ok_or(NoneErr).and_then(|dh| {
        let (conn, path) = uri_to_path(ctxt, uri)?;
        let fid = conn.conn_fpathlock(&path)?;
        let nonce = conn.conn_fmeta(fid)?.0.get_i64("nonce")?;
        let dest = dh.splitn(5, "/").nth(4).ok_or(NoneErr)?;
        let decoded = uridecode(dest)?;
        Ok((dh, path, conn, nonce, decoded))
    }) {
        Err(e) => {
            debug!("{}", e);
            return code_reply(stream, 404, "", b"");
        } //src isn't there or dest/src bad form
        Ok(c) => c,
    };
    let (desth, path, conn, nonce, decoded) = prerequsities;
    let res = match conn.conn_frename(&path, nonce, &decoded) {
        Ok(r) => r,                                         //did the move
        Err(_e) => return code_reply(stream, 400, "", b""), //host died?
    };
    log_err!(conn.conn_funlock(res), "move unlock"); //let it free
    let fidlen = ((res.max(1) as f64).log10() + 1.0) as usize; //how many digits the fid is
    debug!("Moved to new lens {} {} {}", res, fidlen, desth.len());
    let lochlen = "Location: ".len() + desth.len() + "X-FID: ".len() + 4 + fidlen; //headers len
    stack_or_vec_cursor!(160, lochlen, extra_head); //get slice from stack buf or allocate
    write!(extra_head, "Location: {}\r\nX-FID: {}\r\n", desth, res)?; //write resp headers
    code_reply(stream, 201, str::from_utf8(extra_head.into_inner())?, b"") //send 201 Created
}

//DELETE for WebDAV
fn http_delete(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let res = uri_to_fid(ctxt, uri).and_then(|(c, fid)| Ok(fid == c.conn_fdel(fid)?));
    if res.unwrap_or(false) {
        code_reply(stream, 204, "", b"") //send 204 no content, but success
    } else {
        code_reply(stream, 404, "", b"") //send 404 not found
    }
}

pub enum Strng<'a> {
    Stref(&'a str),
    Strown(String),
}
use Strng::*;
impl<'a> core::ops::Deref for Strng<'a> {
    type Target = str;
    fn deref(&self) -> &str {
        match &self {
            Stref(mystr) => mystr,
            Strown(mystring) => &mystring,
        }
    }
}
//bitmap of bad path chars. Bad ones are in the range 0-32, or one of these: <, >, :, ", |, ?, *
static BADCHARS: [u8; 32] = [
    255, 255, 255, 255, 4, 4, 0, 212, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

fn uridecode<'a>(path: &'a str) -> SfRes<Strng<'a>> {
    let mut decoded = None; //Optional vec. Hopefully we don't have to copy.
    let mut i = 0;
    while i < path.len() {
        if path.as_bytes()[i] >= 0x80 || BADCHARS.get_bit(path.as_bytes()[i].into()) {
            debug!("URI decode fail byte {}", path.as_bytes()[i]);
            return Err(SfErr::BadPath); //no unicode stuffs allowed in the raw here
        } else if path.as_bytes()[i] == b'%' {
            if path.len() < i + 3 {
                debug!("URI decode fail percent too short {}", path);
                return Err(SfErr::BadPath);
            }
            if let None = decoded {
                decoded.replace(path.as_bytes()[..i].to_vec()); //now it's a copied string
            }
            let ch = u8::from_str_radix(str::from_utf8(&path.as_bytes()[i + 1..i + 3])?, 16)?;
            if BADCHARS.get_bit(ch as usize) {
                debug!("URI decode fail decoded {}", ch);
                return Err(SfErr::BadPath); //no bad chars allowed decoded either
            } else if let Some(ref mut myvec) = decoded {
                myvec.push(ch); //should always be a vec by the time we get here
            }
            i += 2;
        } else if let Some(ref mut myvec) = decoded {
            myvec.push(path.as_bytes()[i]);
        }
        i += 1;
    }
    //Only do UTF-8 validation here (not mid-char as above!)
    if let Some(d) = decoded {
        Ok(Strown(String::from_utf8(d)?))
    } else {
        Ok(Stref(path))
    }
}

//Parses a WebDAV path, verifies, decodes URI if applicable, and gets the Conn
fn uri_to_path<'a>(ctxt: &Context, uri: &'a str) -> SfRes<(Arc<Conn>, Strng<'a>)> {
    let mut splitter = uri.splitn(3, "/");
    splitter.next(); //skip opening /
    let cidstr = splitter.next().ok_or(SfErr::NotFound)?;
    let path = splitter.next().unwrap_or(""); //might not exist
    Ok((b64_cid_to_convo(ctxt, cidstr)?, uridecode(path)?))
}

//Parses a WebDAV path, verifies and gets the Conn, and looks up and locks the FID
fn uri_to_fid(ctxt: &Context, uri: &str) -> SfRes<(Arc<Conn>, i64)> {
    let (conn, path) = uri_to_path(ctxt, uri)?;
    let fid = conn.conn_fpathlock(&path)?;
    Ok((conn, fid)) //lock the file and return the fid
}

//GET for WebDAV
fn unknown_get(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let (conn, fid) = match uri_to_fid(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //must be of form cid/path/...
        Ok(c) => c,
    };
    download_fid(conn, stream, fid, 0) //Maybe support Range header sometime
}

//HEAD for WebDAV
fn unknown_head(ctxt: &Context, stream: &mut TcpStream, uri: &str) -> SfRes<()> {
    let (conn, fid) = match uri_to_fid(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //must be of form cid/path/...
        Ok(c) => c,
    };
    if let Err(_e) = conn.conn_funlock(fid) {
        return code_reply(stream, 403, "", b""); //403 not allowed? probably won't happen
    }
    if let Err(e) = conn.conn_fmeta(fid).and_then(|(_, met, _)| {
        if let Ok(true) = met.get_bool("del") {
            return Err(SfErr::DeletedError);
        }
        Ok(())
    }) {
        let tp = "Content-Type: text/plain\r\n";
        code_reply(stream, 400, tp, format!("{}", e).as_bytes())
    } else {
        let octets = "Content-Type: application/octet-stream\r\n";
        code_reply(stream, 200, octets, b"")
    }
}

//Directory list/stat for WebDAV
fn propfind(ctxt: &Context, stream: &mut TcpStream, uri: &str, hdrs: &Headers) -> SfRes<()> {
    let (conn, path) = match uri_to_path(ctxt, uri) {
        Err(_e) => return code_reply(stream, 404, "", b""), //must be of form cid/path/...
        Ok(c) => c,
    };
    let content_info = if path.is_empty() {
        None //Root is a folder
    } else if let Ok(fid) = conn.conn_fpathlock(&path) {
        let (inner, _outer, flen) = match conn.conn_fmeta(fid) {
            Ok(meta) => meta,
            Err(_e) => return code_reply(stream, 404, "", b""),
        };
        log_err!(conn.conn_funlock(fid), "propfind unlock"); //let it free
        if let Ok("fold") = inner.get_str("type") {
            None //It's a folder
        } else {
            Some(flen) //It's a file and has a length
        }
    } else {
        return code_reply(stream, 404, "", b""); //Bad path
    };
    let headr = "<?xml version=\"1.0\" encoding=\"utf-8\" ?>\n\
<D:multistatus xmlns:D=\"DAV:\" xmlns:Z=\"urn:schemas-microsoft-com:\">\n\
<D:response>\n<D:href>";
    let contype = "<D:getcontenttype>application/octet-stream</D:getcontenttype>\n";
    let trail = "</D:href>\n<D:propstat>\n<D:prop>\n\
<D:creationdate>2000-01-01T23:59:59Z</D:creationdate>\n\
<D:getlastmodified>Mon, 12 Jan 1998 09:25:56 GMT</D:getlastmodified>\n\
<D:displayname></D:displayname>\n";
    let end = "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n</D:response>\n";
    let mut filepropsbuf = [0; 1024];
    let fileprops = if let Some(flen) = content_info {
        let mut fpcur = Cursor::new(&mut filepropsbuf[..]);
        write!(fpcur, "<D:getcontentlength>{}</D:getcontentlength>\n", flen)?; //Additional file props. Excluding contentlanguage or etag
        write!(fpcur, "{}", contype)?;
        let wrotelen = fpcur.position() as usize;
        str::from_utf8(&filepropsbuf[..wrotelen])?
    } else {
        "<D:resourcetype><D:collection/></D:resourcetype>\n"
    }; // dir prop
    let mut res = format!("{}{}{}{}{}", headr, uri, trail, fileprops, end);

    //Now if it's a collection, add folder items by looping over all the fids and finding children
    let infinite = hdrs.get("depth") == Some(&"infinity");
    if content_info.is_none() && hdrs.get("depth") != Some(&"0") {
        res.reserve(2048); //give us some room. We'll use a bunch.
        let enummer = FileEnum::new(Arc::clone(&conn), Arc::clone(&ctxt.cache));
        for f in enummer {
            //e.g. {'id':0,'met':{'path':'hi.txt'},'lock':false,'len':5,'deleted':false}
            let item: serde_json::map::Map<String, Value> =
                ok_or_continue!(serde_json::from_slice(&f));
            let metj = ok_or_continue!(item.get("met").ok_or(SfErr::NoneErr));
            let met = ok_or_continue!(metj.as_object().ok_or(SfErr::NoneErr));
            let pthj = ok_or_continue!(met.get("path").ok_or(SfErr::NoneErr));
            let pth = ok_or_continue!(pthj.as_str().ok_or(SfErr::NoneErr));
            let locked = item.get("lock") == Some(&serde_json::value::Value::Bool(true));
            if locked || pth.len() <= path.len() || !pth.starts_with(&path as &str) {
                continue; // ignore locked or other folders
            }
            let sub_path = if pth.as_bytes()[path.len()] == b'/' {
                pth.split_at(path.len() + 1).1
            } else {
                pth.split_at(path.len()).1
            };
            if !infinite && sub_path.contains('/') {
                continue; //ignore subfolders unless infinite recursion
            }
            res.push_str("<D:response><D:href>");
            res.push_str(uri);
            if !uri.ends_with('/') && !sub_path.starts_with('/') {
                res.push_str("/");
            }
            res.push_str(sub_path);
            res.push_str(trail);
            if let Some("fold") = met.get("type").and_then(|t| t.as_str()) {
                res.push_str("<D:resourcetype><D:collection/></D:resourcetype>\n");
            } else {
                let l = item.get("len").and_then(|l| l.as_u64()).unwrap_or(0);
                res.push_str(&format!("<D:getcontentlength>{}</D:getcontentlength>", l));
                res.push_str(contype);
            }
            res.push_str(end);
        }
    }
    res.push_str("</D:multistatus>\n");
    let davxml = "DAV: 1, 2\r\nContent-Type: text/xml\r\n";
    do_reply(stream, davxml, res.as_bytes()) //do_reply adds Content-Length
}

//Run the HTTP server.
pub fn run_apisrv(nr: Receiver<ChatMsg>, ctxt: Context, sn: ChatSnd) -> usize {
    let token = b64spk(&wr_randomkey()); //Prep CSRF token
    let addr = ctxt.addr.clone();
    let original_info = Arc::new((Mutex::new(nr), Mutex::new(token), ctxt, sn));
    if cfg!(target_os = "windows") && cfg!(not(test)) {
        let url = format!("http://{}", addr);
        if let Err(e) = std::process::Command::new("explorer.exe").arg(url).spawn() {
            error!("Error opening http://{} in browser: {}", addr, e);
        }
    }
    run_httpsrv(addr, original_info, &srv_req)
}
//Handle one request
fn srv_req(
    meth: &str,
    uri: &str,
    headers: &Headers,
    stream: &mut TcpStream,
    bodstart: &[u8],
    args: &Arc<(Mutex<Receiver<ChatMsg>>, Mutex<KeyString>, Context, ChatSnd)>,
) -> SfRes<()> {
    let (ref rclone, ref csrftoken, ref ctxt, ref nsender) = **args;
    info!("{}: {} {}", ctxt.addr, meth, uri);
    //better have CSRF param if POST
    if meth == "POST" && *headers.get("csrftoken").unwrap_or(&"") != csrftoken.lock()?.as_str() {
        let tp = "Content-Type: text/plain\r\n";
        return code_reply(stream, 400, tp, b"Bad CSRF token");
    }
    let js_ct = "Content-Type: application/javascript\r\n";
    let html_ct = "Content-Type: text/html\r\n";
    let plain_ct = "Content-Type: text/plain\r\n";
    let css_ct = "Content-Type: text/css\r\n";
    let json_ct = "Content-Type: application/json\r\n";
    let mut uc = uri.chars();
    uc.next(); //skip the opening "/"
    match (meth, uc.as_str().split('?').next().unwrap_or("")) {
        ("GET", "") => do_reply(stream, html_ct, &include_bytes!("../index.html")[..]),
        ("GET", "index.js") => do_reply(stream, js_ct, &include_bytes!("../index.min.js")[..]),
        ("GET", "jsQR.js") => do_reply(stream, js_ct, &include_bytes!("../jsQR.min.js")[..]),
        ("GET", "qrcode.min.js") => {
            do_reply(stream, js_ct, &include_bytes!("../qrcode.min.js")[..])
        }
        ("GET", "sf.css") => do_reply(stream, css_ct, &include_bytes!("../sf.css")[..]),
        ("POST", "csrftoken") => {
            //new tab has been opened. Regenerate CSRF token and cut off old window
            if let Ok(mut c) = csrftoken.lock() {
                *c = b64spk(&wr_randomkey());
                nsender
                    .send(ChatMsg {
                        doc: doc! {"notice": "New tab opened", "timestamp": epoch_timestamp()},
                        midpoint: json!({}),
                        signer: ctxt.keys.sign.pk.clone(),
                        convoid: None,
                        seq: None,
                    })
                    .unwrap_or_else(|e| error!("Couldn't send new tab message: {}", e));
            } else {
                error!("Error locking csrftoken");
            }
            do_reply(stream, plain_ct, csrftoken.lock()?.as_bytes())
        }
        ("GET", "myinfo") => {
            let ct = csrftoken.lock()?.clone();
            let respobj = if let MeetInfo::Address(ma) = *ctxt.meet_info.lock()? {
                json!({
                    "mykey": b64spk(&ctxt.keys.sign.pk).as_str(),
                    "meetaddr": b64spk(&ma).as_str(),
                    "csrftoken": ct,
                    "dname": ctxt.display_name(),
                })
            } else {
                let synced = ctxt.synced_nodes.load(Relaxed);
                json!({"errnomeet": b64spk(&ctxt.keys.sign.pk).as_str(), "synced": synced, "csrt": ct })
            };
            do_reply(stream, plain_ct, respobj.to_string().as_bytes())
        }
        ("GET", "contacts") => {
            let respobj = json!({"contacts":&*ctxt.contacts.lock()?});
            do_reply(stream, json_ct, respobj.to_string().as_bytes())
        }
        ("GET", "convos") => {
            let respobj = json_convos(&*ctxt.convos.lock()?, ctxt);
            do_reply(stream, json_ct, respobj.to_string().as_bytes())
        }
        ("GET", "download") => download_req(stream, uri, ctxt),
        ("GET", "listfiles") => listfiles_req(stream, uri, ctxt),
        ("GET", "nextmsg") => nextmsg_req(stream, headers, csrftoken, rclone),
        ("GET", "msghistory") => {
            let nsend = nsender.clone();
            get_wrap(stream, headers, uri, &ctxt, move |_, uri, c| {
                msghistory_req(uri, c, &nsend)
            })
        }
        ("GET", "nodes") => get_wrap(stream, headers, uri, ctxt, nodes_req),
        ("POST", "contacts") => {
            return post_wrap(stream, bodstart, headers, ctxt, contacts_p);
        }
        ("POST", "proxy") => {
            return post_wrap(stream, bodstart, headers, ctxt, proxy_p);
        }
        ("POST", "sendmsg") => {
            return post_wrap(stream, bodstart, headers, ctxt, send_inner);
        }
        ("POST", "truncate") => get_wrap(stream, headers, uri, ctxt, truncate_post),
        ("POST", "sendinvite") => {
            return post_wrap(stream, bodstart, headers, ctxt, sendinvite); //invite new participant
        }
        ("POST", "acceptinvite") => {
            let (ns, bs, h) = (nsender.clone(), bodstart, headers); //Accept an invite to a convo
            return post_wrap(stream, bs, h, ctxt, move |_, b, c| accept_inv(b, c, &ns));
        }
        ("POST", "startconvo") => {
            let (n, h) = (nsender.clone(), headers);
            return post_wrap(stream, bodstart, h, ctxt, move |_, b, c| newconv(b, c, &n));
        }
        ("LEAVE", ciduri) => get_wrap(stream, headers, ciduri, ctxt, leave),
        ("POST", "audio") => {
            return post_wrap(stream, bodstart, headers, ctxt, audio_inner);
        }
        ("POST", "video") => {
            return post_wrap(stream, bodstart, headers, ctxt, video_inner);
        }
        ("POST", "requestvid") => {
            return post_wrap(stream, bodstart, headers, ctxt, vid_request);
        }
        ("POST", "vidstop") => {
            return post_wrap(stream, bodstart, headers, ctxt, vid_stop);
        }
        ("POST", "shutdown") => shutdown_post(stream, uri, &ctxt),
        ("POST", "name") => {
            return post_wrap(stream, bodstart, headers, &ctxt, move |_, b, c| pname(b, c));
        }
        //WebDAV stuff
        ("OPTIONS", _) => do_reply(stream, "DAV: 1, 2\r\n", b""),
        ("PROPFIND", _) => propfind(&ctxt, stream, uri, headers),
        ("GET", _) => unknown_get(&ctxt, stream, uri),
        ("HEAD", _) => unknown_head(&ctxt, stream, uri),
        ("LOCK", _) => lock(&ctxt, stream, uri, bodstart, headers),
        ("UNLOCK", _) => http_unlock(&ctxt, stream, uri),
        ("PUT", _) => put(&ctxt, bodstart, stream, uri, headers, nsender),
        ("MKCOL", _) => http_mkcol(&ctxt, stream, uri), //TODO: COPY. Unclear if necessary.
        ("MOVE", _) => http_move(&ctxt, stream, uri, headers),
        ("DELETE", _) => http_delete(&ctxt, stream, uri),
        ("PROPPATCH", _) => proppatch(&ctxt, stream, uri, bodstart, headers),
        ("UNCPRIME", _) => uncprime(&ctxt, stream, uri), //not a real WebDAV method; enables Windows UNC path
        //Default 404
        (_, _) => code_reply(stream, 404, html_ct, b"<h1>404</h1>"),
    }
}
