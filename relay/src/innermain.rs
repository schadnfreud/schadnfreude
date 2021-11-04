// Schadnfreude main. Includes core setup functionality used by both clients and nodes.
pub use arrayref::array_ref;
pub use base64::{self, encode_config, URL_SAFE_NO_PAD};
pub use bson::*;
pub use log::{debug, error, info, log, trace, warn, Level};
pub use rand::{thread_rng, Rng};
pub use serde_derive::{Deserialize, Serialize};
pub use serde_json::json;
pub use serde_json::Value;
pub use sled::{Db, Tree};
#[cfg(windows)]
pub use winapi;
#[cfg(windows)]
pub use winapi::um;
pub use yaml_rust;
pub use yaml_rust::yaml::Yaml;
pub use yaml_rust::{YamlEmitter, YamlLoader};

#[macro_export]
macro_rules! ok_or_continue {
    ($l:expr) => {
        match $l {
            Ok(r) => r,
            Err(_) => continue,
        }
    };
}
#[macro_export]
macro_rules! log_err {
    ($l:expr, $m:literal) => {
        if let Err(e) = $l {
            log::error!("{}: {}", $m, e);
        }
    };
}
#[macro_export]
macro_rules! some_or_break {
    ($l:expr) => {
        match $l {
            Some(r) => r,
            None => break,
        }
    };
}

pub use crate::httpsrv::*;
pub use crate::nodesrv::*;
pub use crate::client::*;
pub use crate::tube::*;
pub use crossbeam_channel::*;
pub use std::collections::hash_map::DefaultHasher;
pub use std::collections::*;
pub use std::convert::TryFrom;
pub use std::fs::File;
pub use std::hash::{Hash, Hasher};
pub use std::io::*;
pub use std::iter::FromIterator;
pub use std::net::*;
pub use std::path::PathBuf;
pub use std::sync::atomic::Ordering::Relaxed;
pub use std::sync::atomic::*;
pub use std::sync::{Arc, Condvar, Mutex, RwLock};
pub use std::thread::{Builder, JoinHandle, Thread};
pub use std::time::{Duration, Instant, SystemTime};
pub use std::*;

pub use crate::sodiumffi::*;
pub use crate::sferr::*;

//Seed nodes for the schadnfreude network.
const NETWORK_SEEDS: &[(SignPKey, &str)] = &[
    (
        *b"\x7f\x1f\x05\x42\x29\x98\x94\xbc\x52\xb8\x20\xda\xec\x47\x8d\xf8\xb5\xac\xb3\xbf\
        \xfa\x02\x84\x5f\x92\x9c\x9f\x9b\xf4\x3d\x17\xb6",
        "199.188.101.228:36080",
    ),
    (
        *b"\x62\x6e\x39\x62\x80\x7a\xd9\xd4\xba\x87\xe0\x01\x5f\x4d\x59\xd2\x1e\x71\x76\x43\
        \x85\x5a\x55\x67\x7b\x0a\x13\xdc\x1f\xb3\xd6\x47",
        "76.237.207.106:54293",
    ),
];

pub const BIN_SOCKADDR_LEN: usize = 19; //length of our serialized sockaddrs
pub const MAX_TUNNELS: usize = 4;
pub const CLOCK_TOLERANCE_SECS: i64 = 60 * 60 * 10; //allow up to 10 hours time drift for meet nodes

pub type ConvoId = [u8; 32];
pub type MSMRecv = Receiver<MeetStateMsg>;
pub type ChatSnd = Sender<ChatMsg>;
pub type Context = Arc<SfContext>;
pub type KeyString = arrayvec::ArrayString<[u8; 43]>;

pub type SfRes<T> = result::Result<T, SfErr>;
pub type Hop = Option<(Arc<Wad>, usize)>;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub struct Contact {
    pub spkey: SignPKey,
    pub name: String,
    pub verified: Option<u64>,
}

//A wad of connections
pub struct Wad {
    pub flag: Arc<AtomicBool>,
    pub hops: Vec<SocketAddr>,
    pub routes: [Mutex<Option<(Arc<AtomicBool>, Tube)>>; MAX_TUNNELS],
    pub control: Tube,
    pub sender: Tube,
    pub bpk: BoxPKey,
    pub seckey: SecKey,
    pub lastwad: Hop,
    pub started: Instant,
    pub rtt: f64,
    pub ctx: Context,
}
impl Wad {
    pub fn add_route(&self, next: &SocketAddr, wad: &Arc<Wad>, sl: bool) -> SfRes<(Tube, Hop)> {
        if self.hops.iter().find(|h| *h == next).is_some() {
            return Err(SfErr::BadHop);
        }
        debug!("Attempting to add route to wad {}", b64sk(&self.seckey));
        let (rkeys, rto) = (rand_keys(), (self.rtt * 2.0) as u64);
        for x in 1..self.routes.len() {
            if let Ok(mut route) = self.routes[x].try_lock() {
                if route.is_none() && self.flag.load(Relaxed) {
                    let addb = binary_bson(&sockaddr_to_bin(next)[..]);
                    let d = doc! {"fnc": "fwd", "addr": addb, "tnum": x as i32};
                    do_rpc_timeout(d, &self.control, &self.bpk, &rkeys, rto)?;
                    //if we get here it worked, now set up a tube pair for forwarding threads
                    let (mut ut, ut2) = Tube::pair(sl); //untagged
                    let utrcv = ut.split_off_recv()?;
                    let flg0 = Arc::new(AtomicBool::new(true));
                    let flg1 = Arc::clone(&flg0);
                    let sndr = self.sender.clone_sender()?;
                    let key1 = self.seckey.clone();
                    //Before we save and spawn threads, atomically check whether wad's shutting down
                    let r0lock = self.routes[0].lock()?; //We hold control (r0) lock to prevent race
                    if self.flag.load(Relaxed) == false {
                        return Err(SfErr::NoRoutesErr); //we're shutting down. Nope.
                    }
                    *route = Some((flg0, ut)); //While we hold control and route locks, save route
                    drop(r0lock); //now can drop the r0 lock
                    spawn_thread("chanwrap", move || tube_wrap(utrcv, sndr, &key1, flg1));
                    debug!("Added route {} to wad {}", x, b64sk(&self.seckey));
                    return Ok((Tube::tagger_wrap(ut2, x as u8)?, Some((Arc::clone(wad), x))));
                    //sender (tag wrapped sends)
                }
            }
        }
        Err(SfErr::NoRoutesErr)
    }
    pub fn close_idx(&self, idx: usize) {
        debug!("Closing wad forward {} {}", idx, b64sk(&self.seckey));
        if self.flag.load(Relaxed) == false {
            info!("Not closing wad fwd {} already flagged", idx);
            if idx == 0 {
                if let Ok(mut cr) = self.ctx.circuits.lock() {
                    cr.remove(&self.started); //Make sure we're removed
                }
            }
            return;
        }
        if let Ok(lck) = self.routes[idx].lock() {
            drop(lck);
            let clrpc = doc! {"fnc":"fwdclose", "c": idx as i32};
            let rto = (self.rtt * 2.0) as u64;
            do_rpc_timeout(clrpc, &self.control, &self.bpk, &rand_keys(), rto)
                .map(|_| ())
                .unwrap_or_else(|e| warn!("hop {} teardown err {}", idx, e));
            if let Ok(rt) = self.routes[idx].lock() {
                rt.as_ref().map(|w| w.0.store(false, Relaxed));
            }
        }
        if idx == 0 {
            self.lastwad.as_ref().map(|(w, idx)| w.close_idx(*idx)); //close outer hop
            debug!("Removing wad from circuits {}", b64sk(&self.seckey));
            if let Ok(mut cr) = self.ctx.circuits.lock() {
                cr.remove(&self.started); //we gone
            }
        } else if let Ok(r0lock) = self.routes[0].lock() {
            if self.routes[1..]
                .iter()
                .find(|l| //Are any routes alive? We hold control (r0) lock to prevent race
                //returns true if route is alive; try_lock returns Err or option set & flag true
                if let Ok(m) = l.try_lock(){
                    if let Some(op) = &*m { op.0.load(Relaxed) } else { false }
                } else { true }).is_none()
            //find returns None if all return false i.e. no routes left
            {
                debug!("last route done. Self-closing wad {}", b64sk(&self.seckey));
                self.flag.store(false, Relaxed); // other threads will eventually get the msg
                r0lock.as_ref().map(|w| w.0.store(false, Relaxed));
                drop(r0lock); //now we can release control lock
                let clrpc = doc! {"fnc":"fwdclose", "c": 0 as i32};
                let rto = (self.rtt * 2.0) as u64;
                do_rpc_timeout(clrpc, &self.control, &self.bpk, &rand_keys(), rto)
                    .map(|_| ())
                    .unwrap_or_else(|e| warn!("hop {} teardown err {}", 0, e));
            }
        }
        debug!("close_idx {} done wad {}", idx, b64sk(&self.seckey));
    }
}

//Basic info that's used by many threads
pub struct SfContext {
    pub keys: Keys,
    pub disco: Keys,
    pub meet_keys: Keys,
    pub meetstate_sender: Arc<Mutex<Sender<MeetStateMsg>>>,
    pub convos: Arc<Mutex<HashMap<ConvoId, Arc<Conn>>>>,
    pub ips: Tree,         //IpAddr -> SignPKey
    pub losses: Tree,      //SignPKey -> [first_fail, fail_count]
    pub nodes: Tree,       //SignPKey -> bsonized node
    pub cache: Arc<Db>,    //db_key -> blob
    pub lock: Mutex<bool>, //lock to hold when making atomic changes to multiple fields, e.g. ip/node
    pub hops: u8,
    pub runasnode: bool,
    pub addr: SocketAddr,
    pub proxy: Option<(u8, SocketAddr)>,
    pub tcp: AtomicBool,
    pub shutting_down: AtomicBool,
    pub workdir: PathBuf,
    pub meet_info: Mutex<MeetInfo>,
    pub synced_nodes: AtomicBool,
    pub netmon_thread: Mutex<Option<Thread>>,
    pub contacts: Mutex<BTreeMap<KeyString, Contact>>,
    pub circuits: Mutex<BTreeMap<Instant, Arc<Wad>>>,
}

impl SfContext {
    pub fn new(
        keys: Keys,
        mssnd: Sender<MeetStateMsg>,
        hops: u8,
        runnode: bool,
        addr: SocketAddr,
        workdir: PathBuf,
        mi: MeetInfo,
        proxy: Option<(u8, SocketAddr)>,
    ) -> Self {
        let meet = wr_crypto_blind_ed25519_secret_key(&keys.sign.sk, "meet");
        let meet_blind = secskey_to_keys(meet);
        let disc = wr_crypto_blind_ed25519_secret_key(&meet_blind.sign.sk, "disc");
        let disc_blind = secskey_to_keys(disc);
        //Allow a panic here; DB failure is genuinely fatal and should only happen at sf startup
        let db = sled::open(&workdir.join("db")).expect("DB failed!");
        db.set_merge_operator(add_merge);
        Self {
            keys: keys,
            disco: disc_blind,
            meet_keys: meet_blind,
            meetstate_sender: Arc::new(Mutex::new(mssnd)),
            convos: Arc::new(Mutex::new(HashMap::new())), // all convos, including groups
            ips: db.open_tree(b"ips").expect("Database failure!"),
            losses: db.open_tree(b"losses").expect("Database loss!"),
            nodes: db.open_tree(b"nodes").expect("Database fail!"),
            cache: Arc::new(db),
            lock: Mutex::new(true),
            hops: hops,
            runasnode: runnode,
            addr: addr,
            proxy: proxy,
            tcp: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            workdir: workdir,
            meet_info: Mutex::new(mi),
            synced_nodes: AtomicBool::new(true),
            netmon_thread: Mutex::new(None),
            contacts: Mutex::new(BTreeMap::new()),
            circuits: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn has_node(&self, spk: &SignPKey) -> bool {
        self.nodes.contains_key(&spk[..]).unwrap_or(false)
    }

    pub fn get_node(&self, spk: &SignPKey) -> SfRes<Node> {
        Node::load(&*self.nodes.get(&spk[..])?.ok_or_else(sfnone)?)
    }

    //Clears out node from the various tables
    pub fn del_node(&self, spk: &SignPKey) -> SfRes<()> {
        if let Some(nodeb) = self.nodes.remove(&spk)? {
            if !cfg!(debug_assertions) {
                let node = Node::load(&*nodeb)?;
                if let NodeAddr::Sockaddr(s) = node.address {
                    match s.ip() {
                        IpAddr::V4(four) => self.ips.remove(&four.octets()[..]),
                        IpAddr::V6(six) => self.ips.remove(&six.octets()[..8]),
                    }?;
                }
            }
        }
        self.losses.remove(&spk)?;
        Ok(())
    }

    pub fn save_node(&self, nod: Node) -> SfRes<()> {
        let nl = self.lock.lock();
        if let NodeAddr::Sockaddr(s) = nod.address {
            debug!("Saving node {}", s);
            let i = s.ip();
            if !cfg!(debug_assertions) {
                if let IpAddr::V4(f) = i {
                    if f.is_private() || f.is_link_local() || f.is_broadcast() {
                        return Err(SfErr::DisallowedAddr(i));
                    }
                }
                if i.is_loopback() || i.is_multicast() || i.is_unspecified() {
                    return Err(SfErr::DisallowedAddr(i));
                }
            }
            //Deduplicate; only allow 1 schadnfreude server per 1 IPv4 or /64 IPv6
            if let Some(spk) = match i {
                IpAddr::V4(four) => self.ips.insert(&four.octets()[..], &nod.key[..]),
                IpAddr::V6(six) => self.ips.insert(&six.octets()[..8], &nod.key[..]),
            }? {
                if !cfg!(debug_assertions) && &nod.key[..] != &spk[..] {
                    info!("{} is now {}", i, b64spk(&nod.key)); //Debug builds allow >1 node per IP
                    log_err!(self.del_node(array_ref![spk, 0, 32]), "delnode")
                }
            }
        }
        self.nodes.insert(&nod.key[..], nod.as_bytes())?; //looks good; add it
        drop(nl);
        Ok(())
    }

    pub fn set_node(&self, spk: &SignPKey, nod: Node) -> SfRes<()> {
        if let NodeAddr::Sockaddr(s) = nod.address {
            debug!("Setting node {}", s);
        }
        self.nodes.insert(&spk[..], nod.as_bytes())?;
        Ok(())
    }

    //get your real display name
    pub fn display_name(&self) -> String {
        let l = self.contacts.lock().ok();
        let res = l
            .and_then(|t| t.get(&b64spk(&self.keys.sign.pk)).map(|c| c.name.clone()))
            .unwrap_or_else(|| "".to_string());
        debug!("display_name for {} is {}", self.addr, &res);
        res
    }

    //Search nodes for the next known node >= the given node
    pub fn nextnode(&self, searchstart: &SignPKey) -> Option<PubNode> {
        let r = self.nodes.range(&searchstart[..]..);
        for node in r.filter_map(|v| v.ok().and_then(|vi| Node::load(&vi.1).ok())) {
            if node.key != self.keys.sign.pk && node.key != self.disco.sign.pk {
                //ignore our own keys
                if let NodeAddr::Sockaddr(s) = node.address {
                    trace!("nextnode found {}", s);
                    return Some(PubNode::new(node.key, node.bkey, s));
                }
            }
        }
        None
    }

    //Calls nextnode, and wraps if it fails
    pub fn nextnode_wrap(&self, searchstart: &SignPKey) -> Option<PubNode> {
        self.nextnode(searchstart)
            .or(self.nextnode(&[0; CRYPTO_BOX_PUBLICKEYBYTES]))
    }

    //Pick a "random" node. Rather than line all the nodes up and picking a random index (slow and
    //easier to game by owners of a /8 or /16) or picking a random key and taking the next-larger
    //(whichever node's just above a large IP allocation gap gets picked all the time), pick a rand
    //byte until we hit an IP with an address starting with that byte, then pick a random 2nd etc.
    //until you hit a complete match. This way, a /16 or /24 is as likely to be chosen as any other.
    pub fn rand_node(&self) -> Option<PubNode> {
        if cfg!(debug_assertions) {
            let mut k = wr_randomkey();
            let mut n = match self.nextnode_wrap(&k) {
                Some(n) => n,
                None => return None,
            };
            for _ in 1..1 + (k[8] % 4) {
                k = n.key; //skip the next X nodes
                increment_spkey(&mut k);
                n = match self.nextnode_wrap(&k) {
                    Some(n) => n,
                    None => return None,
                };
            }
            return Some(n); //all test nodes are localhost, so random key
        }
        self.rand_node_inner() //otherwise use the normal rand_node functionality
    }

    pub fn rand_node_inner(&self) -> Option<PubNode> {
        if self.ips.iter().nth(1).is_none() {
            warn!("No ips to randomize");
            return None; //no other IP's than us or just one node in the DB
        }
        let mut iterations = 0;
        let mut search_buffer = [0; 8];
        let mut cur = &mut search_buffer[0..0]; //current valid slice
        let mut valid_buffer = [0; 256];
        let mut rng = thread_rng();
        while cur.len() < 8 {
            //Let's random the next byte till we get a hit
            let offs = cur.len(); //offset of last byte added to search buffer
            cur = &mut search_buffer[..(offs + 1)];
            let mut valid_count = 0;
            let mut i = 0;
            while i < 256 {
                if cfg!(debug_assertions) {
                    iterations += 1;
                    trace!("rand_node offs {} iterations {} i {}", offs, iterations, i);
                }
                cur[offs] = i as u8;
                let qres = self.ips.range(&*cur..).next().and_then(|r| r.ok());
                if let Some(kv) = qres {
                    if cur[..offs] != kv.0[..offs] {
                        break; //and we're done
                    } else {
                        valid_buffer[valid_count] = kv.0[offs]; //add current hit valid
                        valid_count += 1;
                        i = kv.0[offs] as u16 + 1; //if we can skip a bunch of blank IP space, do so
                    }
                } else {
                    break; //nothing left
                }
            }
            cur[offs] = valid_buffer[rng.gen_range(0, valid_count)]; //pick a valid next byte
            if cur.len() == 4 || cur.len() == 8 {
                //if it's in IP's and we can query nodes
                let qres = self.ips.get(&cur).ok().and_then(|o| o);
                let nq = qres.and_then(|k| self.nodes.get(&*k).ok());
                //if it was in nodes and a valid node with sockaddr (should always be true)
                if let Some(node) = nq.and_then(|no| no).and_then(|n| Node::load(&n).ok()) {
                    if let NodeAddr::Sockaddr(sa) = node.address {
                        debug!("rand_node returning {} {}", sa, b64spk(&node.key));
                        return Some(PubNode::new(node.key, node.bkey, sa));
                    }
                }
            }
        }
        info!("rand_node failed?!");
        None
    }

    //Rand node that isn't in losses or a set of exclusions, block until available.
    pub fn rand_other_node(&self, not: &HashSet<SocketAddr>) -> PubNode {
        let mut try_num = 0;
        loop {
            if let Some(n) = self.rand_node() {
                if !self.losses.contains_key(&n.key[..]).unwrap_or(false)
                    && !not.contains(&n.address)
                {
                    trace!("rand_other_node returning {}", n.address);
                    return n;
                } else if self.losses.contains_key(&n.key[..]).unwrap_or(false) {
                    debug!("Woulda chosen {} but marked as loss", n.address);
                }
                try_num += 1;
                if try_num % 16 != 0 {
                    continue; //if we have nodes, insta-retry 16 times before sleeping/requesting
                }
            } else {
                error!("No nodes known?");
            }
            if let Ok(thopt) = self.netmon_thread.lock() {
                if let Some(th) = (*thopt).as_ref() {
                    th.unpark(); //If we couldn't find a good node, wake up netmon to get us more
                }
            }
            info!("node miss {} {}/{}", try_num, not.len(), self.nodes.len());
            thread::sleep(Duration::from_secs(1))
        }
    }
}

pub struct MeetStateMsg {
    pub opening: bool,
    pub idkeys: Keys,
    pub key: SecKey,
    pub meet_host: PubNode,
    pub backups: Vec<PubNode>,
}

#[derive(Clone)]
pub struct MeetAddr {
    pub serialized: Vec<u8>,
    pub meet_host: SignPKey,
    pub released: SystemTime,
}

//This is a node address. Type should match an available transport
#[derive(Clone)]
pub enum NodeAddr {
    // addrtype 1 = UDP IP:port pair, 2 = meet key
    Sockaddr(SocketAddr),
    Meet(MeetAddr),
}

pub fn sockaddr_to_bin(addr: &SocketAddr) -> [u8; BIN_SOCKADDR_LEN] {
    let mut ipbytes = [0; BIN_SOCKADDR_LEN];
    match addr.ip() {
        IpAddr::V4(four) => {
            ipbytes[0] = 4;
            (&mut ipbytes[1..5]).copy_from_slice(&four.octets()[..]);
        }
        IpAddr::V6(six) => {
            ipbytes[0] = 6;
            (&mut ipbytes[1..17]).copy_from_slice(&six.octets()[..]);
        }
    }
    ipbytes[17] = addr.port() as u8;
    ipbytes[18] = (addr.port() >> 8) as u8;
    ipbytes
}

pub fn debin_addr(b: &[u8; BIN_SOCKADDR_LEN]) -> SocketAddr {
    let port = ((b[18] as u16) << 8) | b[17] as u16;
    if b[0] == 4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b[1], b[2], b[3], b[4])), port)
    } else {
        let s = (b[1] as u16) << 8 | b[2] as u16;
        let t = (b[3] as u16) << 8 | b[4] as u16;
        let u = (b[5] as u16) << 8 | b[6] as u16;
        let v = (b[7] as u16) << 8 | b[8] as u16;
        let w = (b[9] as u16) << 8 | b[10] as u16;
        let x = (b[11] as u16) << 8 | b[12] as u16;
        let y = (b[13] as u16) << 8 | b[14] as u16;
        let z = (b[15] as u16) << 8 | b[16] as u16;
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(s, t, u, v, w, x, y, z)), port)
    }
}

impl NodeAddr {
    //Serialize
    pub fn deparse(&self) -> (i32, Vec<u8>) {
        match self {
            NodeAddr::Sockaddr(s) => (1, sockaddr_to_bin(s)[..].to_vec()),
            NodeAddr::Meet(m) => (2, m.serialized.clone()),
        }
    }
}

//This is a node as info is listed publicly
#[derive(Clone)]
pub struct Node {
    pub key: SignPKey,
    pub bkey: BoxPKey,
    pub address: NodeAddr,
}
impl Node {
    pub fn load(bin: &[u8]) -> SfRes<Self> {
        let ndoc = decode_document(&mut Cursor::new(bin))?;
        let k = leneq(ndoc.get_binary_generic("k")?, CRYPTO_SIGN_PUBLICKEYBYTES)?;
        let b = leneq(ndoc.get_binary_generic("b")?, CRYPTO_BOX_PUBLICKEYBYTES)?;
        let atbin = ndoc.get_i32("t")?;
        let addr = ndoc.get_binary_generic("a")?;
        let nkey = copy_to_array(k);
        Ok(Self {
            key: nkey,
            bkey: copy_to_array(b),
            address: parse_nodeaddr(atbin, addr, &nkey)?,
        })
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let (addrtype, addr) = self.address.deparse();
        bdoc_to_u8vec(&doc! {
            "k": binary_bson(&self.key),
            "b": binary_bson(&self.bkey),
            "t": addrtype,
            "a": binary_bson(&addr),
        })
    }
}
#[derive(Copy, Clone)]
pub struct PubNode {
    pub key: SignPKey,
    pub bkey: BoxPKey,
    pub address: SocketAddr,
}
impl PubNode {
    pub fn new(key: SignPKey, bkey: BoxPKey, address: SocketAddr) -> Self {
        Self {
            key: key,
            bkey: bkey,
            address: address,
        }
    }
}

pub fn leneq(bin: &[u8], len: usize) -> SfRes<&[u8]> {
    if bin.len() != len {
        return Err(SfErr::BadLen);
    }
    Ok(bin)
}
pub fn lenveq(bin: Vec<u8>, len: usize) -> SfRes<Vec<u8>> {
    leneq(&bin, len)?;
    Ok(bin)
}

// deserialize a systemtime/seconds
pub fn bin_seconds_as_systemtime(rbytes: &[u8]) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::new(lbytes_to_u64(rbytes), 0)
}
// serialize a u64
pub fn u64_bytes(val: u64) -> [u8; 8] {
    val.to_ne_bytes()
}

//merge operator for a sled DB that just adds the new value to the old value
pub fn add_merge(_key: &[u8], old_value: Option<&[u8]>, newv: &[u8]) -> Option<Vec<u8>> {
    let old = old_value.map(|ov| bytes_to_u64(ov)).unwrap_or(0) as i64;
    Some((&u64_bytes((bytes_to_u64(newv) as i64 + old) as u64)[..]).to_vec())
}

pub const DBK_LEN: usize = 32 + 4 + 8;
//Makes a binary path to use as a DB key as an array (no allocation)
pub fn db_key(convoid: &ConvoId, id: i64, suffix: &[u8; 4]) -> [u8; DBK_LEN] {
    let mut res = [0; 32 + 4 + 8];
    (&mut res[0..32]).copy_from_slice(&convoid[..]);
    (&mut res[32..(32 + 4)]).copy_from_slice(&suffix[..]);
    (&mut res[(32 + 4)..]).copy_from_slice(&(id as u64).to_be_bytes()[..]);
    res
}

pub fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

//serialize a systemtime with second resolution. Unwrap since this really shouldn't ever die
pub fn now_as_bin_seconds() -> [u8; 8] {
    let st = SystemTime::UNIX_EPOCH.elapsed().unwrap();
    st.as_secs().to_le_bytes()
}

pub fn secs(num_secs: u64) -> Duration {
    Duration::new(num_secs, 0)
}

//serialize a systemtime with microsecond resolution. Unwrap since this really shouldn't ever die
//64-bit number will wrap > 500,000 years after 1970, so I think we're OK.
pub fn now_as_bin_microseconds() -> [u8; 8] {
    let d = SystemTime::UNIX_EPOCH.elapsed().unwrap();
    (d.as_secs() * 1_000_000 + d.subsec_micros() as u64).to_be_bytes()
}

pub fn b64spk(pk: &SignPKey) -> KeyString {
    unsafe {
        let mut x = std::mem::MaybeUninit::<[u8; 43]>::uninit();
        let mut_slice_ref = &mut (*x.as_mut_ptr())[..];
        base64::encode_config_slice(&pk[..], base64::URL_SAFE_NO_PAD, mut_slice_ref);
        use std::str::from_utf8_unchecked;
        KeyString::from(from_utf8_unchecked(&x.assume_init()[..])).unwrap()
    }
}

pub fn spawn_thread<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(name: &str, f: F) {
    match Builder::new().name(name.to_string()).spawn(move || f()) {
        Ok(j) => debug!("spawn {:08X} {}", hash(&j.thread().id()) as u32, name),
        Err(e) => error!("spawn_thread failed {}", e),
    }
}

//For when you want to display a secret key, but not reveal all the info in the logs
pub fn b64sk(k: &SecKey) -> String {
    encode_config(&wr_crypto_hash_sha256(&k[..])[0..5], URL_SAFE_NO_PAD)
}

//Sign a message that people who want to talk to you should contact the node with the given pubkey
pub fn sign_meet_nodeaddr_bin(mykeys: &Keys, meethost_pkey: &SignPKey) -> Vec<u8> {
    let mut verified_addrb = [0; CRYPTO_BOX_PUBLICKEYBYTES + 8];
    (&mut verified_addrb[..8]).copy_from_slice(&now_as_bin_seconds()[..]);
    (&mut verified_addrb[8..]).copy_from_slice(&meethost_pkey[..]);
    let res = wr_crypto_sign(&verified_addrb, &mykeys.sign.sk);
    res
}

//Parse and validate a binary meet signed address
pub fn parse_binaddr(binary_address: &[u8], k: &SignPKey) -> SfRes<NodeAddr> {
    let sig = wr_crypto_sign_open_inplace(binary_address, k)?;
    let b = leneq(sig, CRYPTO_BOX_PUBLICKEYBYTES + 8)?;
    Ok(NodeAddr::Meet(MeetAddr {
        serialized: binary_address.to_vec(),
        meet_host: copy_to_array(&b[8..(8 + CRYPTO_BOX_PUBLICKEYBYTES)]),
        released: bin_seconds_as_systemtime(&b[0..8]),
    }))
}

//Parses and validates a node address for a given key
pub fn parse_nodeaddr(addrtype: i32, addrs: &[u8], pkey: &SignPKey) -> SfRes<NodeAddr> {
    if addrtype == 1 && addrs.len() == BIN_SOCKADDR_LEN {
        let sa = debin_addr(array_ref![addrs, 0, BIN_SOCKADDR_LEN]);
        Ok(NodeAddr::Sockaddr(sa))
    } else if addrtype == 2 {
        parse_binaddr(addrs, pkey)
    } else {
        warn!("Invalid addrtype {} len {}", addrtype, addrs.len());
        Err(SfErr::InvalidOp)
    }
}

//same but for doc
pub fn bdoc_to_u8vec(dobj: &Document) -> Vec<u8> {
    let mut out = Cursor::new(Vec::with_capacity(dobj.len() * 48)); //just guess at size
    log_err!(bson::encode_document(&mut out, dobj.iter()), "bdoc err");
    out.into_inner()
}

//Close a connection in a new thread
pub fn close_wad_conn(hop: Hop) -> Option<JoinHandle<()>> {
    hop.and_then(|(wad, idx)| {
        Builder::new()
            .name("hopteard".to_string())
            .spawn(move || wad.close_idx(idx))
            .map_err(|e| error!("{}", e))
            .map(|join| {
                debug!("spawn {:08X} hopteard", hash(&join.thread().id()) as u32);
                join
            })
            .ok()
    })
}

//Thin wrapper around hop_to that also calculates and caches RTT
pub fn conn_hops(addr: &SocketAddr, ctx: &Context, mbox: &BoxPKey) -> SfRes<(Tube, Hop, f64)> {
    let nlist = doc! {"fnc": "nodelist", "ge": binary_bson(&wr_randomkey()), "np": 0i32};
    let (cli, hop) = hop_to(addr, ctx, ctx.hops, 0);
    let wadid = hop.as_ref().map(|h| be_to_i64(&h.0.seckey[..]));
    let dbk = db_key(mbox, wadid.unwrap_or(0), b"rttc");
    trace!("looking for db key for {}", b64spk(mbox));
    if let Ok(Some(rttval)) = ctx.cache.get(&dbk[..]) {
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        if now > bytes_to_u64(&rttval[..8]) + 60 * 60 * 10 {
            log_err!(ctx.cache.remove(&dbk[..]), "cache rttc del");
        } else {
            return Ok((cli, hop, f64::from_bits(bytes_to_u64(&rttval[8..16]))));
        }
    }
    let res = match do_rpc(nlist, &cli, mbox, &rand_keys()) {
        Ok(r) => r,
        Err(e) => {
            close_wad_conn(hop); //close out the circuit on failure
            return Err(e);
        }
    };
    let mut cacheval = [0; 16];
    (&mut cacheval[..8]).copy_from_slice(&now_as_bin_seconds()[..]);
    (&mut cacheval[8..]).copy_from_slice(&u64_bytes(res.1.to_bits())[..]);
    log_err!(ctx.cache.insert(&dbk[..], &cacheval[..]), "cache set");
    Ok((cli, hop, res.1))
}

//blocking version
pub fn conn_hops_block(addr: &SocketAddr, ctx: &Context, mbox: &BoxPKey) -> (Tube, Hop, f64) {
    loop {
        match conn_hops(addr, ctx, mbox) {
            Ok(r) => return r,
            Err(e) => info!("conn_hops to {} fail {}", addr, e),
        }
        thread::sleep(Duration::from_secs(1));
    }
}

//rand_other_node but also make a hopped connection to them, verify they're good and return the conn
pub fn rand_other_conn(c: &Context, addrs: &HashSet<SocketAddr>) -> (Tube, Hop, f64, PubNode) {
    loop {
        let rand_node = c.rand_other_node(addrs); //try again until you get one that works
        let rand_conn = conn_hops(&rand_node.address, c, &rand_node.bkey); //connect to the random node
        if let Ok(rc) = rand_conn {
            return (rc.0, rc.1, rc.2, rand_node);
        }
        info!("rand_other_conn retrying");
    }
}

//Create a tunneled client UDP socket connecting to a given address through random node(s)
//First node may end up being TCP
pub fn hop_to(addr: &SocketAddr, c: &Context, nhops: u8, fails: usize) -> (Tube, Hop) {
    let mut hops = Vec::with_capacity(nhops as usize);
    if nhops == 0 {
        let tub = if let Some(proxy) = c.proxy.as_ref() {
            Tube::socks_connect(addr, proxy)
        } else {
            Tube::udp_connect(addr)
        };
        if let Ok(tube) = tub {
            return (tube, None); //no hops
        } else {
            error!("Couldn't connect to {}! Sleeping and retrying.", addr);
            thread::sleep(Duration::from_secs(1));
            return hop_to(addr, c, nhops, fails + 1); //tail recurse
        }
    }
    //can we use an existing circuit? Iterate from most recently constructed back up to an hour
    let mut current_range = ..Instant::now();
    while let Ok(circuits) = c.circuits.lock() {
        if let Some((k, v)) = circuits.range(current_range).rev().next() {
            if k.elapsed() > secs(3600) {
                break; //Not recent enough - short circuit exit
            }
            current_range = ..k.clone(); //next iteration start after this one
            let w = Arc::clone(v); //copy the arc so we can use it
            drop(circuits); //drop our lock before the part where we might have to wait for an RPC
            if let Ok(circ) = w.add_route(addr, &w, c.tcp.load(Relaxed)) {
                debug!("Good reusable circuit!?");
                return circ;
            }
        } else {
            break; //No circuits left
        }
    }
    debug!("creating {} hop conn to {} try {}", nhops, addr, fails); //Make new one
    let mut addrs = HashSet::new();
    addrs.insert(addr.clone()); //Pick random nodes for the nhops, different from each other
    while hops.len() < nhops as usize {
        let ron = c.rand_other_node(&addrs);
        addrs.insert(ron.address.clone());
        trace!("Queuing add hop {} to {}", b64spk(&ron.key), addr);
        hops.push((ron.address, ron.bkey));
    }
    if fails > 4 {
        let tcp = c.tcp.load(Relaxed);
        c.tcp.store(!tcp, Relaxed); // try flipping protocols.
    }
    let tube_res = if let Some(proxy) = c.proxy.as_ref() {
        Tube::socks_connect(&hops[0].0, proxy)
    } else if c.tcp.load(Relaxed) {
        Tube::tcp_connect(&hops[0].0).or_else(|_| Tube::udp_connect(&hops[0].0))
    } else {
        Tube::udp_connect(&hops[0].0)
    };
    let mut cli = if let Ok(tube) = tube_res {
        tube // to start the first one
    } else {
        error!("Couldn't connect to {}! Retrying.", &hops[0].0);
        thread::sleep(Duration::from_secs(1));
        return hop_to(addr, c, nhops, fails + 1); //tail recurse
    };
    let inst = Instant::now(); //when we start the wad
    let mut retwad = None;
    for i in 0..nhops {
        trace!("Setting up hop {}", i);
        let next_addr_bin = if i == nhops - 1 {
            addr.clone() //final address
        } else {
            hops[i as usize + 1].0.clone() //next hop address
        };
        let ref hop = hops[i as usize]; //get info
        let key: SecKey = wr_randomkey();
        debug!("hop {} {} to {} c {}", i, hop.0, addr, cli);
        let addb = binary_bson(&sockaddr_to_bin(&next_addr_bin)[..]);
        let d = doc! {"fnc": "fwd", "key": binary_bson(&key[..]), "addr": addb};
        let f = do_rpc_timeout(d, &cli, &hop.1, &rand_keys(), 1000).and_then(|(_, rtt)| {
            //if we get here it worked, now set up a tube pair for forwarding threads
            let (mut s, mut s2) = Tube::pair(c.tcp.load(Relaxed)); //s2 <==> s
            let key1 = key.clone();
            let (clisend, s2rcv) = (cli.clone_sender()?, s2.split_off_recv()?); //for 1st thread
            let fl1 = Arc::new(AtomicBool::new(true)); //Flag for the whole wad
            let (fl2, fl3) = (Arc::clone(&fl1), Arc::clone(&fl1)); //flag refs
            spawn_thread("hop_wrap", move || tube_wrap(s2rcv, clisend, &key1, fl1));
            let clr = cli.split_off_recv()?; //the tube that receives data to fwd
            spawn_thread("hopunwrp", move || tube_unwrap(clr, s2, &key, fl2, true));
            let (mut ut, ut2) = Tube::pair(c.tcp.load(Relaxed)); //untagged
            let utrcv = ut.split_off_recv()?;
            let scl = s.split_off_recv()?;
            let utfl = Arc::new(AtomicBool::new(true)); //Flag for this connection (untagged)
            let utfl2 = Arc::clone(&utfl);
            let ssnd_clone = s.clone_sender()?;
            spawn_thread("dumb_fwd", move || dumb_fwd(utrcv, ssnd_clone, utfl2, true));
            let (mut ctrl, ctrl2) = Tube::pair(c.tcp.load(Relaxed)); //untagged control
            let ctrlrcv = ctrl.split_off_recv()?;
            let fl4 = Arc::clone(&fl3);
            spawn_thread("dumbcfwd", move || dumb_fwd(ctrlrcv, s, fl4, false)); //ctrl = no timeout
            let wad = Arc::new(Wad {
                flag: Arc::clone(&fl3),
                hops: hops[..i as usize].iter().map(|h| h.0).collect(),
                routes: [
                    Mutex::new(Some((fl3, ctrl))), //tag 0 - control for this wad
                    Mutex::new(Some((utfl, ut))),  //tag 1 - tube requested to real destination
                    Mutex::new(None),
                    Mutex::new(None),
                ],
                control: Tube::tagger_wrap(ctrl2, 0)?, //control channel has tag 0
                sender: cli,
                seckey: key.clone(),
                bpk: hop.1.clone(),
                lastwad: retwad.take(), //multihop if implemented
                started: inst.clone(),
                rtt: rtt,
                ctx: Arc::clone(c),
            });
            let tagwad = Arc::clone(&wad);
            spawn_thread("tagroutr", move || tag_route(scl, tagwad));
            Ok((Tube::tagger_wrap(ut2, 1)?, wad, 1)) //new fwds are tag 1
        });
        if let Err(e) = f.as_ref() {
            error!("Tunnel creation failed {} retrying...", e); //throw it out and try again
            return hop_to(addr, c, nhops, fails + 1); //try again (tail recurse)
        }
        let (c2, wad2, num2) = f.unwrap(); //not error, it's good.
        cli = c2;
        retwad = Some((wad2, num2));
    }
    if let Some(rwad) = retwad.as_ref() {
        if let Ok(mut cr) = c.circuits.lock() {
            cr.insert(inst, Arc::clone(&rwad.0)); //cache circuit so we can re-use open wad tags
        }
    }
    debug!("hop_to {} returning new connection", addr);
    (cli, retwad)
}

pub fn dumb_fwd(src: Tube, dst: Tube, flag: Arc<AtomicBool>, timeout: bool) {
    let mut last_good = Instant::now();
    while flag.load(Relaxed) && (!timeout || last_good.elapsed() < secs(300)) {
        if let Err(e) = src.recv_vec().and_then(|rvec| {
            if timeout {
                last_good = Instant::now();
            }
            dst.send_vec(rvec)
        }) {
            if fwd_err_fatal(e, &flag, &[0; 32]) {
                break;
            }
        }
    }
    debug!("dumb fwd closed fl {}", flag.load(Relaxed));
}

//Receives on one tube, reading tag, and directing
pub fn tag_route(src: Tube, wad: Arc<Wad>) {
    let mut last_good = Instant::now();
    while wad.flag.load(Relaxed) && last_good.elapsed() < secs(300) {
        if let Err(e) = src.recv_vec().and_then(|mut rvec| {
            last_good = Instant::now();
            if rvec.len() > 1 && rvec[0] < wad.routes.len() as u8 {
                let tag = rvec.remove(0) as usize;
                trace!("tag_route len {} asking for {}", rvec.len(), tag);
                let route = wad.routes[tag].lock()?;
                if let Some(rte) = route.as_ref() {
                    rte.1.send_vec(rvec)
                } else {
                    debug!("tag_route bad tag {}", tag);
                    Err(SfErr::InvalidOp)
                }
            } else {
                debug!("bad tagtube? rveclen {}", rvec.len());
                Err(SfErr::InvalidOp)
            }
        }) {
            if fwd_err_fatal(e, &wad.flag, &[0; 32]) {
                break;
            }
        }
    }
    debug!("tag cl {} k {}", wad.flag.load(Relaxed), b64sk(&wad.seckey));
}

//verify a remote address
pub fn verify(c: &Context, spk: &SignPKey, bk: &BoxPKey, sa: &SocketAddr, direct: bool) -> bool {
    let (cli, wad) = hop_to(sa, c, if direct { 0 } else { c.hops }, 0);
    let params = doc! {"fnc":"nodelist", "ge":binary_bson(&spk[..]), "np": 0i32};
    let res = do_rpc(params, &cli, &bk, &rand_keys());
    if !direct {
        close_wad_conn(wad);
    }
    if res.is_ok() {
        let new_node = Node {
            key: spk.clone(),
            bkey: bk.clone(),
            address: NodeAddr::Sockaddr(sa.clone()),
        };
        info!("node at {} is alive!", sa); // yay! it works
        log_err!(c.save_node(new_node), "Couldn't save node");
    }
    res.is_ok()
}

//Runs a nodelist query against the given system, returns the last new node to be added if any were
//as well as whether the query was successful
pub fn query_nodelist(
    node: &PubNode,
    pk: &SignPKey,
    ctx: &Context,
    direct: bool,
    verify_save: bool,
) -> (Option<SignPKey>, bool) {
    let mut res = None; //if any new nodes show up
    let (cli, wad) = hop_to(&node.address, ctx, if direct { 0 } else { ctx.hops }, 0);
    let d = if ctx.runasnode && direct {
        doc! {"fnc":"nodelist", "ge":binary_bson(&pk[..]), "np": ctx.addr.port() as i32}
    } else {
        doc! {"fnc":"nodelist", "ge":binary_bson(&pk[..]), "np": 0i32} //not advertising self
    };
    let mut query_success = false;
    let r = do_rpc(d, &cli, &node.bkey, &ctx.keys);
    r.and_then(|(doc, _rto)| {
        if ctx.get_node(&node.key).is_err() {
            // if we don't already have it, then save it
            let new_node = Node {
                key: node.key.clone(),
                bkey: node.bkey.clone(),
                address: NodeAddr::Sockaddr(node.address.clone()),
            };
            log_err!(ctx.save_node(new_node), "Couldn't save node"); //this works so it's good
        }
        let nds = doc.get_array("nodes")?;
        query_success = true;
        for ndb in nds {
            let nd = if let Some(nd) = ndb.as_document() {
                nd
            } else {
                warn!("bad document in nodelist resp");
                continue;
            };
            let kres = nd.get_binary_generic("k").map_err(|_| SfErr::NoneErr);
            kres.and_then(|kb| {
                if kb.len() != CRYPTO_BOX_PUBLICKEYBYTES {
                    return Err(SfErr::BadLen);
                }
                let k = copy_to_array(&kb[..]);
                let k_box = wr_crypto_sign_pk_to_box(&k);
                let atype = nd.get_i32("t")?;
                let addrss = nd.get_binary_generic("a")?;
                let na = parse_nodeaddr(atype, addrss, &k)?; //get the address if valid
                let new_node = Node {
                    key: k.clone(),
                    bkey: k_box.clone(),
                    address: na.clone(),
                };
                if match &na {
                    NodeAddr::Sockaddr(sa) => {
                        if ctx.get_node(&k).is_ok() {
                            return Ok(()); // if we already have it, then ok
                        }
                        if verify_save && !verify(ctx, &k, &k_box, &sa, direct) {
                            info!("node addr {} ping FAILED", sa);
                            false
                        } else {
                            let new_node = Node {
                                key: k.clone(),
                                bkey: k_box,
                                address: NodeAddr::Sockaddr(sa.clone()),
                            };
                            if let Err(e) = ctx.save_node(new_node) {
                                warn!("Couldn't save node {}", e);
                                false
                            } else {
                                true
                            }
                        }
                    }
                    NodeAddr::Meet(m) => {
                        if let Ok(nd) = ctx.get_node(&k) {
                            match nd.address {
                                NodeAddr::Sockaddr(ref _old_addr) => false, //don't overwrite
                                NodeAddr::Meet(ref old_m) => {
                                    if m.released > old_m.released {
                                        log_err!(ctx.save_node(new_node), "Couldn't save node");
                                        true //it's newer
                                    } else {
                                        false //don't update newer record with older one
                                    }
                                }
                            }
                        } else {
                            log_err!(ctx.save_node(new_node), "Couldn't save node");
                            true //no existing one? Insert new
                        }
                    }
                } {
                    res = Some(k);
                }
                Ok(())
            })
            .unwrap_or_else(|e| warn!("ERROR in nodelist parsing node response: {}", e));
        }
        Ok(())
    })
    .unwrap_or_else(|e| warn!("{} unreachable: {}", node.address, e));
    close_wad_conn(wad);
    debug!("query_nodelist added? {}", res.is_some());
    (res, query_success)
}

pub fn rand_i64() -> i64 {
    i64::from_ne_bytes(rand_array())
}

//pulls a full seed sync. Returns whether successful, whether it learned new nodes or not.
pub fn sync_from_seed(context: &Context, seed: &PubNode) -> bool {
    let mut start = [0; 32]; //start pulling from 0 on first run
    loop {
        let (new_node_option, worked) = query_nodelist(seed, &start, context, true, false);
        if let Some(lastnode) = new_node_option {
            start = lastnode; //new highest key to grab the next chunk
            debug!("loading nodes... {:.1}%", start[0] as f32 / 256.0 * 100.0);
        } else {
            return worked;
        }
    }
}

//Network tracking; occasionally poll network servers for updates, self-announce if node
pub fn run_netmonitor(ctxt: &Context, nsender: ChatSnd) {
    if !ctxt.synced_nodes.load(Relaxed) || ctxt.nodes.iter().nth(NETWORK_SEEDS.len()).is_none() {
        info!("Schadnfreude first run; loading nodelist from seed nodes");
        if cfg!(not(test)) {
            for (key, addrs) in NETWORK_SEEDS {
                let node = Node {
                    key: key.clone(),
                    bkey: wr_crypto_sign_pk_to_box(&key),
                    address: NodeAddr::Sockaddr(addrs.parse().unwrap()), //seeds should never fail
                };
                log_err!(ctxt.save_node(node), "Cannot save seed node");
            }
            //Now do the first run full sync on a random seed. Keep trying until it works
            loop {
                let (ref seed, ref addr) =
                    NETWORK_SEEDS[(rand_i64() as usize) % NETWORK_SEEDS.len()];
                let tcp = ctxt.tcp.load(Relaxed);
                let mut synced = ctxt.nextnode(seed).map(|node| sync_from_seed(ctxt, &node)); //sync
                if !synced.unwrap_or(false) {
                    warn!("Couldn't connect to seed {} tcp {}", addr, tcp);
                    ctxt.tcp.store(!tcp, Relaxed);
                    synced = ctxt.nextnode(seed).map(|node| sync_from_seed(ctxt, &node));
                    //sync again
                }
                if synced.unwrap_or(false) {
                    break; // it apparently worked
                }
                warn!("Couldn't connect to seed {} tcp {}", addr, !tcp);
            }
            info!("Saving seeded nodes");
            log_err!(ctxt.nodes.flush(), "Couldn't save nodes");
        }
    }
    //If we're a client, sfcontext has no meet node, but our meet node's listed, update context
    if !ctxt.runasnode {
        let mut mi = ctxt.meet_info.lock().unwrap();
        if let MeetInfo::Receiver(ref mut _mr) = *mi {
            debug!("Trying to pick a meet node");
            let mut new_mi_opt = None;
            let mut nadd = [0; 32];
            if let Ok(nod) = ctxt.get_node(&disc_blind(&ctxt.keys.sign.pk)) {
                if let NodeAddr::Meet(nm) = &nod.address {
                    log_err!(meet_node(&nm.meet_host, ctxt), "Found meet key not node");
                    nadd = nm.meet_host.clone();
                    new_mi_opt = Some(MeetInfo::Address(nadd.clone()));
                }
            }
            //If we still haven't found a node, pick a random one
            if let None = new_mi_opt {
                if let Some(rn) = ctxt.rand_node() {
                    //rand_node should return a node unless the world is destroyed
                    nadd = rn.key.clone();
                    new_mi_opt = Some(MeetInfo::Address(rn.key.clone()));
                }
            }
            if let Some(mut new_mi) = new_mi_opt {
                mem::swap(&mut *mi, &mut new_mi); //after swap, new_mi will be the receiver
                if let MeetInfo::Receiver(mi_recv) = new_mi {
                    info!("Launching discovered/picked meetmon for {}", b64spk(&nadd));
                    drop(mi);
                    launch_meetmon(Arc::clone(ctxt), &nsender, mi_recv);
                    log_err!(fs::write(&ctxt.workdir.join("my_meet.bin"), &nadd[..]), "");
                }
            } else {
                error!("Couldn't pick a meet node");
            }
        } else {
            debug!("No need to pick a meet node");
        }
    }
    ctxt.synced_nodes.store(true, Relaxed);
    if let Ok(mut th) = ctxt.netmon_thread.lock() {
        *th = Some(thread::current()); //Store yourself so other threads can wake you up if needed
    }
    let mut last_run_success = false;
    loop {
        debug!("Netmonitor querying nodelist..."); //query randomly
        if let Some(nod) = ctxt.rand_node() {
            if query_nodelist(&nod, &wr_randomkey(), ctxt, true, true).1 {
                last_run_success = true;
                log_err!(ctxt.losses.remove(&nod.key[..]), "DB fail"); //forgive & forget
            } else if last_run_success {
                debug!("Netmonitor initial fail for {}", nod.address);
                //see if we can hit another box. If we had a success + fail + success, then it's bad
                if let Some(tmpnode) = ctxt.rand_node() {
                    if query_nodelist(&tmpnode, &wr_randomkey(), ctxt, true, true).1 {
                        info!("Node at {} failed live check", nod.address);
                        //We did have a success + fail + success
                        if let Ok(l) = ctxt.losses.get(&nod.key[..]) {
                            let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
                            let (first_fail, fail_count) = l
                                .and_then(|dat| {
                                    let dop = leneq(&dat, 16).ok();
                                    dop.map(|b| (bytes_to_u64(&b[..8]), bytes_to_u64(&b[8..]) + 1))
                                })
                                .unwrap_or((now, 1));
                            //Is it terminally bad? (3+ fails over 2+hrs) if so, drop it entirely
                            if now - first_fail > 60 * 60 * 2 && fail_count > 2 {
                                info!("Node at {} being removed", nod.address); //query randomly
                                ctxt.del_node(&nod.key)
                                    .unwrap_or_else(|e| error!("DB {}", e))
                            } else {
                                let mut together = [0; 16]; //save new fail info
                                (&mut together[..8]).copy_from_slice(&u64_bytes(first_fail)[..]);
                                (&mut together[8..]).copy_from_slice(&u64_bytes(fail_count)[..]);
                                let r = ctxt.losses.insert(&nod.key[..], &together[..]);
                                r.map(|_| ()).unwrap_or_else(|e| error!("DB error {}", e))
                            }
                        }
                    } else {
                        debug!("Failed communicating with multiple nodes - are we offline?");
                        last_run_success = false;
                    }
                }
            }
        }
        thread::park_timeout(Duration::from_secs(10)); //Can be woken up by a thread in need
    }
}

//Generate random client keys for one-off requests
pub fn rand_keys() -> Keys {
    let skeys = wr_crypto_sign_keypair();
    Keys {
        bx: BoxKeys {
            pk: wr_crypto_sign_pk_to_box(&skeys.pk),
            sk: wr_crypto_sign_sk_to_box(&skeys.sk),
        },
        sign: skeys,
    }
}

//Unidirectional forward thread from plaintext tube encrypting to ciphertext tube
pub fn tube_wrap(src: Tube, dst: Tube, key: &SecKey, flag: Arc<AtomicBool>) {
    debug!("tw recv on {} send from {} key {}", src, dst, b64sk(key));
    log_err!(src.set_timeout(secs(1)), "set_timeout failed"); //Relax timeout a bit from default
    let mut encbuf = Vec::with_capacity(1472); // UDP MSS
    encbuf.extend_from_slice(&wr_randomkey()[..]); //random nonce at start
    let mut last_good = Instant::now();
    while flag.load(Relaxed) && last_good.elapsed() < secs(300) {
        if let Err(e) = src.recv_vec().and_then(|rvec| {
            last_good = Instant::now();
            let enclen = rvec.len() + CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES;
            if encbuf.len() < enclen {
                encbuf.resize(enclen, 0); //make sure there's enough room
            }
            let (nonsl, ctbuf) = (&mut encbuf).split_at_mut(CRYPTO_BOX_NONCEBYTES);
            let newnonce = (lbytes_to_u64(&nonsl) + 1).to_le_bytes(); //increment nonce
            (&mut nonsl[0..8]).copy_from_slice(&newnonce); //save new nonce
            let nonce = array_ref![nonsl, 0, CRYPTO_BOX_NONCEBYTES];
            wr_crypto_secretbox_inplace_n(&rvec, ctbuf, nonce, &key); //do encryption
            trace!("tw {} {} d {} k {}", rvec.len(), enclen, dst, b64sk(key));
            dst.send(&encbuf[0..enclen])
        }) {
            if fwd_err_fatal(e, &flag, key) {
                break;
            }
        }
    }
    let fl = flag.load(Relaxed);
    debug!("tw fwd key {} closed fl {}", b64sk(key), fl);
}

//Unidirectional forward thread from ciphertext tube decrypting to plaintext tube
//Stops when flag is set to false or no data for 5 minutes
pub fn tube_unwrap(src: Tube, dst: Tube, key: &SecKey, flag: Arc<AtomicBool>, order: bool) {
    debug!("tu on {} to {} key {}", src, dst, b64sk(key));
    log_err!(src.set_timeout(secs(1)), "set_timeout failed"); //timeout
    let mut last_good = Instant::now(); //5 min expiration
    let mut oldnon = None;
    while flag.load(Relaxed) && last_good.elapsed() < secs(300) {
        if let Err(e) = src.recv_vec().and_then(|mut rcvd| {
            if rcvd.len() <= CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES {
                warn!("Bad length tube_unwrap {} {} -> {}", rcvd.len(), src, dst);
                return Err(SfErr::BadLen); //this continues the loop
            }
            let non = lbytes_to_u64(&rcvd) as i64; //nonce as integer
            if order && oldnon.map(|o| non.wrapping_sub(o) < 0).unwrap_or(false) {
                warn!("Bad order tube_unwrap {} {} -> {}", rcvd.len(), src, dst);
                return Err(SfErr::BadSignatureErr); // don't die on spoofed/old packets
            }
            let pt = wr_crypto_secretbox_open(&mut rcvd, key)?;
            last_good = Instant::now();
            oldnon = Some(non);
            trace!("tu {} ({} plain) k {}", pt.len() + 40, pt.len(), b64sk(key));
            dst.send(pt) //forward through dst
        }) {
            if fwd_err_fatal(e, &flag, key) {
                break;
            }
        }
    }
    let fl = flag.load(Relaxed);
    debug!("tu key {} closed fl {}", b64sk(key), fl);
}

//Decides whether a forwarding error is fatal, and prints it out if need be
pub fn fwd_err_fatal(e: SfErr, flag: &AtomicBool, key: &SecKey) -> bool {
    if let SfErr::IoErr(ie) = &e {
        match ie.kind() {
            std::io::ErrorKind::TimedOut => {}
            std::io::ErrorKind::WouldBlock => {}
            std::io::ErrorKind::ConnectionReset => {
                debug!("ConnectionReset false flag {}", b64sk(key));
                flag.store(false, Relaxed); //it's disconnected
                return true;
            }
            std::io::ErrorKind::UnexpectedEof => {
                debug!("UnexpectedEof false flag {}", b64sk(key));
                flag.store(false, Relaxed); //it's disconnected
                return true;
            }
            _ => info!("fwd {} error {} {:?}", b64sk(key), ie, ie.kind()), //non timeout
        }
    } else if let SfErr::TimeoutErr(te) = e {
        if let crossbeam_channel::RecvTimeoutError::Disconnected = te {
            debug!("Disconnected false flag {}", b64sk(key));
            flag.store(false, Relaxed); //it's disconnected
            return true;
        }
    } else if let SfErr::SendError = e {
        debug!("SendError false flag {}", b64sk(key));
        flag.store(false, Relaxed); //it's disconnected
        return true;
    }
    false
}

//wrap a binary into a BSON generic binary type
pub fn binary_bson(bin: &[u8]) -> Bson {
    Bson::Binary(bson::spec::BinarySubtype::Generic, bin.to_vec())
}
pub fn binary_bvec(bin: Vec<u8>) -> Bson {
    Bson::Binary(bson::spec::BinarySubtype::Generic, bin)
}

//Takes in a SignSKey and calculates and returns the full keypair... pair
pub fn secskey_to_keys(skey: SignSKey) -> Keys {
    let pk = copy_to_array(&skey[32..]);
    let skeys = SignKeys { pk: pk, sk: skey };
    Keys {
        bx: BoxKeys {
            pk: wr_crypto_sign_pk_to_box(&skeys.pk),
            sk: wr_crypto_sign_sk_to_box(&skeys.sk),
        },
        sign: skeys,
    }
}

// Returns my primary keypair, along with my blinded keys for discovery and meet
pub fn get_my_keypair(workdir: &PathBuf) -> Keys {
    let kpath = workdir.join("my_seckey.bin");
    let origkeys = match fs::read(&kpath) {
        Ok(readpk) => {
            let mut ssk: SignSKey = [0; 64];
            ssk.copy_from_slice(&readpk[..64]);
            secskey_to_keys(ssk)
        }
        Err(e) => {
            warn!("Could not read your keys; is this a first run? {}", e);
            let k = wr_crypto_sign_keypair();
            fs::write(kpath, &k.sk[..])
                .unwrap_or_else(|e| error!("ERROR: could not save secret keys {}", e));
            secskey_to_keys(k.sk)
        }
    };
    origkeys
}

// Timestamp in milliseconds from epoch as u64
pub fn epoch_timestamp() -> u64 {
    let dur = &SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .expect("Time is out of whack"); //should never happen
    let epochms = dur.as_secs() * 1000 + dur.subsec_millis() as u64;
    trace!("Grabbed epoch_timestamp as {}", epochms);
    epochms
}

pub fn bytes_to_u64(rbytes: &[u8]) -> u64 {
    u64::from_ne_bytes(*array_ref![rbytes, 0, 8])
}

pub fn lbytes_to_u64(rbytes: &[u8]) -> u64 {
    u64::from_le_bytes(*array_ref![rbytes, 0, 8])
}

pub fn be_to_i64(rbytes: &[u8]) -> i64 {
    i64::from_be_bytes(*array_ref![rbytes, 0, 8])
}

// Add a sequence to a range vector. Returns whether added (new) or already known (old)
pub fn update_acks(acks: &mut Vec<ops::Range<i64>>, seq: i64) -> bool {
    for i in 0..acks.len() {
        //Update our tracking of which messages we have received
        if seq > acks[i].end {
            continue; //next plz
        }
        if seq < acks[i].start - 1 {
            //Space before the start of this ack range; needs new ack block
            debug!("Inserting ack block {} for {}", i, seq);
            acks.insert(i, seq..(seq + 1)); //insert the ack range for just seq
        } else if seq == acks[i].start - 1 {
            //Immediately at the start of this ack range; extend backwards
            debug!("Extending ack block {} back for {}", i, seq);
            acks[i].start = seq;
        } else if seq == acks[i].end {
            //Immediately at the end of the ack range; extend forwards
            if i + 1 < acks.len() && acks[i + 1].start == seq + 1 {
                //Filled in the gap between two ack blocks, combine
                debug!("Joining ack blocks {} for {}", i, seq);
                acks[i].end = acks[i + 1].end;
                acks.remove(i + 1);
            } else {
                //just extending
                debug!("Extending ack block {} for {}", i, seq);
                acks[i].end = seq + 1;
            }
        } else {
            return false; // already known
        }
        return true; //Handled, one way or the other
    }
    debug!("Adding ack block for {} acks len {}", seq, acks.len());
    acks.push(seq..(seq + 1)); //Add new ack block on end
    return true;
}

//Same as do_rpc but sets a special timeout first
pub fn do_rpc_timeout(d: Document, t: &Tube, b: &BoxPKey, k: &Keys, to: u64) -> SfRes<(Document, f64)> {
    t.set_timeout(Duration::new(to / 1000, (to % 1000) as u32 * 1000000))
        .unwrap_or_else(|e| error!("set_timeout failed {}", e));
    do_rpc(d, t, b, k)
}

// Does a standalone RPC call to a remote node
const RPC_RETRANSES: usize = 4;
const RPC_PEEKS: usize = 3; //consecutive recvs before retransmitting
pub fn do_rpc(mut doc: Document, cli: &Tube, box_tgt: &BoxPKey, keys: &Keys) -> SfRes<(Document, f64)> {
    //Create a random ID if needed
    let id = doc.get_i64("id").unwrap_or_else(|_| {
        let newid = rand_i64();
        doc.insert("id", bson::Bson::I64(newid));
        newid
    });
    // they can calculate the box key but may care about the sign_key too
    doc.insert("respkey", binary_bson(&keys.sign.pk[..]));
    let fnc = doc.get_str("fnc").unwrap_or("").to_string();
    let mut recvdec: SfRes<Document> = Err(SfErr::NoneErr);
    let mut starts = [Instant::now(); RPC_RETRANSES];
    let mut rtt = 1000.0;
    //Send up to RPC_RETRANSES times, trying to receive a response thrice for each send
    let mut peeks = 0;
    let mut tries = 0;
    while tries < RPC_RETRANSES {
        //Resend the RPC if it's new or previous receive timed out.
        if peeks == 0 || peeks > RPC_PEEKS {
            doc.insert("tr", bson::Bson::I32(tries as i32));
            let encdata = wr_crypto_box_seal(&bdoc_to_u8vec(&doc), box_tgt);
            let l = encdata.len();
            debug!("Send RPC {:X} {} {} from {} try {}", id, fnc, l, cli, tries);
            starts[tries] = Instant::now(); //record when we sent this one
            if let Err(e) = cli.send(&encdata) {
                error!("ERROR: {} couldn't send message try {}", e, tries);
            }
            tries += 1;
            peeks = 0;
        }
        let received = match cli.recv_vec() {
            Ok(r) => r,
            Err(e) => {
                trace!("RPC recv error {}", e);
                peeks = 0; //Probably a timeout, so start the next try again at square 0
                continue;
            }
        };
        trace!("Received {} bytes looking for ID {:X}", received.len(), id);
        match wr_crypto_box_open_easy(&received, box_tgt, &keys.bx.sk).and_then(|plain| {
            let rdtmp = decode_document(&mut Cursor::new(&plain))?; //Get the RTT for this exact send
            let start_idx = rdtmp.get_i32("tr").unwrap_or(0) as usize;
            trace!("Decrypted {} for ID {:X} si {}", plain.len(), id, start_idx);
            let start = starts[start_idx.max(0).min(tries - 1)];
            rtt = dur_millis(&start.elapsed());
            Ok((rdtmp.get_i64("id")?, rdtmp))
        }) {
            Ok((rid, rdtmp)) => {
                if rid == id {
                    debug!("Received ID {:X} rtt {}", id, rtt);
                    recvdec = Ok(rdtmp);
                    break;
                } else {
                    warn!("ID {:X} expected {:X}, {} bytes", rid, id, received.len())
                }
            }
            Err(e) => {
                warn!("Bad RPC resp len {} ID {:X}: {}", received.len(), id, e);
                peeks += 1; //A bad key response could be a spurious resend from before with
                continue; //different keys. Check the next packet w/o resending
            }
        };
    }
    //Format RPC errors into sf/ioerrors
    recvdec.and_then(|dec| {
        if let Ok(errstr) = dec.get_str("err") {
            return Err(SfErr::NodeError((errstr.to_string(), dec)));
        }
        Ok((dec, rtt))
    })
}

// Calculates the discovery blind pubkey of a given permanent pubkey
pub fn disc_blind(tgt: &SignPKey) -> SignPKey {
    wr_crypto_blind_ed25519_public_key(&wr_crypto_blind_ed25519_public_key(tgt, "meet"), "disc")
}

pub fn dur_millis(ds: &Duration) -> f64 {
    (ds.as_secs() * 1000) as f64 + (ds.subsec_nanos() as f64) / 1_000_000.0
}

// Makes our keys for stashing personal info on the meet node
pub fn derive_self_chat_keys(context: &Context, meetkey: &SignPKey) -> (SecKey, Keys) {
    let mut m: [u8; 64] = [0; 64];
    (&mut m[0..32]).clone_from_slice(&context.keys.sign.sk[0..32]);
    (&mut m[32..]).clone_from_slice(&meetkey[..]);
    let key: SecKey = wr_crypto_hash_sha256(&m);
    (key, seed_keys(wr_crypto_hash_sha256(&key[..])))
}
pub fn seed_keys(seed: [u8; 32]) -> Keys {
    let skeys = wr_crypto_sign_seed_keypair(seed);
    Keys {
        bx: BoxKeys {
            pk: wr_crypto_sign_pk_to_box(&skeys.pk),
            sk: wr_crypto_sign_sk_to_box(&skeys.sk),
        },
        sign: skeys,
    }
}

//Increments a pkey. Nice for iterating pkeys.
pub fn increment_spkey(spkey: &mut SignPKey) {
    let mut idx = spkey.len() as i64 - 1; // increment the key to get the next one
    while idx >= 0 {
        let idx_us = idx as usize;
        if spkey[idx_us] == 0xFF {
            spkey[idx_us] = 0;
        } else {
            spkey[idx_us] += 1;
            break;
        }
        idx -= 1;
    }
}

pub fn yml(path: &PathBuf) -> Yaml {
    if let Ok(bytes) = fs::read(path) {
        if let Ok(mut docs) = YamlLoader::load_from_str(&String::from_utf8_lossy(&bytes)) {
            if docs.len() > 0 {
                return docs.remove(0);
            }
        }
    }
    Yaml::Hash(linked_hash_map::LinkedHashMap::new())
}

//Parse args, init libsodium, and start the server
pub fn innermain(args: Vec<String>) -> SfRes<usize> {
    if -1 == wr_sodium_init() {
        error!("Cannot initialize libsodium");
        return Err(SfErr::DoneErr);
    }
    let mut logl = 1; //logging level
    let mut workdir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    workdir.push("schadnfreude");
    let mut config = yml(&workdir.join("config.yml")).into_hash().unwrap(); //get config.yml
    let mut argidx = 1;
    while argidx < args.len() {
        if &args[argidx] == "-p" && args.len() > argidx + 1 {
            argidx += 1;
            let prt = Yaml::Integer(args[argidx].parse()?);
            config.insert(Yaml::String("port".to_string()), prt);
        } else if &args[argidx] == "-n" {
            config.insert(Yaml::String("node".to_string()), Yaml::Boolean(true));
        } else if &args[argidx] == "-h" && args.len() > argidx + 1 {
            argidx += 1;
            config.insert(
                Yaml::String("host".to_string()),
                Yaml::String(args[argidx].to_string()),
            );
        } else if &args[argidx] == "-d" && args.len() > argidx + 1 {
            argidx += 1;
            workdir = PathBuf::from(&args[argidx]);
            config = yml(&workdir.join("config.yml")).into_hash().unwrap();
        } else if &args[argidx] == "-v" && args.len() > argidx + 1 {
            argidx += 1;
            logl = args[argidx].parse::<usize>()?;
        } else {
            eprintln!("Usage: schadnfreude [-n] [-d configdir] [-p port] [-h host] [-v verbosity]");
            eprintln!(" -n Run as node, relaying other connections");
            eprintln!(" -d The config folder, where keys should be kept");
            eprintln!(" -p The port to listen on");
            eprintln!(" -h Host to listen on. 127.0.0.1 for client, 0.0.0.0 for server.");
            eprintln!(" -v The verbosity level (0-4)");
            return Ok(7);
        }
        argidx += 1;
    }
    //Now we can use log macros (error! warn! info! debug! debug!)
    let levels: [Level; 5] = [
        Level::Error,
        Level::Warn,
        Level::Info,
        Level::Debug,
        Level::Trace,
    ];
    crate::sflogger::init_stdio_with_level(levels[logl], logl < 4)
        .unwrap_or_else(|e| eprintln!("ERROR initializing logging {}", e));
    fs::create_dir_all(&workdir)?; //ensure workdir exists

    Ok(run(workdir, Yaml::Hash(config)))
}

//either has a receiver in waiting to pass to a monitor thread once an address has been decided upon
//or has the address once the thread has been launched or is about to be.
pub enum MeetInfo {
    Receiver(Receiver<MeetStateMsg>),
    Address(SignPKey),
}

// dump a YAML config to your config.yml
pub fn save_yaml(dir: &PathBuf, config: &Yaml) {
    let mut yml_str = String::new();
    if let Err(e) = YamlEmitter::new(&mut yml_str).dump(config) {
        error!("{}", e);
    } else {
        log_err!(fs::write(&dir.join("config.yml"), yml_str), "config write");
    }
}

//Runs a Schadnfreude instance, kicking off threads as necessary
pub fn run(dir: PathBuf, config: Yaml) -> usize{
    let port = config["port"].as_i64().unwrap_or(7878) as u16;
    let hostconf = config["host"].as_str().and_then(|p| p.parse().ok());
    let node = config["node"].as_bool().unwrap_or(false);
    let hops = config["hops"].as_i64().unwrap_or(1) as u8;
    let prox4 = config["socks4"].as_str().and_then(|p| p.parse().ok());
    let prox5 = config["socks5"].as_str().and_then(|p| p.parse().ok());
    let prx = prox4.map(|sa| (4, sa)).or_else(|| prox5.map(|sa| (5, sa)));
    let host = if let Some(h) = hostconf {
        h
    } else if node {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    };
    let addr = SocketAddr::new(host, port);
    save_yaml(&dir, &config);

    let skeys = get_my_keypair(&dir); //Prep your keys
    let (mssnd, meetstate_receiver) = unbounded();
    let mut mrecv = None; //See if we have a meet node via cli args or saved in our dir
    let mi = if let Ok(meet_spk_vec) = fs::read(&dir.join("my_meet.bin")) {
        if let Ok(meet_spk) = lenveq(meet_spk_vec, CRYPTO_SIGN_PUBLICKEYBYTES) {
            mrecv = Some(meetstate_receiver);
            MeetInfo::Address(copy_to_array(&meet_spk))
        } else {
            MeetInfo::Receiver(meetstate_receiver)
        }
    } else {
        MeetInfo::Receiver(meetstate_receiver)
    };

    //print our keys
    info!("Key {} port {} hops {}", b64spk(&skeys.sign.pk), addr, hops);
    let ctx = Arc::new(SfContext::new(skeys, mssnd, hops, node, addr, dir, mi, prx));

    //bootstrap nodes
    if ctx.nodes.is_empty() {
        ctx.synced_nodes.store(false, Relaxed);
        warn!("First run? No nodes!");
    }

    //And node monitor
    let (nsender, notification_receiver) = unbounded();
    let (ctx_clone2, nsender_clone) = (Arc::clone(&ctx), nsender.clone());
    let tb = Builder::new().name("netmontr".to_string());
    let delay = if mrecv.is_none() { 0 } else { 1 }; //wait a second on boot if we're restarting
    let sres = tb.spawn(move || {
        thread::park_timeout(Duration::from_secs(delay)); //delay to not compete with meet monitor
        run_netmonitor(&ctx_clone2, nsender_clone)
    });
    sres.map(|_| ()).unwrap_or_else(|e| error!("{}", e));

    if node {
        info!("Running as node");
        run_node(ctx, &config) //run node server (UDP) - this should not return
    } else {
        run_cli(ctx, mrecv, nsender, notification_receiver)
    }
}

//Relaunch us. Start a process to wait for our exit then respawn us, and then exit;
pub fn restart() {
    unsafe {
        #[cfg(windows)]
        {
            use std::os::windows::prelude::*;
            let mypid = um::processthreadsapi::GetCurrentProcessId();
            let cmdlinewptr = um::processenv::GetCommandLineW();
            let cmdllen = um::winbase::lstrlenW(cmdlinewptr);
            let cmdlineslice = slice::from_raw_parts(cmdlinewptr, cmdllen as usize);
            let cmdlineoss = ffi::OsString::from_wide(cmdlineslice);
            let cmd = cmdlineoss.to_string_lossy();
            let pid = format!("{}", mypid);
            let argz = ["/C", "taskkill", "/F", "/PID", &pid, "&", "cmd", "/c", &cmd];
            log_err!(process::Command::new("cmd.exe").args(&argz).spawn(), "kill");
        }
        #[cfg(not(windows))]
        {
            //get cmdline from /proc/self/cmdline
            if let Ok(cmdbytes) = fs::read("/proc/self/cmdline") {
                let cmdline = String::from_utf8_lossy(&cmdbytes);
                let mypid = libc::getpid();
                let pid = format!("{}", mypid);
                let myargs = ["/c", "kill", "-9", &pid, ";", &cmdline];
                log_err!(process::Command::new("/bin/sh").args(&myargs).spawn(), "kl");
            }
        }
    }
    process::exit(0);
}
