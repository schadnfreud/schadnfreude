//Unit and integration tests for schadnfreude
#[cfg(test)]
mod tests {
    use crate::innermain::*;
    use crate::*;
    use crate::{b64spk, seed_keys, SfContext, SfErr, SfRes, URL_SAFE_NO_PAD};
    use arrayref::array_ref;
    use log::{debug, error, info, Level};
    use rand::Rng;
    use reqwest::{Client, Method};
    use serde_json::json;
    use serde_json::Value;
    use std::fs;
    use std::io::Read;
    use std::mem::discriminant;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering::Relaxed;
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime};
    use yaml_rust::YamlLoader;
    static LOGGER_INIT: std::sync::Once = std::sync::Once::new();
    fn init_logger() {
        //get our debug output if we haven't already started the debugger.
        LOGGER_INIT.call_once(|| {
            sflogger::init_stdio_with_level(Level::Debug, true).expect("logging err!");
        });
    }

    //Random keypairs
    fn test_keypairs() -> (Keys, Keys, Keys) {
        let origkeys = crate::secskey_to_keys(wr_crypto_sign_keypair().sk);
        let meet_blind_keys = crate::secskey_to_keys(wr_crypto_blind_ed25519_secret_key(
            &origkeys.sign.sk,
            "meet",
        ));
        let disc_blind_keys = crate::secskey_to_keys(wr_crypto_blind_ed25519_secret_key(
            &meet_blind_keys.sign.sk,
            "disc",
        ));
        (origkeys, disc_blind_keys, meet_blind_keys)
    }

    //Test context and initialize the logger, since it will then get initialized in most tests
    fn test_context(
        node: bool,
        port: u16,
        meetaddr: Option<SignPKey>,
        workdir: &str,
    ) -> (Arc<SfContext>, Option<Receiver<crate::MeetStateMsg>>) {
        init_logger();
        let keys = crate::secskey_to_keys(wr_crypto_sign_keypair().sk);
        let (mssnd, meetstate_receiver) = unbounded();
        let mut mrecv = None;
        let mi = if let Some(mkey) = meetaddr {
            mrecv = Some(meetstate_receiver);
            crate::MeetInfo::Address(mkey)
        } else {
            crate::MeetInfo::Receiver(meetstate_receiver)
        };
        let wd = PathBuf::from(workdir);
        let sa = SocketAddr::from(([127, 0, 0, 1], port));
        (
            Arc::new(SfContext::new(keys, mssnd, 1, node, sa, wd, mi, None)),
            mrecv,
        )
    }
    fn test_conn(stube: Tube, rtube: Tube) -> Conn {
        let node = crate::PubNode::new([0; 32], [0; 32], "127.0.0.1:1".parse().unwrap());
        Conn {
            key: [0; 32],
            stube: std::sync::RwLock::new(stube),
            ci: Mutex::new(ConnInfo::new(
                (rtube, None, 1.0, node.clone()),
                Instant::now(),
            )),
            idkeys: seed_keys([0; 32]),
            cachepath: dirs::cache_dir().unwrap(),
            participants: Mutex::new(HashSet::new()),
            queued: Mutex::new(BTreeMap::new()),
            meet: std::sync::RwLock::new(node.clone()),
            host_seq: AtomicIsize::new(0),
            rttest: AtomicUsize::new(1),
            ctflag: AtomicBool::new(false),
            calls: Mutex::new(BTreeMap::new()),
            resps: Mutex::new(BTreeMap::new()),
            streamies: Mutex::new(BTreeMap::new()),
            backups: Mutex::new(Vec::new()),
            running: Mutex::new(None),
            acks: Mutex::new(Vec::new()),
        }
    }
    fn rand_node() -> crate::Node {
        let mut rng = rand::thread_rng();
        let keys = crate::rand_keys();
        let ip = [rng.gen(), rng.gen(), rng.gen(), rng.gen()];
        let port = rng.gen();
        crate::Node {
            key: keys.sign.pk,
            bkey: keys.bx.pk,
            address: crate::NodeAddr::Sockaddr(SocketAddr::from((ip, port))),
        }
    }
    fn rand_pubnode() -> crate::PubNode {
        let node = rand_node();
        if let crate::NodeAddr::Sockaddr(s) = node.address {
            return crate::PubNode::new(node.key, node.bkey, s);
        }
        panic!("rand_pubnode bad node");
    }
    #[test]
    fn now_as_bin_seconds_len() {
        init_logger();
        assert_eq!(crate::now_as_bin_seconds().len(), 8);
    }
    #[test]
    fn bin_seconds_as_systemtime_cmp() {
        init_logger();
        let secs = crate::bin_seconds_as_systemtime(&[39, 236, 207, 91, 0, 0, 0, 0])
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        debug!("{}", secs);
        assert_eq!(secs, 1540353063);
    }
    #[test]
    fn enc_dec() {
        init_logger();
        let encd = crate::bdoc_to_u8vec(&doc! {"m": "abc", "s": 123});
        debug!("encd len {}", encd.len());
        let decres = decode_document(&mut ::std::io::Cursor::new(&encd));
        assert!(decres.is_ok());
        let decdoc = decres.unwrap();
        assert!(decdoc.get_str("m").is_ok());
        assert_eq!(decdoc.get_i32("s").unwrap(), 123);
    }
    #[test]
    fn sockaddr_bin() {
        init_logger();
        let addr: SocketAddr = "[cafe:1234::b00c]:8765".parse().unwrap();
        let abin = crate::sockaddr_to_bin(&addr);
        let debin = crate::debin_addr(&abin);
        assert_eq!(addr, debin);
    }
    #[test]
    fn sodium_seal() {
        init_logger();
        let (origkeys, _disc_blind_keys, meet_blind_keys) = test_keypairs();
        let sealed = wr_crypto_box_seal("hello world".as_bytes(), &origkeys.bx.pk);
        let opened = wr_crypto_box_seal_open(&sealed, &origkeys.bx);
        assert!(opened.is_ok());
        assert_eq!(opened.unwrap(), "hello world".as_bytes());
        let mkey = wr_crypto_blind_ed25519_public_key(&origkeys.sign.pk, "meet");
        let mbkey = wr_crypto_sign_pk_to_box(&mkey);
        let msealed = wr_crypto_box_seal("hello world".as_bytes(), &mbkey);
        let mopened = wr_crypto_box_seal_open(&msealed, &meet_blind_keys.bx);
        assert_eq!(mopened.unwrap(), "hello world".as_bytes());
    }
    #[test]
    fn keys_nodeaddr_sign() {
        init_logger();
        let keys = crate::rand_keys();
        let meetkeys = crate::rand_keys();
        let signed = crate::sign_meet_nodeaddr_bin(&keys, &meetkeys.sign.pk);
        assert!(signed.len() > 32);
        let parsed = crate::parse_binaddr(&signed, &keys.sign.pk).unwrap();
        match parsed {
            crate::NodeAddr::Sockaddr(ref _s) => panic!("invalid"),
            crate::NodeAddr::Meet(ref m) => assert!(m.meet_host == meetkeys.sign.pk),
        }
        //Now test stringifying
        let (code, serialed) = parsed.deparse();
        assert_eq!(code, 2);
        let reparsed = crate::parse_nodeaddr(2, &serialed, &keys.sign.pk).unwrap();
        match reparsed {
            crate::NodeAddr::Sockaddr(_s) => panic!("invalid reparse"),
            crate::NodeAddr::Meet(rm) => assert!(rm.meet_host == meetkeys.sign.pk),
        }
    }
    #[test]
    fn rand_node_query() {
        init_logger();
        fs::remove_dir_all("deleteme_rntest").unwrap_or(());
        fs::create_dir("deleteme_rntest").unwrap_or(());
        let ctx1 = test_context(false, 1234, None, "deleteme_rntest").0;
        for _i in 0..500 {
            ctx1.save_node(rand_node()).unwrap();
        }
        assert!(ctx1.rand_node_inner().is_some());
        fs::remove_dir_all("deleteme_rntest").unwrap_or(());
    }
    #[test]
    fn load_save_next_nodes() {
        init_logger();
        let keys = crate::rand_keys();
        let new_node = crate::Node {
            key: keys.sign.pk,
            bkey: keys.bx.pk,
            address: crate::NodeAddr::Sockaddr(SocketAddr::from(([127, 0, 0, 1], 123))),
        };
        fs::remove_dir_all("deleteme_nstest").unwrap_or(());
        fs::create_dir("deleteme_nstest").unwrap_or(());
        let ctx1 = test_context(false, 1234, None, "deleteme_nstest").0;
        ctx1.save_node(new_node).unwrap();
        ctx1.nodes.flush().unwrap();
        drop(ctx1);
        let ctx = test_context(false, 1234, None, "deleteme_nstest").0;
        assert!(!ctx.nodes.is_empty());
        info!("Worked I guess");
        assert!(ctx.nextnode_wrap(&[0xff; 32]).is_some());
        fs::remove_dir_all("deleteme_nstest").unwrap_or(());
    }
    #[test]
    fn conn_call_size_indistinguishability() {
        init_logger();
        let (stube, sentube) = Tube::pair(true); //writes to stube show up on sentube and vice versa
        let (rtube, _recvtube) = Tube::pair(true); // not used
        let c = Arc::new(test_conn(stube, rtube));
        let conn2 = Arc::clone(&c);
        //start rec thread
        let mythread = thread::current();
        thread::spawn(move || {
            let mut last_rcvd_len = None;
            for respfield in &["dls", "lck", "ulk", "???", "res", "wrs", "cls"] {
                let recvd_len = sentube.recv_vec().unwrap().len();
                let calls = conn2.calls.lock().unwrap();
                let id = *(calls.keys().next().unwrap());
                info!("Conn Call {} ID {} {} bytes", respfield, id, recvd_len);
                drop(calls);
                let d = doc! {*respfield: 0 as i64};
                conn2.resps.lock().unwrap().insert(id, d);
                mythread.unpark();
                if let Some(rlen) = last_rcvd_len {
                    assert_eq!(rlen, recvd_len);
                }
                last_rcvd_len = Some(recvd_len);
            }
        });
        //UNCOMMENT AS SUPPORT ADDED FOR INDISTINGUISHIBILITY
        //c.conn_fnew("abc", 0, false); //return must have "fid"
        //c.conn_newfold("defg"); //return must have "fid"
        c.conn_fdel(0).unwrap();
        //c.conn_fpathlock("hijkl").unwrap(); //return must have "lck"
        c.conn_flock(0).unwrap();
        c.conn_funlock(1).unwrap();
        //c.conn_frename("a", 0, "b").unwrap(); //return must have "fid"
        let _ = c.conn_fmeta(0); //return can be a doc with "del" in it but will return error
        c.conn_sread(0, 1).unwrap();
        c.conn_swrite(0, 1).unwrap();
        c.conn_sclose(0, 1).unwrap();
    }
    #[test]
    fn socks_test() {
        init_logger();
        let sockaddr: SocketAddr = "127.0.0.1:3080".parse().unwrap();
        let sockaddr2 = sockaddr.clone();
        thread::spawn(move || {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                use socks5_async::SocksServer;
                let mut srv = SocksServer::new(sockaddr2, true, Box::new(|_, _| true)).await;
                srv.serve().await;
            });
        });
        let start = Instant::now();
        let timeout = Duration::new(5, 0);
        while TcpStream::connect(&sockaddr).is_err() && start.elapsed() < timeout {
            debug!("waiting for socks server to be up");
            thread::sleep(Duration::from_millis(10));
        }
        use std::net::TcpListener;
        let laddr = "127.0.0.1:3971".parse().unwrap();
        let listener = TcpListener::bind(&laddr).unwrap();
        let stube = crate::Tube::socks_connect(&laddr, &(5, sockaddr.clone())).unwrap();
        let otherside = crate::Tube::tcp_accept(&listener).unwrap();
        stube.send_vec(vec![4; 12]).unwrap();
        let rvec = otherside.recv_vec().unwrap();
        assert_eq!(vec![4; 12], rvec);
        otherside.send_vec(vec![5; 12]).unwrap();
        let rvec2 = stube.recv_vec().unwrap();
        assert_eq!(vec![5; 12], rvec2);

        debug!("IPV6 test. If this fails enable IPv6 in docker/your system.");
        let laddr6 = "[::1]:2676".parse().unwrap();
        let l6 = TcpListener::bind(&laddr6);
        if let Err(e) = &l6 {
            error!("IPv6 FAILED {}", e);
        }
        assert!(l6.is_ok());
        let listener6 = l6.unwrap();
        let stube6 = crate::Tube::socks_connect(&laddr6, &(5, sockaddr)).unwrap();
        let otherside6 = crate::Tube::tcp_accept(&listener6).unwrap();
        stube6.send_vec(vec![6; 12]).unwrap();
        let rvec6 = otherside6.recv_vec().unwrap();
        assert_eq!(vec![6; 12], rvec6);
    }
    fn recv_doc(rcvd: &[u8], key: &SecKey, typecode: &str) -> (SignPKey, Document) {
        let doc = decode_document(&mut std::io::Cursor::new(rcvd)).unwrap();
        let u = doc.get_binary_generic(typecode).unwrap();
        let decrypted = wr_crypto_secretbox_open_easy(&u, key).unwrap();
        let (frombin, smsg) = decrypted.split_at(CRYPTO_SIGN_PUBLICKEYBYTES);
        let signer: SignPKey = copy_to_array(frombin); //Now let's get & verify the sig
        let valmsg = wr_crypto_sign_open_inplace(smsg, &signer).unwrap();
        let docinner = decode_document(&mut std::io::Cursor::new(valmsg)).unwrap();
        (signer, docinner)
    }
    #[test]
    fn backup_tests() {
        init_logger();
        fs::remove_dir_all("deleteme_bktest1").unwrap_or(());
        fs::create_dir("deleteme_bktest1").unwrap_or(());
        let mut ctx = test_context(false, 1234, None, "deleteme_bktest1").0;
        Arc::get_mut(&mut ctx).unwrap().hops = 0; // no hops - prevents us from having to run full network hosts for hops
        let (stube, mut sentube) = Tube::pair(true); //writes to stube show up on sentube and vice versa
        let (rtube, _recvtube) = Tube::pair(true); // not used
        let c = Arc::new(test_conn(stube, rtube));
        let mut coreci = c.ci.lock().unwrap();
        coreci.failed -= Duration::new(301, 0);
        let mut cbackups = c.backups.lock().unwrap();
        //Add backup stubs
        let (mut b1stube, b1rtube) = Tube::pair(true); // not used
        let mut b1stubeclone = b1stube.split_off_recv().unwrap();
        let mut b1node = rand_pubnode();
        b1node.address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            b1node.address.port(),
        );
        cbackups.push(ConnInfo::new((b1stube, None, 0.1, b1node), Instant::now()));
        cbackups[0].flag = Some(Arc::new(AtomicBool::new(true)));
        cbackups[0].recvd -= Duration::new(16, 0); //Pretend backups[0]'s been out for 1 minute
        cbackups[0].pinged -= Duration::new(6, 0); //And our ping has expired
        let orig_backup_0_node = cbackups[0].node.clone();
        debug!("Made error backup {}", cbackups[0].node.address);
        let (b2tube, b2rtube) = Tube::pair(true); // not used
        cbackups.push(ConnInfo::new(
            (b2tube, None, 0.1, rand_pubnode()),
            Instant::now(),
        ));
        cbackups[1].flag = Some(Arc::new(AtomicBool::new(true)));

        //Now try to exercise backup ping
        let mut addrs: HashSet<SocketAddr> =
            cbackups.iter().map(|b| b.node.address.clone()).collect();
        addrs.insert(coreci.node.address.clone());
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        let rcvd = b1rtube.recv_vec().unwrap();
        info!("RECVD {} bytes", rcvd.len());
        cbackups[0].pinged -= Duration::new(6, 0); //And our ping has expired

        //Now try to exercise backup reconnect
        cbackups[0].recvd -= Duration::new(60, 0); //Pretend backups[0]'s been out for > 1 minute
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        if let crate::Tube::Sock(_) = &cbackups[0].tube {
        } else {
            panic!("Bad backup reconnect {}", &cbackups[0].tube);
        }
        std::mem::swap(&mut cbackups[0].tube, &mut b1stubeclone); //swap back in the original tube after reconnect
        cbackups[0].flag = Some(Arc::new(AtomicBool::new(true))); //and key
        cbackups[0].recvd -= Duration::new(300, 0); //Pretend backups[0]'s been out for 5 minutes
                                                    //Now try to exercise its backup down detection
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        //and check results
        sentube.set_timeout(Duration::from_millis(1)).unwrap(); //we are doing this serially, no delay
        b2rtube.set_timeout(Duration::from_millis(1)).unwrap(); //we are doing this serially, no delay
        let nodedowndoc = sentube.recv_vec().unwrap();
        let (_signer, docinner) = recv_doc(&nodedowndoc, &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodedown"));
        assert!(&docinner.get_binary_generic("rolk").unwrap()[..] == &cbackups[0].node.key[..]);
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodedown"));
        assert!(&b2doc.get_binary_generic("rolk").unwrap()[..] == &cbackups[0].node.key[..]);

        //Test receiving another nodedown message
        b2rtube.send_vec(nodedowndoc.clone()).unwrap();
        c.poll_backup(&mut cbackups, 1, &ctx, &mut coreci, &addrs)
            .unwrap();

        //ok now try proposing new. We short circuit this by creating dummy nodes:
        let mut node = rand_node();
        node.address = crate::NodeAddr::Sockaddr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9876,
        ));
        let dbk = crate::db_key(&node.bkey, 0, b"rttc");
        let mut cacheval = [0; 16];
        (&mut cacheval[..8]).copy_from_slice(&crate::now_as_bin_seconds()[..]);
        (&mut cacheval[8..]).copy_from_slice(&crate::u64_bytes((0.1 as f64).to_bits())[..]);
        ctx.save_node(node.clone()).unwrap();
        ctx.cache.insert(&dbk[..], &cacheval[..]).unwrap(); //this will prevent requests from going to establish RTT
        assert_eq!(
            discriminant(&cbackups[0].state),
            discriminant(&NodeState::SentNodedown(Instant::now()))
        );
        if let NodeState::SentNodedown(ref mut time_sent) = &mut cbackups[0].state {
            *time_sent -= Duration::new(16, 0); //now pretend we're 16 seconds later
        }

        //Now try to exercise its roll proposal
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        //and check results
        let nodepropmsg = sentube.recv_vec().unwrap();
        let (_signer, docinner) = recv_doc(&nodepropmsg, &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodeprop"));
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(b2doc.get_str("rolp"), Ok("nodeprop"));

        //ok now try proposed_time_elapsed - note that we need a thread to respond to the function
        if let NodeState::Proposed {
            when: ref mut time_sent,
            rollover: _,
            round: _,
            count: _,
            prev: _,
        } = &mut cbackups[0].state
        {
            *time_sent -= Duration::new(16, 0); //pretend we're 16 seconds later
        } else {
            panic!("Bad backup state");
        }
        let sentube2 = sentube.split_off_recv().unwrap();
        let th2 = thread::spawn(move || {
            info!("WAITING FOR RECV");
            sentube2.set_timeout(Duration::from_millis(200)).unwrap(); //we are doing this serially, no delay
            let recvd_len = sentube2.recv_vec().unwrap().len();
            info!("roll {} bytes", recvd_len);
        });

        //Now try to exercise roll commit and unwrap
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        th2.join().unwrap();

        //Now reset for a bad nodedown
        let (mut bbd_tube1, bbd_tube2) = crate::Tube::pair(false);
        cbackups[0].recvd = Instant::now(); //reset basically all cbackups[0] info
        cbackups[0].flag = Some(Arc::new(AtomicBool::new(true)));
        cbackups[0].node = orig_backup_0_node;
        std::mem::swap(&mut cbackups[0].tube, &mut bbd_tube1);
        bbd_tube2.send_vec(nodedowndoc).unwrap();
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        //and check results from all three channels
        let bisupdat = bbd_tube2.recv_vec().unwrap();
        let (_signer, docinner) = recv_doc(&bisupdat, &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodeisup"));
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(b2doc.get_str("rolp"), Ok("nodeisup"));
        let (_signer, docinner) = recv_doc(&sentube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodeisup"));
        assert!(&docinner.get_binary_generic("rolk").unwrap()[..] == &cbackups[0].node.key[..]);

        //put it down again but this time abort
        cbackups[0].recvd -= Duration::new(300, 0); //Pretend backups[0]'s been out for 5 minutes
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap(); //exercise backup down detection again
                       //and check results
        let nodedowndoc = sentube.recv_vec().unwrap(); //yes this replaces the previous nodedowndoc
        let (_signer, docinner) = recv_doc(&nodedowndoc, &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodedown"));
        assert!(&docinner.get_binary_generic("rolk").unwrap()[..] == &cbackups[0].node.key[..]);
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(b2doc.get_str("rolp"), Ok("nodedown"));
        assert!(&b2doc.get_binary_generic("rolk").unwrap()[..] == &cbackups[0].node.key[..]);
        b2rtube.send_vec(bisupdat).unwrap(); //Now tell it nevermind via the other backup
        c.poll_backup(&mut cbackups, 1, &ctx, &mut coreci, &addrs)
            .unwrap();
        assert_eq!(
            discriminant(&cbackups[0].state),
            discriminant(&NodeState::Chill)
        );

        //put it down again, propose again, but then conflict
        cbackups[0].recvd = Instant::now() - Duration::new(300, 0); //Pretend backups[0]'s been out for 5 minutes
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap(); //exercise backup down detection again
        let (_signer, _docinner) = recv_doc(&sentube.recv_vec().unwrap(), &[0; 32], "u");
        let (_signer, _b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(
            discriminant(&cbackups[0].state),
            discriminant(&NodeState::SentNodedown(Instant::now()))
        );
        if let NodeState::SentNodedown(ref mut time_sent) = &mut cbackups[0].state {
            *time_sent -= Duration::new(16, 0); //now pretend we're 16 seconds later
        }
        ctx.del_node(&node.key).unwrap(); //now get a different node to propose
        let mut node2 = rand_node();
        node2.address = crate::NodeAddr::Sockaddr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9876,
        ));
        let dbk = crate::db_key(&node2.bkey, 0, b"rttc");
        let mut cacheval2 = [0; 16];
        (&mut cacheval2[..8]).copy_from_slice(&crate::now_as_bin_seconds()[..]);
        (&mut cacheval2[8..]).copy_from_slice(&crate::u64_bytes((0.1 as f64).to_bits())[..]);
        ctx.save_node(node2.clone()).unwrap();
        log_err!(ctx.cache.insert(&dbk[..], &cacheval[..]), "cache set"); //this will prevent requests from going to establish RTT
                                                                          //make it send a proposal with new node
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap();
        let (_signer, docinner) = recv_doc(&sentube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodeprop"));
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(b2doc.get_str("rolp"), Ok("nodeprop"));
        ctx.save_node(node).unwrap();
        b2rtube.send(&nodepropmsg).unwrap(); //Send the conflicting proposal over the other tube
        c.poll_backup(&mut cbackups, 1, &ctx, &mut coreci, &addrs)
            .unwrap(); //THIS SHOULD RECOGNIZE A CONFLICT
        b2rtube.send_vec(nodepropmsg).unwrap(); //Repeat the conflicting proposal over the other tube
        c.poll_backup(&mut cbackups, 1, &ctx, &mut coreci, &addrs)
            .unwrap(); //THIS SHOULD CONCUR THE CONFLICT
        if let NodeState::Conflict {
            ref mut when,
            round: _,
            rollovers: _,
        } = &mut cbackups[0].state
        {
            *when -= Duration::new(16, 0); //Now fast forward 16 seconds
        } else {
            panic!("Not good state NO CONFLICT")
        }
        debug!("Checking new round");
        c.poll_backup(&mut cbackups, 0, &ctx, &mut coreci, &addrs)
            .unwrap(); //conflict_expired - should propose new round
        let (_signer, docinner) = recv_doc(&sentube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(docinner.get_str("rolp"), Ok("nodeprop"));
        let (_signer, b2doc) = recv_doc(&b2rtube.recv_vec().unwrap(), &[0; 32], "u");
        assert_eq!(b2doc.get_str("rolp"), Ok("nodeprop"));

        //test swap_backup
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_to_connect_to = socket.local_addr().unwrap();
        let keys = seed_keys([2; 32]);
        cbackups[0].swap_backup(keys.sign.pk, addr_to_connect_to, &ctx);
        cbackups[0].tube.send_vec(vec![8; 10]).unwrap();
        let mut rawbuf = [0; 1024];
        let (rlen, _) = socket.recv_from(&mut rawbuf).unwrap();
        assert_eq!(rlen, 10);
        //clean up
        fs::remove_dir_all("deleteme_bktest1").unwrap_or(());
    }

    #[test]
    fn main_backup_test() {
        init_logger();
        fs::remove_dir_all("deleteme_srvbktest").unwrap_or(());
        fs::remove_dir_all("deleteme_srv2bktest").unwrap_or(());
        fs::remove_dir_all("deleteme_clibktest").unwrap_or(());
        //Get a backup server ready for server tests, like promote
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap(); //this should go fast
        let addr_to_connect_to = socket.local_addr().unwrap();
        let srvctx = test_context(true, addr_to_connect_to.port(), None, "deleteme_srvbktest").0;
        let config = yaml_rust::Yaml::Hash(linked_hash_map::LinkedHashMap::new());
        let (local_sndr, _local_rcvr) = unbounded();
        let mut sctx = crate::nodesrv::SfSrv::new(&srvctx, Arc::new(socket), &config, local_sndr);
        let totl_sec = wr_crypto_auth(b"totl", array_ref![&srvctx.keys.sign.sk[..], 0, 32]); //derive key
        (&mut sctx.totl_key[0..32]).copy_from_slice(&totl_sec[..]);
        (&mut sctx.totl_key[32..]).copy_from_slice(b"totl");

        //Create convo/connection. These tubes aren't used since we're pretending main is down
        let (stube, _sentube) = Tube::pair(true); //writes to stube show up on the other and vice versa
        let (rtube, _recvtube) = Tube::pair(true); // not used
        let conn_main = Arc::new(test_conn(stube, rtube));
        let convks = conn_main.idkeys.clone();
        let convo_arc = sctx.newchat(&convks.sign.pk, false, 0); //make the new backup chat and insert it

        //Create a client
        let sess = crate::nodesrv::Session::new(
            &doc! {},
            *&convks.sign.pk,
            &sctx.db,
            [0; 32],
            true,
            Tube::pair(false).0,
        );
        let sk = sess.key.clone();
        let mut clictx =
            test_context(false, addr_to_connect_to.port(), None, "deleteme_clibktest").0;
        Arc::get_mut(&mut clictx).unwrap().hops = 0; // no hops - prevents us from having to run full network hosts for hops
        let s = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).unwrap();
        s.connect(&addr_to_connect_to).unwrap();
        let src = s.local_addr().unwrap();
        s.set_read_timeout(Some(Duration::new(0, 250 * 1000 * 1000)))
            .unwrap();
        convo_arc.lock().unwrap().sessions.insert(src.clone(), sess);
        sctx.clis.insert(src.clone(), (sk, Arc::clone(&convo_arc)));
        let (newcli, flag) = wrapping_tubepair(sk, Tube::Sock(Arc::new(s))).unwrap(); // Wrap this tube up in client to meet crypto

        //Create client conn stuff
        let mut addrs = HashSet::new();
        addrs.insert(addr_to_connect_to.clone());
        let (rbtube, _rbtube) = Tube::pair(true); // not used, emulates the down node
        let mut rcoreci = conn_main.ci.lock().unwrap();
        *rcoreci = ConnInfo::new((rbtube, None, 1.0, rand_pubnode()), Instant::now());
        rcoreci.recvd -= Duration::new(350, 0); //pretend it's been > 5 minutes
        let mut rbackups = conn_main.backups.lock().unwrap();
        *rbackups = vec![ConnInfo::new(
            (newcli, None, 0.1, rand_pubnode()),
            Instant::now(),
        )];
        rbackups[0].flag = Some(Arc::new(AtomicBool::new(true)));
        rbackups[0].node.address = addr_to_connect_to.clone();
        rbackups[0].node.key = srvctx.keys.sign.pk.clone();
        rbackups[0].node.bkey = srvctx.keys.bx.pk.clone();
        let bblob = [];
        let opts = Some((&mut rbackups[0], &bblob[..])); //the backup and slice we want to use
        debug!("Poll rolling timeouty main");
        let res = conn_main.poll_roll(&mut rcoreci, &clictx, true, &addrs, opts);
        if let NodeState::SentNodedown(ref mut time_sent) = &mut rcoreci.state {
            *time_sent -= Duration::new(16, 0); //now pretend we're 16 seconds later
        } else {
            panic!("Bad main state {:?}", res);
        }

        //ok now try proposing new. We short circuit this by creating a dummy node
        let socket2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let node2addr = socket2.local_addr().unwrap();
        let srv2ctx = test_context(true, node2addr.port(), None, "deleteme_srv2bktest").0;
        let node = crate::Node {
            key: srv2ctx.keys.sign.pk,
            bkey: srv2ctx.keys.bx.pk,
            address: crate::NodeAddr::Sockaddr(node2addr),
        };
        let dbk = crate::db_key(&node.bkey, 0, b"rttc");
        let mut cacheval = [0; 16];
        (&mut cacheval[..8]).copy_from_slice(&crate::now_as_bin_seconds()[..]);
        (&mut cacheval[8..]).copy_from_slice(&crate::u64_bytes((0.1 as f64).to_bits())[..]);
        clictx.save_node(node.clone()).unwrap();
        clictx.cache.insert(&dbk[..], &cacheval[..]).unwrap(); //this will prevent requests from going to establish RTT
        debug!("Poll rolling prop main on {}", node2addr);
        let opts = Some((&mut rbackups[0], &bblob[..])); //the backup and slice we want to use
        let res = conn_main.poll_roll(&mut rcoreci, &clictx, true, &addrs, opts);
        debug!(
            "Done poll rolling prop main {} next the final roll",
            res.as_ref().unwrap()
        );
        //ok now try proposed_time_elapsed - note that we need a thread to respond to the function
        if let NodeState::Proposed {
            when: ref mut time_sent,
            rollover: _,
            round: _,
            count: _,
            prev: _,
        } = &mut rcoreci.state
        {
            *time_sent -= Duration::new(16, 0); //pretend we're 16 seconds later
        } else {
            panic!("Bad main state");
        }
        let th2 = thread::spawn(move || {
            debug!("WAITING FOR session_msg RECV");
            let mut rawbuf = [0; 1024];
            let (buflen, src) = sctx.sock.recv_from(&mut rawbuf).unwrap();
            sctx.session_msg(&src, &rawbuf[..buflen]).unwrap(); //Process the roll message
            debug!("PROCESSED session_msg");
            sctx
        });
        let opts = Some((&mut rbackups[0], &bblob[..])); //the backup and slice we want to use
        let res = conn_main.poll_roll(&mut rcoreci, &clictx, true, &addrs, opts);
        debug!(
            "Done poll rolling final roll main {} rcorecitube {}",
            res.is_some(),
            rcoreci.tube
        );
        let mut sctx = th2.join().unwrap();
        assert!(sctx.convos.iter().next().unwrap().1.lock().unwrap().primary); //see if it got promoted
        debug!("rbackups[0] state {:?}", discriminant(&rbackups[0].state));

        //now pretend the backup's down
        rbackups[0].recvd -= Duration::new(350, 0); //pretend it's been > 5 minutes
        debug!("Poll rolling timeouty backup");
        addrs.insert(rbackups[0].node.address.clone());
        conn_main.poll_roll(&mut rbackups[0], &clictx, true, &addrs, None);
        if let NodeState::SentNodedown(ref mut time_sent) = &mut rbackups[0].state {
            *time_sent -= Duration::new(16, 0); //now pretend we're 16 seconds later
        } else {
            panic!("Bad bk state {:?}", discriminant(&rbackups[0].state));
        }
        //make yet another bogus node to roll to
        let mut node = rand_node();
        let socket3 = UdpSocket::bind("127.0.0.1:0").unwrap();
        node.address = crate::NodeAddr::Sockaddr(socket3.local_addr().unwrap());
        let dbk = crate::db_key(&node.bkey, 0, b"rttc");
        let mut cacheval = [0; 16];
        (&mut cacheval[..8]).copy_from_slice(&crate::now_as_bin_seconds()[..]);
        (&mut cacheval[8..]).copy_from_slice(&crate::u64_bytes((0.1 as f64).to_bits())[..]);
        clictx.save_node(node).unwrap();
        clictx.cache.insert(&dbk[..], &cacheval[..]).unwrap(); //this will prevent requests from going to establish RTT
        conn_main.poll_roll(&mut rbackups[0], &clictx, true, &addrs, None);
        if let NodeState::Proposed {
            when: ref mut wen,
            rollover: _,
            round: _,
            count: _,
            prev: _,
        } = &mut rbackups[0].state
        {
            *wen -= Duration::new(16, 0); //pretend we're 16 seconds later
        } else {
            panic!("Bad bk2 state");
        }
        debug!("Proposed. Now spawning roll handler");
        let th2 = thread::spawn(move || {
            let mut rawbuf = [0; 1024];
            let (buflen, src) = sctx.sock.recv_from(&mut rawbuf).unwrap();
            let sres = sctx.session_msg(&src, &rawbuf[..buflen]);
            log_err!(&sres, "smsgtest");
            sres.unwrap(); //Process the roll message
            sctx
        });
        conn_main.poll_roll(&mut rbackups[0], &clictx, true, &addrs, None);
        th2.join().unwrap();
        debug!(
            "PROCESSED CONN_ROLL. WAITING FOR MESSAGE ON {}",
            socket3.local_addr().unwrap()
        );
        //see if we get the roll command
        let mut rawbuf = [0; 1024];
        socket3.set_read_timeout(Some(Duration::new(1, 0))).unwrap();
        let (buflen, _src) = socket3.recv_from(&mut rawbuf).unwrap();
        debug!("GOT MSG LEN {}", buflen);
        assert!(buflen > 64);

        //cleanup
        flag.store(false, Relaxed);
        fs::remove_dir_all("deleteme_srvbktest").unwrap_or(());
        fs::remove_dir_all("deleteme_srv2bktest").unwrap_or(());
        fs::remove_dir_all("deleteme_clibktest").unwrap_or(());
    }
    // INTEGRATION TESTS
    //Helper functions, mainly to act as an HTTP client
    fn do_data_req(url: &str, bod: &str, csrftoken: &str, meth: &str) -> String {
        let ct = "application/json";
        String::from_utf8(do_req(url, bod.as_bytes(), ct, "", csrftoken, meth).unwrap()).unwrap()
    }
    //Generic HTTP synchronous client method. Returns the body received
    fn do_req(url: &str, bod: &[u8], d: &str, cid: &str, t: &str, method: &str) -> SfRes<Vec<u8>> {
        let mut bytez = vec![];
        let c = Client::new();
        let mut r = c.request(Method::from_bytes(method.as_bytes()).unwrap(), url);
        r = r.header("csrftoken", t).header("cid", cid);
        let ct = "content-type";
        let mut s = r.header(ct, d).body(bod.to_vec()).send().unwrap();
        if !s.status().is_success() {
            return Err(SfErr::SendError);
        };
        s.read_to_end(&mut bytez).unwrap();
        Ok(bytez)
    }
    //Simple GET request decoding response as JSON
    fn get_json(url: &str) -> Value {
        reqwest::get(url).unwrap().json().unwrap()
    }
    //Simple GET request, providing CSRF token
    fn get_url(url: &str, csrftoken: &str) -> String {
        let r = Client::new().get(url).header("csrftoken", csrftoken).send();
        r.unwrap().text().unwrap()
    }
    //Looping GET requests for /nextnode, ignoring notices and acks
    fn next_msg(url: &str, csrftoken: &str) -> Value {
        let starttime = Instant::now();
        loop {
            let st = get_url(url, csrftoken);
            info!("{} {} {}", url, st, starttime.elapsed().as_secs());
            assert!(starttime.elapsed() < Duration::from_secs(4));
            let res: Value = serde_json::from_str(&st).unwrap();
            let ro = res.as_object().unwrap();
            let m = ro.get("msg").unwrap();
            let mp = ro.get("midpoint");
            if !m.as_object().unwrap().get("notice").is_some()
                && !mp.unwrap().as_object().unwrap().get("ack").is_some()
            {
                return res;
            }
        }
    }
    //Looping GET requests for /nextnode, ignoring notices and acks and newcon and blank text
    fn next_real_msg_json(url: &str, csrftoken: &str) -> Value {
        loop {
            let res = next_msg(url, csrftoken);
            let ro = res.as_object().unwrap();
            let m = ro.get("msg").unwrap().as_object().unwrap();
            if m.get("newcon").is_none()
                && (m.get("text").is_none() || m.get("text").unwrap().as_str().unwrap().len() > 0)
            {
                return res;
            }
        }
    }
    //Gets an ent message or panics
    fn next_ent_msg(url: &str, csrftoken: &str) {
        let msg = next_real_msg_json(url, csrftoken);
        let o = msg.as_object().unwrap();
        let mdp = o.get("midpoint").unwrap().as_object().unwrap();
        mdp.get("ent").unwrap();
    }
    //Looping GET requests for a midpoint notice
    fn fetch_mpm_json_sync(url: &str, csrftoken: &str) -> Value {
        let starttime = Instant::now();
        loop {
            let res: Value = serde_json::from_str(&get_url(url, csrftoken)).unwrap();
            info!("{} {} {}", url, res, starttime.elapsed().as_secs());
            assert!(starttime.elapsed() < Duration::from_secs(4));
            let mp = res.as_object().unwrap().get("midpoint");
            if mp.unwrap().as_object().unwrap().len() > 0 {
                return res;
            }
        }
    }
    //Converts a json byte array [1,2,3... into a base64 string
    fn serdejarr_to_b64(jarrwrap: Option<&Value>) -> String {
        let jarr = jarrwrap.unwrap().as_array().unwrap();
        let u8vec: Vec<u8> = jarr.iter().map(|v| v.as_u64().unwrap() as u8).collect();
        base64::encode_config(&u8vec, URL_SAFE_NO_PAD)
    }
    //MAIN INTEGRATION TESTS - Runs 4 local nodes and 2 clients, then tests chatting between them.
    #[test]
    fn chat_test() {
        init_logger();
        //Setup stuff; create all the contexes and start all the instances as threads
        fs::remove_dir_all("deleteme_sf_testdata").unwrap_or(());
        //rm the cache directory
        let cashdir = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
        let cp = cashdir.to_str().unwrap_or(".");
        let cachepath: PathBuf = [&cp, "schadnfreude"].iter().collect(); // cache_dir/schadnfreude/port/convoid
        fs::remove_dir_all(&cachepath).unwrap_or(());
        fs::create_dir("deleteme_sf_testdata").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_relay1").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_relay2").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_meet1").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_meet2").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_cli1").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_cli2").unwrap_or(());
        fs::create_dir("deleteme_sf_testdata/deleteme_cli3").unwrap_or(());
        let relay1_context =
            test_context(true, 10001, None, "deleteme_sf_testdata/deleteme_relay1").0;
        let relay2_context =
            test_context(true, 10002, None, "deleteme_sf_testdata/deleteme_relay2").0;
        let meet1_context =
            test_context(true, 10003, None, "deleteme_sf_testdata/deleteme_meet1").0;
        let meet2_context =
            test_context(true, 10004, None, "deleteme_sf_testdata/deleteme_meet2").0;
        let m1_k = Some(meet1_context.keys.sign.pk.clone());
        let (cli1_context, cli1_recvr) =
            test_context(false, 10005, m1_k, "deleteme_sf_testdata/deleteme_cli1");
        let m2_k = Some(meet2_context.keys.sign.pk.clone());
        let (cli2_context, cli2_recvr) =
            test_context(false, 10006, m2_k, "deleteme_sf_testdata/deleteme_cli2");
        let (cli3_context, cli3_recvr) =
            test_context(false, 10007, None, "deleteme_sf_testdata/deleteme_cli3");
        info!("cli3 sk {}", crate::b64sk(&cli3_context.keys.sign.pk));
        //client 4 is client 2's other device
        fs::create_dir("deleteme_sf_testdata/deleteme_cli4").unwrap_or(());
        let (c4snd, cli4_recvr) = unbounded();

        let wd = PathBuf::from("deleteme_sf_testdata/deleteme_cli4");
        let k4 = cli2_context.keys.clone();
        let mi = crate::MeetInfo::Address(meet2_context.keys.sign.pk.clone());
        let ad4 = SocketAddr::from(([127, 0, 0, 1], 10008));
        let cli4_context = Arc::new(SfContext::new(k4, c4snd, 1, false, ad4, wd, mi, None));
        cli4_context.tcp.store(true, Relaxed); // make it TCP

        //Statically prefill nodes except for relay2 (will manually add).
        for nd_ctx in &[&relay1_context, &meet1_context, &meet2_context] {
            for dest_ctx in &[
                &relay1_context,
                &relay2_context,
                &meet1_context,
                &meet2_context,
                &cli1_context,
                &cli2_context,
                &cli3_context,
                &cli4_context,
            ] {
                let n = crate::Node {
                    key: nd_ctx.keys.sign.pk.clone(),
                    bkey: nd_ctx.keys.bx.pk.clone(),
                    address: crate::NodeAddr::Sockaddr(nd_ctx.addr.clone()),
                };
                dest_ctx.save_node(n).unwrap();
            }
        }
        //client 3 needs to know about everybody because 3 needs to pick a meet
        let n = crate::Node {
            key: relay2_context.keys.sign.pk.clone(),
            bkey: relay2_context.keys.bx.pk.clone(),
            address: crate::NodeAddr::Sockaddr(relay2_context.addr.clone()),
        };
        cli3_context.save_node(n).unwrap();
        relay2_context
            .nodes
            .remove(&meet2_context.keys.sign.pk)
            .unwrap(); //so he can learn something
        relay2_context
            .nodes
            .remove(&meet1_context.keys.sign.pk)
            .unwrap();
        let _ = std::fs::remove_file("contacts.bin"); //remove any old files to ensure the contacts/nodes are a clean slate
        let _ = std::fs::remove_file("nodes.bin"); //we do this again since sometimes another thread can create one of these files after our test ends

        //spawn node threads
        for nd_ctx in &[
            &relay1_context,
            &relay2_context,
            &meet1_context,
            &meet2_context,
        ] {
            let config = YamlLoader::load_from_str("max_db_size: 50000\nmax_convo: 40000")
                .unwrap()
                .remove(0);
            let context = Arc::clone(nd_ctx);
            thread::Builder::new()
                .name("testnode".to_string())
                .spawn(move || run_node(context, &config))
                .unwrap();
        }
        info!("Spawned nodes");
        thread::sleep(Duration::from_millis(100)); //give em a lil bit to start up
        let relay2_clone = Arc::clone(&relay2_context);
        //Just testing netmon with relay2
        let netmon_threadh = thread::Builder::new()
            .name("nmon".to_string())
            .spawn(move || crate::run_netmonitor(&relay2_clone, unbounded().0))
            .unwrap();
        let cli1key = cli1_context.keys.sign.pk.clone();
        let cli2key = cli2_context.keys.sign.pk.clone();
        let cli3key = cli3_context.keys.sign.pk.clone();
        let cli3_context2 = Arc::clone(&cli3_context);
        //spawn clients
        info!("Spawning clients then polling until ports open...");
        let preclis = Instant::now();
        let (chan1, chan2, chan3) = (unbounded(), unbounded(), unbounded());
        let chan3snd2 = chan3.0.clone(); //another sender for the net mon thread
        thread::Builder::new()
            .name("cli1test".to_string())
            .spawn(move || run_cli(cli1_context, cli1_recvr, chan1.0, chan1.1))
            .unwrap();
        thread::Builder::new()
            .name("cli2test".to_string())
            .spawn(move || run_cli(cli2_context, cli2_recvr, chan2.0, chan2.1))
            .unwrap();
        thread::Builder::new()
            .name("cli3test".to_string())
            .spawn(move || run_cli(cli3_context, cli3_recvr, chan3.0, chan3.1))
            .unwrap();
        //start a netmon thread for a client, to auto-find meet hosts
        thread::Builder::new()
            .name("nmoncli3".to_string())
            .spawn(move || crate::run_netmonitor(&cli3_context2, chan3snd2))
            .unwrap();
        while TcpStream::connect("127.0.0.1:10005").is_err()
            || TcpStream::connect("127.0.0.1:10006").is_err()
            || TcpStream::connect("127.0.0.1:10007").is_err()
        {
            thread::sleep(Duration::from_millis(10));
            assert!(preclis.elapsed() < Duration::from_secs(5));
        }
        let clis_open = preclis.elapsed();

        //Get CSRF tokens, test self-info
        let mi1 = get_json("http://127.0.0.1:10005/myinfo");
        let myinfo1 = mi1.as_object().unwrap();
        assert_eq!(
            myinfo1.get("mykey").unwrap().as_str().unwrap(),
            b64spk(&cli1key).as_str()
        );
        let csrftok1 = myinfo1.get("csrftoken").unwrap().as_str().unwrap();
        let mi2 = get_json("http://127.0.0.1:10006/myinfo");
        let myinfo2 = mi2.as_object().unwrap();
        assert_eq!(
            myinfo2.get("mykey").unwrap().as_str().unwrap(),
            b64spk(&cli2key).as_str()
        );
        let csrftok2 = myinfo2.get("csrftoken").unwrap().as_str().unwrap();

        let mut mi3 = get_json("http://127.0.0.1:10007/myinfo");
        while mi3.as_object().unwrap().get("errnomeet").is_some() {
            assert!(preclis.elapsed() < Duration::from_secs(6));
            thread::sleep(Duration::from_millis(500));
            mi3 = get_json("http://127.0.0.1:10007/myinfo");
        }
        info!("3 {}", mi3);
        let myinfo3 = mi3.as_object().unwrap();
        let mut csrftok3 = myinfo3.get("csrftoken").unwrap().as_str().unwrap(); // should be an errnomeet

        //Test first run setting meet
        let mu = "http://127.0.0.1:10007/name"; //URL to post
        let ctpost = do_data_req(mu, "bob", &csrftok3, "POST");
        assert_eq!(&ctpost, "ok");

        //Test regenerating CSRF token
        let c3 = do_data_req("http://127.0.0.1:10007/csrftoken", "", &csrftok3, "POST");
        csrftok3 = &c3;
        let clis_working = preclis.elapsed();
        info!("CSRF tokens {}... (port open elapsed: {}.{:03} total until requests complete: {}.{:03})",
            csrftok1, clis_open.as_secs(), clis_open.subsec_millis(), clis_working.as_secs(), clis_working.subsec_millis());

        //Test to ensure network bootup (syncing with self, starting meet listeners etc.) should be fast
        let mut msg1 = next_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        let mut dur1 = preclis.elapsed();
        info!("m1 {} {}.{:03}", msg1, dur1.as_secs(), dur1.subsec_millis());
        let mut msg2 = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2); //newcon
        let mut dur2 = preclis.elapsed();
        info!("m2 {} {}.{:03}", msg2, dur2.as_secs(), dur2.subsec_millis());
        let mut msg3 = next_msg("http://127.0.0.1:10007/nextmsg", &csrftok3);
        let dur3 = preclis.elapsed();
        info!("m3 {} {}.{:03}", msg3, dur3.as_secs(), dur3.subsec_millis());
        assert!(dur3 < Duration::from_secs(5));
        netmon_threadh.thread().unpark();
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        next_ent_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        next_ent_msg("http://127.0.0.1:10007/nextmsg", &csrftok3);

        thread::sleep(Duration::from_millis(100)); //just .1 seconds to allow propagation of meet info

        //Test 404
        let fourohfour = get_url("http://127.0.0.1:10005/doesnotexist", "");
        info!("404 {}", fourohfour.to_string());
        assert_eq!(fourohfour, "");

        //Test static files
        assert!(get_url("http://127.0.0.1:10006/", "").len() > 500);
        assert!(get_url("http://127.0.0.1:10006/sf.css", "").len() > 500);
        assert!(get_url("http://127.0.0.1:10006/index.js", "").len() > 500);
        assert!(get_url("http://127.0.0.1:10006/qrcode.min.js", "").len() > 500);
        assert!(get_url("http://127.0.0.1:10006/jsQR.js", "").len() > 500);

        //Test contact addition
        let ctxbefore = get_json("http://127.0.0.1:10005/contacts"); // get before
        info!("ctxbefore {}", ctxbefore.to_string());
        let ctxbo = ctxbefore.as_object().unwrap().get("contacts").unwrap();
        assert_eq!(ctxbo.as_object().unwrap().len(), 1);
        let ctxctx = ctxbo.as_object().unwrap().get(b64spk(&cli1key).as_str());
        let ct1 = ctxctx.unwrap().as_object().unwrap();
        assert_eq!(ct1.get("name").unwrap().as_str().unwrap(), "");
        //first overwrite our own name
        let dat = json!({"ct": b64spk(&cli1key), "name": "meeee"}).to_string();
        let ctpost = do_data_req("http://127.0.0.1:10005/contacts", &dat, &csrftok1, "POST");
        info!("ctpost ourselves {}", ctpost);
        //and see if it got overwritten
        let ctxupdated = get_json("http://127.0.0.1:10005/contacts"); // get before
        info!("ctxupdated {}", ctxupdated.to_string());
        let ctxuo = ctxupdated.as_object().unwrap().get("contacts").unwrap();
        let ctxu = ctxuo.as_object().unwrap().get(b64spk(&cli1key).as_str());
        let ctu = ctxu.unwrap().as_object().unwrap();
        assert_eq!(ctu.get("name").unwrap().as_str().unwrap(), "meeee");

        //then add a new contact
        let dat = json!({"ct": b64spk(&cli2key), "name": "myfriend"}).to_string();
        let ctpost = do_data_req("http://127.0.0.1:10005/contacts", &dat, &csrftok1, "POST");
        let ctxafter = get_json("http://127.0.0.1:10005/contacts"); //get after
        info!("Contact: {} (after: {})", ctpost, ctxafter.to_string());
        assert_eq!(ctpost, "ok".to_string()); // test adding
        let ctxao = ctxafter.as_object().unwrap();
        let ctxctxa = ctxao.get("contacts").unwrap().as_object().unwrap();
        assert_eq!(ctxctxa.len(), 2); //a new one!

        //Test starting a chat
        info!("now starting chat");
        let prechat = Instant::now();
        let jt = json!({ "tgt": b64spk(&cli2key) }).to_string();
        let sc = do_data_req("http://127.0.0.1:10005/startconvo", &jt, &csrftok1, "POST");
        let t = prechat.elapsed();
        assert!(t < Duration::from_secs(5));
        info!("{} in {}.{:03}", sc, t.as_secs(), t.subsec_millis());
        let startconvo_json: Value = serde_json::from_str(&sc).unwrap();
        let scobj = startconvo_json.as_object().unwrap();
        let convoid_b64 = scobj.get("convoid").unwrap().as_str().unwrap();
        //Ok, now let's see if both got the new convo msg (will timeout if not)
        let prechalert = Instant::now();
        next_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        dur1 = prechalert.elapsed();
        info!("total {}.{:03}", dur1.as_secs(), dur1.subsec_millis());
        next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        dur2 = prechalert.elapsed();
        info!("total {}.{:03}", dur2.as_secs(), dur2.subsec_millis());
        assert!(dur2 < Duration::from_secs(2));
        netmon_threadh.thread().unpark();
        //and both get the enter for both
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        next_ent_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        next_ent_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);

        //Test bad CSRF token
        let d = json!({"cid": &convoid_b64, "text": "bad csrf"}).to_string();
        let bcu = "http://127.0.0.1:10005/sendmsg";
        let aj = "application/json";
        let badcsrf = do_req(bcu, &d.as_bytes(), aj, "", "abcdef", "POST");
        assert!(badcsrf.is_err());

        //Test sending a message over the convo
        info!("now sending msg");
        let sd = json!({"cid": &convoid_b64, "text": "hello world"}).to_string();
        let sentmsg = do_data_req("http://127.0.0.1:10005/sendmsg", &sd, &csrftok1, "POST");
        info!("sent message res: {}", sentmsg);
        let get_ack_msg = get_url("http://127.0.0.1:10005/sendmsg", &csrftok1);
        info!("after sent: {}", get_ack_msg);
        msg2 = next_real_msg_json("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let o2 = msg2.as_object().unwrap();
        let o2m = o2.get("msg").unwrap().as_object().unwrap();
        assert_eq!(o2m.get("text").unwrap().as_str().unwrap(), "hello world");

        //Test convos call and that conversation ID matches
        let conv2 = get_json("http://127.0.0.1:10006/convos");
        info!("convos2 {}? {}", convoid_b64, conv2.to_string());
        let c2ob = conv2.as_object().unwrap();
        let c2c = c2ob.get("convos").unwrap().as_object().unwrap();
        let c2id = c2c.get(convoid_b64).unwrap();
        assert!(c2id.as_object().unwrap().contains_key("participants"));
        info!("convos2 passed");

        //Test sending reply message
        let m2d = json!({"cid": &convoid_b64, "text": "donuts"}).to_string();
        let sentmsg2 = do_data_req("http://127.0.0.1:10006/sendmsg", &m2d, &csrftok2, "POST");
        info!("sent message res: {}", sentmsg2);
        msg1 = next_real_msg_json("http://127.0.0.1:10005/nextmsg", &csrftok1);
        let nm1o = msg1.as_object().unwrap();
        let nm1m = nm1o.get("msg").unwrap().as_object().unwrap();
        assert_eq!(nm1m.get("text").unwrap().as_str().unwrap(), "donuts");

        //Test audio snippet for a call (1024 0x05's as a standin for audio data)
        let audurl = "http://127.0.0.1:10005/audio";
        let ctyp = "application/octet-stream";
        let pres = do_req(audurl, &[5; 1024], ctyp, &convoid_b64, &csrftok1, "POST").unwrap();
        info!("precv {}", String::from_utf8(pres).unwrap());
        let mut precv: Vec<u8> = vec![];
        while precv.len() != 1024 {
            let nmu = "http://127.0.0.1:10006/nextmsg";
            precv = do_req(nmu, &[][..], "", "", &csrftok2, "GET").unwrap();
            info!("precv len {} {:?}", precv.len(), &precv[..]);
        }
        assert_eq!(&precv[..], &[5; 1024][..]); //make sure data was good

        //Test video snippet (1900 0x09's as a standin for vid data)
        let vidurl = "http://127.0.0.1:10005/video";
        let ctyp = "application/octet-stream";
        let sid = "12X_81kbuMg";
        let c = Client::new();
        let mut r = c.request(Method::from_bytes(b"POST").unwrap(), vidurl);
        r = r.header("csrftoken", csrftok1).header("cid", convoid_b64);
        r = r.header("sid", sid).header("p", "0");
        r = r.header("splits", "1600,300").header("content-type", ctyp);
        let s = r.body([9; 1900].to_vec()).send();
        let mut bytez = vec![];
        s.unwrap().read_to_end(&mut bytez).unwrap();
        assert_eq!(&b"ok"[..], &bytez[..]);
        let nmu = "http://127.0.0.1:10006/nextmsg";
        while precv.len() != 1188 {
            precv = do_req(nmu, &[][..], "", "", &csrftok2, "GET").unwrap();
            info!("precv len {} {:?}", precv.len(), &precv[..]);
        }
        assert_eq!(&[9; 1188][..], &precv[..]);
        while precv.len() != 1600 - 1188 {
            precv = do_req(nmu, &[][..], "", "", &csrftok2, "GET").unwrap();
            info!("precv len {} {:?}", precv.len(), &precv[..]);
        }
        assert_eq!(&[9; 1600 - 1188][..], &precv[..]);
        while precv.len() != 300 {
            precv = do_req(nmu, &[][..], "", "", &csrftok2, "GET").unwrap();
            info!("precv len {} {:?}", precv.len(), &precv[..]);
        }
        assert_eq!(&[9; 300][..], &precv[..]);

        //Test request vid
        let rvidurl = "http://127.0.0.1:10005/requestvid";
        let rv = do_req(rvidurl, sid.as_bytes(), "", &convoid_b64, &csrftok1, "POST").unwrap();
        assert_eq!(&b"ok"[..], &rv[..]);
        let rrecv = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let rro = rrecv.as_object().unwrap();
        let msg_o = rro.get("msg").unwrap().as_object().unwrap();
        let vid_r = msg_o.get("vid_request").unwrap().as_str().unwrap();
        assert_eq!(vid_r, sid);

        //Test stop vid
        let rvidurl = "http://127.0.0.1:10005/vidstop";
        let rv = do_req(rvidurl, sid.as_bytes(), "", &convoid_b64, &csrftok1, "POST").unwrap();
        assert_eq!(&b"ok"[..], &rv[..]);
        let rrecv = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let rro = rrecv.as_object().unwrap();
        let msg_o = rro.get("msg").unwrap().as_object().unwrap();
        let vid_r = msg_o.get("vid_stop").unwrap().as_str().unwrap();
        assert_eq!(vid_r, sid);

        //Test starting a chat with n3
        info!("now opening connection with");
        let prechat = Instant::now();
        let sdat = json!({ "tgt": b64spk(&cli3key) }).to_string();
        let scu = "http://127.0.0.1:10005/startconvo";
        let sc3 = do_data_req(scu, &sdat, &csrftok1, "POST");
        let t = prechat.elapsed();
        assert!(t < Duration::from_secs(2));
        info!("{} in {}.{:03}", sc3, t.as_secs(), t.subsec_millis());
        let startconvo3_json: Value = serde_json::from_str(&sc3).unwrap();
        let sc3o = startconvo3_json.as_object().unwrap();
        let convoid3_b64 = sc3o.get("convoid").unwrap().as_str().unwrap();
        //Now see if we sync'd client 3's display name
        let ctx3 = get_json("http://127.0.0.1:10005/contacts"); //get after
        info!("Contact 3 {}", ctx3);
        let ctxao3 = ctx3.as_object().unwrap();
        let ctxo3 = ctxao3.get("contacts").unwrap().as_object().unwrap();
        assert!(ctxo3.len() > 2);

        //Ok, now let's see if both got the new convo msg (will timeout if not)
        let prechalert3 = Instant::now();
        next_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        let md1 = prechalert3.elapsed();
        info!("msg1 {}.{:03}", md1.as_secs(), md1.subsec_millis());
        next_msg("http://127.0.0.1:10007/nextmsg", &csrftok3);
        let md3 = prechalert3.elapsed();
        info!("msg3 {}.{:03}", md3.as_secs(), md3.subsec_millis());
        assert!(md3 < Duration::from_secs(2));
        //and get both ent messages on both
        next_ent_msg("http://127.0.0.1:10007/nextmsg", &csrftok3);
        next_ent_msg("http://127.0.0.1:10007/nextmsg", &csrftok3);
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        let ctx3up = get_json("http://127.0.0.1:10007/contacts"); // get before
        info!("ctx3up {}", ctx3up.to_string());
        let ctx3uo = ctx3up.as_object().unwrap().get("contacts").unwrap();
        let ctxu = ctx3uo.as_object().unwrap().get(b64spk(&cli1key).as_str());
        let ct3 = ctxu.unwrap().as_object().unwrap();
        assert_eq!(ct3.get("name").unwrap().as_str().unwrap(), "meeee");

        //Now invite n3 to chat with n2
        let ivd = json!({"cid": &convoid3_b64, "scid": &convoid_b64});
        let ivurl = "http://127.0.0.1:10005/sendinvite";
        let sentinviter = do_data_req(ivurl, &ivd.to_string(), &csrftok1, "POST");
        info!("Sent invite, resp {}", sentinviter);

        //Now let's see if n3 got it
        msg3 = next_real_msg_json("http://127.0.0.1:10007/nextmsg", &csrftok3);
        let md3 = prechalert3.elapsed();
        info!("msg3 {}.{:03}", md3.as_secs(), md3.subsec_millis());
        let nm3o = msg3.as_object().unwrap();
        let msg_json = nm3o.get("msg").unwrap().as_object().unwrap();
        let invitecidb64 = serdejarr_to_b64(msg_json.get("invitecid"));
        let meetkeyb64 = serdejarr_to_b64(msg_json.get("meetkey"));
        let sesskeyb64 = serdejarr_to_b64(msg_json.get("sesskey"));
        let seedb64 = serdejarr_to_b64(msg_json.get("seed"));
        let meetaddr = msg_json.get("meetaddr").unwrap().as_str().unwrap();

        //Now accept the invite
        let aid = json!({
            "cid": &invitecidb64,
            "meetkey": &meetkeyb64,
            "sesskey": &sesskeyb64,
            "seed": &seedb64,
            "meetaddr": &meetaddr
        })
        .to_string();
        let aiurl = "http://127.0.0.1:10007/acceptinvite";
        let acceptinviter = do_data_req(aiurl, &aid, &csrftok3, "POST");
        info!("Sent accept invite, resp {}", acceptinviter);
        next_ent_msg("http://127.0.0.1:10006/nextmsg", &csrftok2); //ent msgs
        next_ent_msg("http://127.0.0.1:10005/nextmsg", &csrftok1); //ent msgs
        msg2 = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        info!("msg2 {}", msg2);
        let nm2fro = msg2.get("from").unwrap().as_str().unwrap();
        assert_eq!(nm2fro, b64spk(&cli3key).as_str());
        msg1 = next_msg("http://127.0.0.1:10005/nextmsg", &csrftok1);
        info!("msg1 {}", msg1);
        let nm1fro = msg1.get("from").unwrap().as_str().unwrap();
        assert_eq!(nm1fro, b64spk(&cli3key).as_str());

        //Now see if client 2 sync'd client 3's display name
        let ctx2 = get_json("http://127.0.0.1:10006/contacts"); //get after
        info!("Contact 2 {}", ctx2);
        let ctxao2 = ctx2.as_object().unwrap();
        let ctxo2 = ctxao2.get("contacts").unwrap().as_object().unwrap();
        assert!(ctxo2.len() > 2);

        //Test spinning up another device
        let precli4 = Instant::now();
        let cli4_cl = Arc::clone(&cli4_context);
        let chan4 = unbounded();
        thread::Builder::new()
            .name("cli4test".to_string())
            .spawn(move || run_cli(cli4_cl, Some(cli4_recvr), chan4.0, chan4.1))
            .unwrap();
        while TcpStream::connect("127.0.0.1:10008").is_err() {
            thread::sleep(Duration::from_millis(10));
            assert!(precli4.elapsed() < Duration::from_secs(5));
        }
        //Get CSRF token
        let mi4 = get_json("http://127.0.0.1:10008/myinfo");
        let myinfo4 = mi4.as_object().unwrap();
        let csrftok4 = myinfo4.get("csrftoken").unwrap().as_str().unwrap();
        let cli4_working = preclis.elapsed();
        info!(
            "CSRF token 4 {}... (delay: {}.{:03})",
            csrftok4,
            cli4_working.as_secs(),
            cli4_working.subsec_millis()
        );
        //Look for the messages
        let prechat4 = Instant::now();
        let mut got_hello = false;
        let mut got_donuts = false;
        while !got_hello || !got_donuts {
            let nextmsg4 = next_msg("http://127.0.0.1:10008/nextmsg", &csrftok4);
            let md4 = prechat4.elapsed();
            assert!(md4 < Duration::from_secs(5));
            info!("nextmsg4 {}.{:03}", md4.as_secs(), md4.subsec_millis());
            let chatmsg_json = nextmsg4.as_object().unwrap();
            let cmm = chatmsg_json.get("msg").unwrap().as_object().unwrap();
            cmm.get("text").map(|txt| {
                let msgstr4 = txt.as_str().unwrap().to_string();
                got_hello = got_hello || &msgstr4 == "hello world";
                got_donuts = got_donuts || &msgstr4 == "donuts";
            });
        }

        //Test sending a file. First get a file and wrap in a multipart upload
        let fcontents = base64::decode(&"\
            IyBzY2hhZG5mcmV1ZGUKCkFuIGVuZC10by1lbmQgZW5jcnlwdGVkLCBhbm9ueW1vdXMgb25pb24tcm91dGluZywgZnVsbHkgZGVjZW50cmFsaXplZCwgYXVkaW8vdmlk\
            ZW8vb2ZmbGluZSBtZXNzYWdpbmcgcGxhdGZvcm0gYnVpbHQgZm9yIGJvdGggY29tbXVuaWNhdGlvbnMgYW5kIGFwcGxpY2F0aW9uIHNlY3VyaXR5IGFuZCBwZXJmb3Jt\
            YW5jZS4KCiAgICBTZWN1cmUKICAgIENvbW11bmljYXRpb25zCiAgICBIb3BwaW5nOgogICAgQW5vbnltb3VzCiAgICBEZWxpdmVyeS4KICAgIE5vdwogICAgRm9yCiAg\
            ICBSZWxheGluZywKICAgIEVuam95CiAgICBVbmRlcmNvdmVyCiAgICBEaWdpdGFsCiAgICBFeGNlbGxlbmNlCgojIyBHb2FsCgpTY2hhZG5mcmV1ZGUncyBnb2FsIGlz\
            IHRvIHByb3ZpZGUgYWxsIHRoZSBhZHZhbnRhZ2VzIG9mIGEgdHJhZGl0aW9uYWwgc2VjdXJlIG1lc3NhZ2luZyBwbGF0Zm9ybSB3aXRob3V0IHRoZSBwaXRmYWxscyBv\
            ZiBjZW50cmFsbHktY29udHJvbGxlZCBzZXJ2aWNlcyBhbmQgdnVsbmVyYWJsZSB0ZWNobm9sb2dpZXMuIFNwZWNpZmljYWxseSwgd2Ugc2VlayB0byBhbm9ueW1pemUg\
            ZW5kcG9pbnRzLCBoaWRlIElQIGFkZHJlc3NlcywgcHJldmVudCB1c2VyIGVudW1lcmF0aW9uLCBlbGltaW5hdGUgc2luZ2xlIHBvaW50cyBvZiBmYWlsdXJlLCBhbmQg\
            Y2F0ZWdvcmljYWxseSBwcmV2ZW50IHRoZSBtb3N0IGNvbW1vbiBhbmQgc2V2ZXJlIHZ1bG5lcmFiaWxpdHkgY2xhc3Nlcywgd2hpbGUgcHJlc2VydmluZyB0aGUgcGVy\
            Zm9ybWFuY2UsIGNvbnZpZW5pZW5jZSwgYW5kIGZlYXR1cmVzIG9mIG90aGVyIHNlY3VyZSBtZXNzYWdpbmcgYXBwbGljYXRpb25zLgoKIyMgSW1wbGVtZW50YXRpb24K\
            ClNjaGFkbmZyZXVkZSB1c2VzIGEgbmV0d29yayBvZiBub2RlcyB0byBwZXJmb3JtIGl0cyBhbm9ueW1pemluZyBmdW5jdGlvbmFsaXR5LiBUaGUgc2NoYWRuZnJldWRl\
            IGNsaWVudCBzZWxlY3RzIG9uZSBvciBtb3JlIG1lZXQgbm9kZXMgdG8gdXNlIGxvbmctdGVybSwgYnV0IG1heSBjaGFuZ2UgaXQgbGF0ZXIgaWYgZGVzaXJlZC4gVGhl\
            IG1lZXQgbm9kZSBob2xkcyBvZmZsaW5lIGVuY3J5cHRlZCBtZXNzYWdlcyBhbmQgZmlsZXMsIGJ1dCBjYW5ub3QgcmVhZCB0aGVtIG9yIHNlZSB3aG8gaXMgYWNjZXNz\
            aW5nIHRoZW0uIFRoZSBzY2hhZG5mcmV1ZGUgY2xpZW50IG5ldmVyIGNvbm5lY3RzIGRpcmVjdGx5IHRvIGl0cyBtZWV0IG5vZGUsIGluc3RlYWQgc2V0dGluZyB1cCB0\
            dW5uZWxzIHRocm91Z2ggb25lIG9yIG1vcmUgcmVsYXkgbm9kZXMgZmlyc3QuIExpa2V3aXNlLCByZWxheXMgYXJlIHVzZWQgdG8gY29ubmVjdCB0byBvdGhlciBjbGll\
            bnRzJyBtZWV0IG5vZGVzIGFzIHdlbGwuCgpTY2hhZG5mcmV1ZGUgdXNlcyBhIG1lc3NhZ2UtYmFzZWQgbW9kZWwgcmlkaW5nIG92ZXIgVURQIGJ5IGRlZmF1bHQgZm9y\
            IG1heGltdW0gcGVyZm9ybWFuY2UuIFRoaXMgYWxsb3dzIGl0IHRvIHJlZHVjZSByb3VuZCB0cmlwIHRpbWVzIGNvbWJpbmluZyBjcnlwdG9ncmFwaGljIGFuZCB0cmFk\
            aXRpb25hbCBjb25uZWN0aW9uIGluaXRpYXRpb24sIGFuZCBiZXR0ZXIgc3VwcG9ydCByZWFsdGltZSBhdWRpby92aWRlbyBjb21tdW5pY2F0aW9ucywgYWxsb3dpbmcg\
            cGFja2V0IGRyb3BzLiBJdCBkb2VzIHJlc3VsdCBpbiBtb3JlIGNvbXBsZXggY29kZSB0byBoYW5kbGUgbW9yZSByZWxpYWJsZSBkZWxpdmVyeSB3aGVuIGRlc2lyZWQu\
            CgpDb250YWN0cyBhcmUgaWRlbnRpZmllZCBieSBwdWJsaWMga2V5LiBTdWNoIGtleXMgYXJlIHVzZWQgd2hlbiBzZXR0aW5nIHVwIGEgY29udmVyc2F0aW9uLCB3aGlj\
            aCBlc3RhYmxpc2hlcyBhIHN5bW1ldHJpYyBrZXkgdG8gYXV0aGVudGljYXRlIGFuZCBlbmNyeXB0IG1lc3NhZ2VzIGJldHdlZW4gdHdvIGVuZHBvaW50cy4gVGhpcyBr\
            ZXkgbWF5IGJlIHNoYXJlZCBsYXRlciB3aXRoIGFkZGl0aW9uYWwgY29udGFjdHMgdG8gaW52aXRlIHRoZW0gdG8gdGhlIGNvbnZlcnNhdGlvbiBhbmQgZW5hYmxlIHRo\
            ZW0gdG8gc2VlIHRoZSBncm91cCBtZXNzYWdlcy4KCiMjIENvbXBhcmlzb24K".repeat(10)).unwrap();
        let sent_hash = wr_crypto_hash_sha256(&fcontents); // we'll make sure we get the same thing on the other end
        let sent_len = fcontents.len();
        info!("Uploading {} bytes", sent_len);
        let mut put_uri = "http://127.0.0.1:10005/".to_string();
        put_uri.push_str(&convoid_b64);
        put_uri.push_str(&"/README.md");
        let mut uploadmsg = vec![];
        let c = Client::new();
        let r = c.request(Method::from_bytes(b"PUT").unwrap(), &put_uri);
        let s = r.header("x-lock", "true").body(fcontents.clone()).send();
        s.unwrap().read_to_end(&mut uploadmsg).unwrap();
        assert!(uploadmsg.len() == 0);
        loop {
            //Now see if we get the file notification
            msg2 = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
            let im = msg2.as_object().unwrap().get("msg");
            let inner_msg = im.unwrap().as_object().unwrap();
            if inner_msg.get("path").is_some()
                && inner_msg.get("path").unwrap().as_str().unwrap() == "README.md"
            {
                //skip conn notifs
                break;
            }
        }
        let nm2o = msg2.as_object().unwrap();
        let nm2mo = nm2o.get("msg").unwrap().as_object().unwrap();
        assert_eq!(nm2mo.get("fid").unwrap().as_i64().unwrap(), 0);

        //Now see if we can get the file, twice to also test cache
        let mut downfile_uri = "http://127.0.0.1:10006/download?".to_string();
        downfile_uri.push_str(&convoid_b64);
        downfile_uri.push_str(".0");
        for _ in 0..2 {
            let downfile_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET").unwrap();
            info!("Got {} bytes back from download", downfile_res.len());
            assert_eq!(sent_len, downfile_res.len());
            assert_eq!(wr_crypto_hash_sha256(&downfile_res), sent_hash); //and if it matches up
        }

        //Now upload the file as a shared file
        let aos = "application/octet-stream";
        let uploadmsg = do_req(&put_uri, &fcontents, aos, "", &csrftok1, "PUT").unwrap();
        info!("upload res: {}", String::from_utf8(uploadmsg).unwrap());

        //See if it got uploaded as shared
        loop {
            //Now see if we get the file notification
            msg2 = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
            let im = msg2.as_object().unwrap().get("msg");
            let inner_msg = im.unwrap().as_object().unwrap();
            if inner_msg.get("path").is_some()
                && inner_msg.get("path").unwrap().as_str().unwrap() == "README.md"
            {
                //skip conn notifs
                break;
            }
        }
        let mo = msg2.as_object().unwrap().get("msg");
        let m = mo.unwrap().as_object().unwrap();
        assert_eq!(m.get("fid").unwrap().as_i64().unwrap(), 1);
        assert!(m.get("shared").unwrap().as_bool().unwrap());

        //Now see if we can get the shared file
        let mut downfile_uri = "http://127.0.0.1:10006/download?".to_string();
        downfile_uri.push_str(&convoid_b64);
        downfile_uri.push_str(".1");
        let downfile_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET").unwrap();
        info!("Got {} bytes back from download", downfile_res.len());
        assert_eq!(wr_crypto_hash_sha256(&downfile_res), sent_hash); //and if it matches up

        //Now test download as WebDAV
        let mut downfile_uri = "http://127.0.0.1:10006/".to_string();
        downfile_uri.push_str(&convoid_b64);
        downfile_uri.push_str("/README.md");
        let downfile_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET").unwrap();
        info!("Got {} bytes back from download", downfile_res.len());
        assert_eq!(sent_len, downfile_res.len());
        assert_eq!(wr_crypto_hash_sha256(&downfile_res), sent_hash); //and if it matches up

        //Now see if we can move the shared file
        let mut move_uri = "http://127.0.0.1:10005/".to_string();
        move_uri.push_str(&convoid_b64);
        let mut dest_uri = move_uri.clone();
        move_uri.push_str(&"/README.md");
        dest_uri.push_str(&"/NEWREADME.md");
        let mut uploadmsg = vec![];
        let c = Client::new();
        let r = c.request(Method::from_bytes(b"MOVE").unwrap(), &move_uri);
        let s = r.header("destination", &dest_uri).send();
        s.unwrap().read_to_end(&mut uploadmsg).unwrap();
        assert!(uploadmsg.len() == 0);
        info!("Renamed");
        //See if it got moved
        let midpoint_msg = fetch_mpm_json_sync("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let mpmo = midpoint_msg.as_object().unwrap();
        let mpmm = mpmo.get("midpoint").unwrap().as_object().unwrap();
        assert_eq!(mpmm.get("op").unwrap().as_str().unwrap(), "ume");

        //See if the bytes still match
        downfile_uri = "http://127.0.0.1:10006/download?".to_string();
        downfile_uri.push_str(&convoid_b64);
        downfile_uri.push_str(".2");
        let downfile_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET").unwrap();
        info!("Got {} bytes back from download", downfile_res.len());
        assert_eq!(wr_crypto_hash_sha256(&downfile_res), sent_hash); //and if it matches up

        //Now see if we can list the files
        let mut listfiles_uri = "http://127.0.0.1:10006/listfiles?".to_string();
        listfiles_uri.push_str(&convoid_b64);
        let listfiles_res = get_url(&listfiles_uri, "");
        info!("listfiles_res {}", listfiles_res);
        let mut files_res = listfiles_res.split_terminator("\n").map(|j| {
            let v: Value = serde_json::from_str(j).unwrap();
            v
        });
        let o = files_res.next().unwrap();
        let l = o.as_object().unwrap().get("lock");
        assert!(!l.unwrap().as_bool().unwrap());
        assert!(files_res.next().is_none());

        //Now truncate the file
        let mut truncate_uri = "http://127.0.0.1:10005/truncate?".to_string();
        truncate_uri.push_str(&convoid_b64);
        truncate_uri.push_str(".2.2048");
        let deletemsg = do_req(&truncate_uri, &[][..], "", "", &csrftok1, "POST").unwrap();
        info!("truncate res: {}", String::from_utf8(deletemsg).unwrap());
        //Now see if we can get it and whether it's right
        let mut downfile_uri = "http://127.0.0.1:10006/download?".to_string();
        downfile_uri.push_str(&convoid_b64);
        downfile_uri.push_str(".2");
        let downfile_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET").unwrap();
        info!("Got {} bytes back from download", downfile_res.len());
        assert_eq!(&downfile_res[..], &fcontents[..2048]); //Check shortened contents

        //Now lock, test locked, & unlock the file
        let mut newreaduri = "http://127.0.0.1:10005/".to_string();
        newreaduri.push_str(&convoid_b64);
        newreaduri.push_str(&"/NEWREADME.md");
        do_req(&newreaduri, &[][..], "", "", &csrftok1, "LOCK").unwrap();
        let mut newreaduri6 = "http://127.0.0.1:10006/".to_string();
        newreaduri6.push_str(&convoid_b64);
        newreaduri6.push_str(&"/NEWREADME.md");
        let badlock = do_req(&newreaduri6, &[][..], "", "", &csrftok2, "LOCK");
        assert!(badlock.is_err());
        do_req(&newreaduri, &[][..], "", "", &csrftok1, "UNLOCK").unwrap();

        //Now delete the file
        let deletemsg = do_req(&newreaduri, &[][..], "", "", &csrftok1, "DELETE").unwrap();
        info!("delete res: {}", String::from_utf8(deletemsg).unwrap());
        //And see if it's gone
        let downfile_del_res = do_req(&downfile_uri, &[][..], "", "", &csrftok2, "GET");
        assert!(downfile_del_res.is_err()); //download should fail

        //See if we got the notice on the other side
        let midpoint_msg = fetch_mpm_json_sync("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let mpmo = midpoint_msg.as_object().unwrap();
        let mpmm = mpmo.get("midpoint").unwrap().as_object().unwrap();
        assert_eq!(mpmm.get("op").unwrap().as_str().unwrap(), "del");

        //Make a directory and check that it works
        let mut ndurl = "http://127.0.0.1:10005/".to_string();
        ndurl.push_str(&convoid_b64);
        ndurl.push_str("/lolzy");
        let newdirm = do_req(&ndurl, &[][..], "", "", &csrftok1, "MKCOL").unwrap();
        assert!(newdirm.len() == 0);
        msg2 = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let im = msg2.as_object().unwrap().get("msg");
        let inner_msg = im.unwrap().as_object().unwrap();
        assert!(inner_msg.get("type").unwrap().as_str().unwrap() == "fold");
        assert!(inner_msg.get("path").unwrap().as_str().unwrap() == "lolzy");

        //Test nodes list
        let nodesj1 = get_json("http://127.0.0.1:10005/nodes");
        info!("nodesj1 {}", nodesj1);
        let nodes1 = nodesj1.as_object().unwrap();
        assert!(nodes1.len() >= 3);

        //Test PROPPATCH
        let ppbod = "<?xml version=\"1.0\" encoding=\"utf-8\" ?><D:propertyupdate xmlns:D=\"DAV:\" \
        xmlns:Z=\"urn:schemas-microsoft-com:\"><D:set><D:prop> \
        <Z:Win32CreationTime>Fri, 11 Dec 2020 21:09:55 GMT</Z:Win32CreationTime> \
        <Z:Win32FileAttributes>00000020</Z:Win32FileAttributes></D:prop></D:set></D:propertyupdate>";
        do_req(&ndurl, ppbod.as_bytes(), "", "", &csrftok1, "PROPPATCH").unwrap();
        do_req(&ndurl, ppbod.as_bytes(), "", "", &csrftok1, "PROPFIND").unwrap();

        //Test leaving conversation
        let mut leaveurl = "http://127.0.0.1:10005/".to_string();
        leaveurl.push_str(&convoid_b64);
        let shutdown1m = do_data_req(&leaveurl, "", &csrftok1, "LEAVE");
        info!("leave message 1 res: {}", shutdown1m);

        //and see if we get notice on the others
        let msg = next_real_msg_json("http://127.0.0.1:10006/nextmsg", &csrftok2);
        let o = msg.as_object().unwrap();
        let mdp = o.get("midpoint").unwrap().as_object().unwrap();
        mdp.get("lve").unwrap();

        //Now see if we can re-read all our messages with /msghistory?convoid.seq
        let mut msghistory_uri = "http://127.0.0.1:10006/msghistory?".to_string();
        msghistory_uri.push_str(&convoid_b64);
        let msghistory_res = get_json(&msghistory_uri);
        info!("msghistory: {}", msghistory_res);
        loop {
            // this loop will block, causing a timeout assertion failure, if we don't get the donuts we expect
            let history_obj = next_msg("http://127.0.0.1:10006/nextmsg", &csrftok2);
            let history_m = history_obj.as_object().unwrap().get("msg");
            let history_msg = history_m.unwrap().as_object().unwrap();
            if history_msg.get("text").is_some()
                && history_msg.get("text").unwrap().as_str().unwrap() == "donuts"
            {
                //skip conn notifs
                break;
            }
        }

        //Test shutdown
        let shutdown1m = do_data_req("http://127.0.0.1:10005/shutdown", "", &csrftok1, "POST");
        info!("shutdown message 1 res: {}", shutdown1m);
        let shutdown2m = do_data_req("http://127.0.0.1:10006/shutdown", "", &csrftok2, "POST");
        info!("shutdown message 2 res: {}", shutdown2m);
        let shutdown3m = do_data_req("http://127.0.0.1:10007/shutdown", "", &csrftok3, "POST");
        info!("shutdown message 3 res: {}", shutdown3m);
        let shutdown4m = do_data_req("http://127.0.0.1:10008/shutdown", "", &csrftok4, "POST");
        info!("shutdown message 4 res: {}", shutdown4m);

        //Attempt to clean up generated files
        fs::remove_dir_all("deleteme_sf_testdata").unwrap_or(());
        fs::remove_dir_all(&cachepath).unwrap_or(());
        assert!(cli4_context.tcp.load(Relaxed)); //Ensure it didn't fall back to UDP
    }
}
