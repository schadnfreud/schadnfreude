//Wraps various kinds of lower-level sending/receiving capabilities (like TCP/UDP sockets)
//a series of tubes
use crate::innermain::*;
use std::fmt::Display;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use super::*;

pub fn set_required_sockopts(sock: &UdpSocket) {
    #[cfg(windows)]
    {
        let mut nope = 0 as u32; //This little monstrous block tells Windows to not kill our entire
        use std::os::windows::io::AsRawSocket; //server when it gets a sad ICMP reply.
        extern "system" {
            fn ioctlsocket(s: u64, cmd: u32, argp: *mut u32);
        }
        unsafe { ioctlsocket(sock.as_raw_socket(), 0x9800000C, &mut nope) }; //SIO_UDP_CONNRESET
    }
}

#[derive(Debug)]
pub enum Tube {
    //"Are you pondering what I'm pondering?"
    //"I think so, Brain, but isn't that why they invented tube socks?"
    Sock(Arc<UdpSocket>),
    Tagged((Arc<UdpSocket>, u8)), //adds tag to received data
    Tagger((Sender<Vec<u8>>, Receiver<Vec<u8>>, AtomicUsize, u8)), //adds tag to sent data
    Udp((Arc<UdpSocket>, SocketAddr)),
    Tcp((Arc<Mutex<TcpStream>>, Option<SocketAddr>)),
    //Sending vecs over a channel is faster than a localhost sockpair
    Channel((Sender<Vec<u8>>, Receiver<Vec<u8>>, AtomicUsize)),
}

impl Tube {
    pub fn sock_clone(pair: (&Arc<UdpSocket>, SocketAddr)) -> Tube {
        let (existingsock, addr) = pair;
        Tube::Udp((Arc::clone(existingsock), addr))
    }
    pub fn tagger_wrap(tub: Tube, tag: u8) -> SfRes<Tube> {
        if let Tube::Channel((snd, rcv, usz)) = tub {
            return Ok(Tube::Tagger((snd, rcv, usz, tag)));
        }
        error!("tagger_wrap with non-channel?");
        Err(SfErr::NotAllowed) //This should never happen
    }
    pub fn udp_connect(addr: &SocketAddr) -> SfRes<Tube> {
        let s = if addr.is_ipv4() {
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        } else {
            UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        }?;
        set_required_sockopts(&s);
        s.connect(&addr)?;
        log_err!(s.set_read_timeout(Some(Duration::new(0, 250_000_000))), "");
        let t = Tube::Sock(Arc::new(s));
        debug!("UDP connect {}", t);
        Ok(t)
    }
    //returns sender, tagged receiver
    pub fn dual_udp_tag(addr: &SocketAddr, tag: u8) -> SfRes<(Tube, Tube)> {
        let tube1 = Tube::udp_connect(addr)?;
        let tube2 = if let Tube::Sock(ref s) = &tube1 {
            Tube::Tagged((Arc::clone(s), tag))
        } else {
            panic!("this shouldn't ever happen")
        };
        debug!("Dual UDP connect {} <-> {}", tube1, addr);
        Ok((tube1, tube2))
    }
    pub fn socks_connect(addr: &SocketAddr, prox: &(u8, SocketAddr)) -> SfRes<Tube> {
        let (ref socksver, ref paddr) = *prox;
        if let Tube::Tcp((tmutx, ad)) = Tube::tcp_connect(paddr)? {
            let p = addr.port();
            let (phigh, plow) = (((p >> 8) & 0xFF) as u8, (p & 0xFF) as u8);
            let mut t = tmutx.lock()?;
            let mut req = [0; 22];
            let mut good = false;
            if *socksver == 5 {
                t.write_all(&[5, 1, 0][..])?; //version ID/method sync request for no auth
                let mut methresp = [0, 0];
                t.read_exact(&mut methresp)?; //see rfc1928
                if methresp[1] != 0 {
                    return Err(SfErr::ProxyFailed);
                }
                if let IpAddr::V4(ip) = addr.ip() {
                    (&mut req[..4]).copy_from_slice(&[5, 1, 0, 1][..]); //v5, connect, reserved, ip4
                    (&mut req[4..8]).copy_from_slice(&ip.octets()[..]);
                    (&mut req[8..10]).copy_from_slice(&[phigh, plow][..]);
                    t.write_all(&req[..10])?;
                    t.read_exact(&mut req[..10])?;
                    good = req[1] == 0 && req[3] == 1; // good if reply field is X'00' succeeded and IPv4
                } else if let IpAddr::V6(ip6) = addr.ip() {
                    (&mut req[..4]).copy_from_slice(&[5, 1, 0, 4][..]); //v5, connect, reserved, ip6
                    (&mut req[4..20]).copy_from_slice(&ip6.octets()[..]);
                    (&mut req[20..22]).copy_from_slice(&[phigh, plow][..]);
                    t.write_all(&req[..22])?;
                    t.read_exact(&mut req[..4])?; //up to address type
                    good = req[1] == 0; // good if reply field is X'00' succeeded and IPv6
                    let lenrest = if req[3] == 4 { 18 } else { 6 };
                    t.read_exact(&mut req[..lenrest])?;
                }
            } else if let IpAddr::V4(ip) = addr.ip() {
                (&mut req[..4]).copy_from_slice(&[4, 1, phigh, plow][..]); //socksv4, connect, port
                (&mut req[4..8]).copy_from_slice(&ip.octets()[..]); //ip
                t.write_all(&req[..9])?; //and a trailing 0 for no username
                t.read_exact(&mut req[..8])?; //read response
                good = req[1] == 90; // good if CD (result) code is 90: request granted
            }
            if good {
                drop(t);
                return Ok(Tube::Tcp((tmutx, ad)));
            }
        }
        Err(SfErr::ProxyFailed)
    }
    pub fn tcp_connect(addr: &SocketAddr) -> SfRes<Tube> {
        let dur = Duration::new(3, 0); //TCP sockets are assumed to be slower
        let t = TcpStream::connect_timeout(addr, dur)?;
        debug!("TCP connected to {}", addr);
        t.set_nodelay(true)?;
        let rwdur = Duration::new(60, 0);
        t.set_read_timeout(Some(rwdur.clone()))?;
        t.set_write_timeout(Some(rwdur))?;
        let laddr = t.local_addr().ok();
        Ok(Tube::Tcp((Arc::new(Mutex::new(t)), laddr)))
    }
    pub fn tcp_accept(listener: &TcpListener) -> SfRes<Tube> {
        let (t, addr) = listener.accept()?;
        debug!("TCP accepted from {}", addr);
        t.set_nodelay(true)?;
        let rwdur = Duration::new(60, 0);
        t.set_read_timeout(Some(rwdur.clone()))?;
        t.set_write_timeout(Some(rwdur))?;
        let laddr = t.local_addr().ok();
        Ok(Tube::Tcp((Arc::new(Mutex::new(t)), laddr)))
    }
    pub fn pair(slower: bool) -> (Tube, Tube) {
        let (s1, r1) = unbounded();
        let (s2, r2) = unbounded();
        let dur = if slower {
            1000000 //1s timeout
        } else {
            250 * 1000 //0.25s timeout
        };
        let chan_a = Tube::Channel((s1, r2, AtomicUsize::new(dur)));
        let chan_b = Tube::Channel((s2, r1, AtomicUsize::new(dur)));
        (chan_a, chan_b)
    }
    pub fn send(&self, buf: &[u8]) -> SfRes<()> {
        trace!("{} sending {}", &self, buf.len());
        if buf.len() > 65535 {
            return Err(SfErr::MtuFail);
        }
        Ok(match self {
            Tube::Sock(sock) => {
                sock.send(buf)?;
            }
            Tube::Tagged((sock, _tag)) => {
                sock.send(buf)?;
            }
            Tube::Udp((sock, saddr)) => {
                sock.send_to(buf, *saddr)?;
            }
            Tube::Tcp((stream_mut, _addr)) => {
                let val = buf.len();
                let mut sendable = Vec::with_capacity(val + 2);
                sendable.push((val & 0xFF) as u8); //first 2 bytes are little endian length
                sendable.push(((val >> 8) & 0xFF) as u8);
                sendable.extend_from_slice(buf); //copying into vec and sending together is faster than 2 sends
                let mut stream = stream_mut.lock()?;
                stream.write_all(&sendable)?; //send length and buf
                trace!("{} sent {}", &self, buf.len());
            }
            Tube::Channel(ch) => ch.0.send(buf.to_vec())?,
            Tube::Tagger((snd, _rcv, _to, tag)) => {
                let mut bufv = Vec::with_capacity(buf.len() + 1);
                bufv.push(*tag);
                bufv.extend_from_slice(buf);
                snd.send(bufv)?
            }
        })
    }
    pub fn send_vec(&self, mut buf: Vec<u8>) -> SfRes<()> {
        match self {
            Tube::Channel(ch) => {
                trace!("{} vsending {}", &self, buf.len());
                Ok(ch.0.send(buf)?) //skips a copy
            }
            Tube::Tagger((snd, _rcv, _to, tag)) => {
                trace!("{} vsending {}", &self, buf.len());
                buf.insert(0, *tag);
                Ok(snd.send(buf)?)
            }
            _ => self.send(&buf),
        }
    }
    pub fn recv_vec(&self) -> SfRes<Vec<u8>> {
        let mut buf = [0; 65536]; // leave space for very large data packets just in case
        let (rcvlen, _src) = match self {
            Tube::Sock(sock) => sock,
            Tube::Udp((sock, _)) => sock,
            Tube::Tagged((sock, tag)) => {
                buf[0] = *tag;
                let (rcvlen, _src) = sock.recv_from(&mut buf[1..])?;
                trace!("{} received {}", &self, rcvlen);
                return Ok(buf[0..(rcvlen + 1)].to_vec());
            }
            Tube::Tcp((stream_mut, _addr)) => {
                trace!("{} locking", &self);
                let mut stream = stream_mut.lock()?;
                trace!("{} locked", &self);
                stream.read_exact(&mut buf[0..2])?; //read length
                let chunklen = (buf[0] as u16 + ((buf[1] as u16) << 8)) as usize;
                trace!("{} receiving {}", &self, chunklen);
                let mut chunk = vec![0; chunklen];
                stream.read_exact(&mut chunk)?;
                trace!("{} received {}", &self, chunklen);
                return Ok(chunk);
            }
            Tube::Channel(ch) => {
                let usec = ch.2.load(Relaxed);
                let dur = Duration::new((usec / 1000000) as u64, (usec % 1000000) as u32 * 1000);
                let rcvd = ch.1.recv_timeout(dur)?;
                trace!("{} received {}", &self, rcvd.len());
                return Ok(rcvd);
            }
            Tube::Tagger(ch) => {
                let usec = ch.2.load(Relaxed);
                let dur = Duration::new((usec / 1000000) as u64, (usec % 1000000) as u32 * 1000);
                let rcvd = ch.1.recv_timeout(dur)?;
                trace!("{} received {}", &self, rcvd.len());
                return Ok(rcvd);
            }
        }
        .recv_from(&mut buf)?;
        trace!("{} received {}", &self, rcvlen);
        Ok(buf[0..rcvlen].to_vec())
    }
    pub fn set_timeout(&self, to: Duration) -> SfRes<()> {
        match self {
            Tube::Sock(sock) => sock.set_read_timeout(Some(to))?,
            Tube::Tagged((sock, _t)) => sock.set_read_timeout(Some(to))?,
            Tube::Udp((sock, _addr)) => sock.set_read_timeout(Some(to))?,
            Tube::Tcp((stream_mut, _)) => {
                trace!("Tube timeout {}.{:03}", to.as_secs(), to.subsec_millis());
                stream_mut.lock()?.set_read_timeout(Some(to))?;
                trace!("Tube {} done setting timeout", &self);
            }
            Tube::Channel(ch) => {
                let v = to.as_secs() as usize * 1000000 + to.subsec_micros() as usize;
                ch.2.store(v, Relaxed);
            }
            Tube::Tagger(ch) => {
                let v = to.as_secs() as usize * 1000000 + to.subsec_micros() as usize;
                ch.2.store(v, Relaxed);
            }
        }
        Ok(())
    }
    //Splits off the receive channel of the tube into a new tube; for e.g. a forwarding thread.
    //After calling this, it is not recommended to receive on the original tube or send on the new!
    pub fn split_off_recv(&mut self) -> SfRes<Tube> {
        Ok(match self {
            Tube::Sock(sock) => Tube::Sock(Arc::clone(sock)),
            Tube::Tagged((sock, tag)) => Tube::Tagged((Arc::clone(sock), *tag)),
            Tube::Udp((sock, addr)) => Tube::Udp((Arc::clone(sock), addr.clone())),
            Tube::Tcp((t, a)) => {
                trace!("TCP splitting recv");
                let res = Tube::Tcp((Arc::new(Mutex::new(t.lock()?.try_clone()?)), a.clone()));
                trace!("TCP done splitting recv");
                res
            }
            Tube::Channel(c) => Tube::Channel((c.0.clone(), c.1.clone(), usclone(&c.2))),
            Tube::Tagger(c) => Tube::Tagger((c.0.clone(), c.1.clone(), usclone(&c.2), c.3)),
        })
    }
    //Clones the send channel of the tube into a new tube; for e.g. a forwarding thread.
    //After calling this, it is not recommended to receive on the new tube!
    pub fn clone_sender(&self) -> SfRes<Tube> {
        Ok(match self {
            Tube::Sock(sock) => Tube::Sock(Arc::clone(sock)),
            Tube::Tagged((sock, tag)) => Tube::Tagged((Arc::clone(sock), *tag)),
            Tube::Udp((sock, addr)) => Tube::Udp((Arc::clone(sock), addr.clone())),
            Tube::Tcp((t, a)) => Tube::Tcp((Arc::clone(&t), a.clone())),
            Tube::Channel(c) => Tube::Channel((c.0.clone(), c.1.clone(), usclone(&c.2))),
            Tube::Tagger(c) => Tube::Tagger((c.0.clone(), c.1.clone(), usclone(&c.2), c.3)),
        })
    }
}
impl Display for Tube {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Tube::Sock(s) => s
                .local_addr()
                .and_then(|l| Ok((l, s.peer_addr()?)))
                .map(|(l, p)| write!(f, "{} S {}", l, p))
                .unwrap_or_else(|_| "?".fmt(f)),
            Tube::Udp((s, p)) => s
                .local_addr()
                .map(|l| write!(f, "{} - {}", l, p))
                .unwrap_or_else(|_| "?".fmt(f)),
            Tube::Tagged((s, tag)) => s
                .local_addr()
                .and_then(|l| Ok((l, s.peer_addr()?)))
                .map(|(l, p)| write!(f, "{} - {} tag {}", l, p, tag))
                .unwrap_or_else(|_| "?".fmt(f)),
            Tube::Tcp((_, s)) => s
                .map(|a| write!(f, "TCP {}", a))
                .unwrap_or_else(|| "?".fmt(f)),
            Tube::Channel(_c) => "channel".fmt(f),
            Tube::Tagger(t) => "tagger ".fmt(f).and_then(|_| t.3.fmt(f)),
        }
    }
}
//why don't AtomicUsize's have clone anyway?
fn usclone(old_usize: &AtomicUsize) -> AtomicUsize {
    AtomicUsize::new(old_usize.load(Relaxed))
}
