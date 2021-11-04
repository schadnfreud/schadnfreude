// Stream functionality in schadnfreude; specifically for file transfers.
use crate::innermain::*;
use std::time::Instant;

use super::*;

//Congestion control configuration constants
const MIN_INFLIGHT: usize = 4; //always keep this many packets (~payload kb) inflight
const BURST_SIZE: usize = 10; //initial burst size; must be > 4!
const PAYLOAD_SIZE: usize = 1024;
const STABILIZE_CUTOFF_MUL: f64 = 2.0; //if rtt > this * base while accelerating, stop
const RUN_LOW_BOUND: f64 = 1.2; //if rtt < this * base while running, increase inflight
const RUN_MAX_MULT: f64 = 1.1; //don't increase more than this in one RTT while running
const RUN_HIGH_BOUND: f64 = 1.5; //if rtt > this * base while running, decrease inflight
const RUN_MIN_MULT: f64 = 0.7; //don't decrease more than this in one RTT while running
const RTO_RTT_MULT: f64 = 1.5; //Retransmit timeout = this * running RTT
const RTT_RUNNING_AVG_FACTOR: f64 = 0.2; //RTTest = RTTest * this + old_rtt * (1 - this)

pub struct WriteStream<T: Write> {
    pub streamid: i64,
    pub f: T,
    pub start: i64,
    pub offset: i64,
    pub overwritable: i64,
    pub cache: BTreeMap<i64, Vec<u8>>,
}
impl<T: Write> WriteStream<T> {
    pub fn new(streamid: i64, f: T, overwritable: i64, start: i64) -> Self {
        Self {
            streamid: streamid,
            f: f,
            start: start,
            offset: 0,
            overwritable: overwritable,
            cache: BTreeMap::new(),
        }
    }
    pub fn write_inner(&mut self, buff: &[u8]) -> SfRes<usize> {
        debug!("{} Swrite {}+{}", self.streamid, self.offset, buff.len());
        let overwritten = self.overwritable.min(buff.len() as i64); //how much did we overwrite?
        self.overwritable -= overwritten; //runway just got shorter if not already 0
        self.f.write_all(&buff)?;
        self.offset += buff.len() as i64;
        Ok(buff.len() - overwritten as usize)
    }
    //Stream write! Is it in order? Write it!
    pub fn stream_write(&mut self, t: &Tube, key: Option<&SecKey>, doc: &Document) -> SfRes<usize> {
        let off = doc.get_i64("o")?;
        let buff = doc.get_binary_generic("b")?;
        let mut written = 0;
        if off == self.offset {
            written += self.write_inner(buff)?; //Sends data to next layer. Updates self.offset etc.
            loop {
                if let Some(c) = self.cache.remove(&self.offset) {
                    written += self.write_inner(&c)?; //updates self.offset
                } else {
                    break;
                }
            }
        } else if off > self.offset {
            // there's a gap. Ack the gap and cache if not already cached
            self.cache.entry(off).or_insert_with(|| buff.clone());
        }
        //Either way, ack it. Figure out all our gaps from our offset and cached chunks
        let mut acks_bson: Vec<Bson> = Vec::new();
        let mut start = 0;
        let mut end = self.offset;
        if self.cache.len() == 0 && buff.len() == 0 && off >= self.offset {
            end += 1; //end of stream; just like TCP, the FIN/EOF counts as a byte
        }
        for (offs, buf) in self.cache.iter() {
            if *offs != end {
                acks_bson.push(bson!([start, end]));
                start = *offs;
            }
            end = *offs + buf.len() as i64;
        }
        if start != end {
            acks_bson.push(bson!([start, end]));
        }
        let r = doc.get_i32("r").unwrap_or(0);
        send_ack(self.streamid, t, key, acks_bson, off, r)?;
        if written > 0 || (self.cache.len() == 0 && off >= self.offset) {
            Ok(written) //data recvd and not out of order
        } else {
            Err(SfErr::OutOfOrderErr)
        }
    }
}

pub struct Unacked {
    sends: Vec<Instant>,
    bdoc: Document,
}

#[derive(Copy, Clone)]
pub enum CongestionControlMode {
    Startup = 1,
    Accelerate,
    Run,
}

pub struct ReadStream<F: Read> {
    streamid: i64,
    f: F,
    seq: i64,
    unacked: BTreeMap<i64, Unacked>, // seq -> retransmits, lastretrans
    acked: BTreeMap<Instant, i64>,   // recvd -> recvd_seq only used in startup
    pub rttms: f64,
    baserttms: f64,
    congestion_mode: CongestionControlMode,
    last_adjusted_time: Instant,
    last_adjusted_window: f64,
    window: f64,
    pub lasts: Option<Instant>,
    pub lastr: Option<Instant>,
}
impl<F: Read> ReadStream<F> {
    pub fn new(streamid: i64, f: F, rttmsest: f64) -> Self {
        Self {
            streamid: streamid,
            f: f,
            seq: 0,
            unacked: BTreeMap::new(), // seq -> retransmits, lastretrans
            acked: BTreeMap::new(),   // recvd -> recvd_seq only used in startup
            rttms: rttmsest,
            baserttms: rttmsest,
            congestion_mode: CongestionControlMode::Startup,
            last_adjusted_time: Instant::now(),
            last_adjusted_window: BURST_SIZE as f64,
            window: BURST_SIZE as f64,
            lasts: None,
            lastr: None,
        }
    }
    //Checks whether this stream needs to resend data and sends it, or tells when next timeout is
    pub fn check_rto(&mut self, stuber: &Tube, k: Option<&SecKey>) -> (Duration, bool) {
        let rto = Duration::from_millis((self.rttms * 2.0) as u64);
        let r = self.lasts.and_then(|l| rto.checked_sub(l.elapsed()));
        if let Some(delay_diff) = r {
            (delay_diff, false) // we sent a packet less than rto ago, wait for reply
        } else {
            let dl = Duration::from_millis(((self.rttms + 200.0) * 10.0) as u64);
            let lr = self.lastr.map(|r| r.elapsed() > dl); //deadline = 10RTT+2s
            debug!("streamup send_stream start"); // last send > rto ago, so resend
            log_err!(self.send_stream(stuber, k, None), "sup");
            debug!("streamup send_stream done");
            (rto, lr.unwrap_or(false))
        }
    }
    pub fn send_stream(&mut self, tube: &Tube, k: Option<&SecKey>, l: Option<i64>) -> SfRes<usize> {
        let (sessionkey_opt, last_acked) = (k, l);
        self.lasts = Some(Instant::now());
        //If some sacked pkts weren't resent or elapsed > (sendcount + 0.5) * rtt, resend one
        for (iseq, ref mut unack) in self.unacked.range_mut(..) {
            //duration since last send. Sends always has at least one element in it from creation.
            let dur = dur_millis(&unack.sends.iter().rev().next().unwrap().elapsed());
            let resend = if last_acked.is_none() {
                dur > (unack.sends.len() as f64 + RTO_RTT_MULT + 1.0) * self.rttms.max(50.0) * 2.0
            } else {
                *iseq < last_acked.unwrap() && unack.sends.len() == 0
                    || dur > (unack.sends.len() as f64 + RTO_RTT_MULT) * self.rttms.max(10.0)
            };
            if resend {
                debug!("Gap {} s {} rtt {}", unack.sends.len(), iseq, self.rttms);
                unack.bdoc.insert("r", unack.sends.len() as i32); //retransmit # to track exact RTT
                unack.sends.push(Instant::now());
                let mut sendable = bdoc_to_u8vec(&unack.bdoc);
                if let Some(sessionkey) = sessionkey_opt {
                    sendable = wr_crypto_secretbox_easy(&sendable, &sessionkey);
                }
                tube.send(&sendable)?;
                return Ok(1);
            }
        }
        //otherwise read and send new packet
        let mut buf = [0; PAYLOAD_SIZE + CRYPTO_BOX_MACBYTES + 8];
        let seq = self.seq;
        debug!("SID {} trying to read len {}", self.streamid, buf.len());
        let bts = self.f.read(&mut buf[..])?; //read bytes
        debug!("New msg sid {} seq {} len {}", self.streamid, self.seq, bts);
        self.seq += bts as i64;
        let d = doc! {"s": self.streamid, "o": seq, "self": 0i32, "b": binary_bson(&buf[..bts])};
        let mut sendable = bdoc_to_u8vec(&d);
        if let Some(sessionkey) = sessionkey_opt {
            sendable = wr_crypto_secretbox_easy(&sendable, &sessionkey);
        }
        tube.send(&sendable)?;
        if bts == 0 {
            if self.unacked.len() == 0 {
                return Err(SfErr::IoErr(Error::new(ErrorKind::UnexpectedEof, "EOF")));
            }
            debug!("{} {}", self.streamid, self.unacked.keys().next().unwrap());
        } else {
            let u = Unacked {
                sends: vec![Instant::now()],
                bdoc: d,
            };
            self.unacked.insert(seq, u);
        }
        Ok(1)
    }

    //Reads from a ReadStream; handles tracking losses and retransmits as well as congestion control
    pub fn stream_read(&mut self, tube: &Tube, k: Option<&SecKey>, doc: &Document) -> SfRes<()> {
        let sacks = doc.get_array("sacks")?; //doc as passed in is an ack from remote side
        let acked_off = doc.get_i64("o")?;
        let rtnum = doc.get_i32("r")?;
        let recvd = Instant::now();
        self.lastr = Some(Instant::now());
        //Is it acks from a read? If so are we reading and do we still have stuff to read?
        debug!("stream_read sacks len: {}", sacks.len());
        let mut lastacked = None;
        for sack in sacks.iter() {
            let ack = sack.as_array().ok_or(SfErr::InvalidOp)?;
            if ack.len() < 2 {
                break; //invalid
            }
            let low = ack[0].as_i64().ok_or(SfErr::InvalidOp)?;
            let high = ack[1].as_i64().ok_or(SfErr::InvalidOp)?;
            if low < 0 || high < low {
                break; //invalid
            }
            if high > self.seq {
                return Err(SfErr::DoneErr); //other side acked FIN/EOF; we're done here!
            }
            while let Some((iseq, unack)) = self.unacked.range(low..high).next() {
                if *iseq == acked_off {
                    if let Some(inst) = unack.sends.iter().nth(rtnum as usize) {
                        let durms = dur_millis(&inst.elapsed()); //exact RTT for this send
                        debug!("s {} ack {} rt {}: {}", self.streamid, *iseq, rtnum, durms);
                        //calculate running round trip time estimate
                        self.baserttms = self.baserttms.min(durms); //base is always the min
                        self.rttms = durms * RTT_RUNNING_AVG_FACTOR
                            + self.rttms * (1.0 - RTT_RUNNING_AVG_FACTOR);
                        if let CongestionControlMode::Startup = self.congestion_mode {
                            self.acked.insert(recvd.clone(), *iseq); //maybe messy w/ losses
                        }
                    }
                }
                let rmseq = *iseq;
                self.unacked.remove(&rmseq);
            }
            lastacked = Some(high);
        }
        //Should we send & how much? Let's ask the congestion control algorithm.
        debug!(
            "CCM {} u {} a {} base {} r {} w {}",
            self.congestion_mode as u8,
            self.unacked.len(),
            self.acked.len(),
            self.baserttms,
            self.rttms,
            self.window
        );
        let mut sent: usize = 0;
        while self.unacked.len() < MIN_INFLIGHT && sent < MIN_INFLIGHT {
            sent += self.send_stream(tube, k, lastacked)?;
        }
        match &self.congestion_mode {
            CongestionControlMode::Startup => {
                while self.unacked.len() < BURST_SIZE && sent < 2 {
                    sent += self.send_stream(tube, k, lastacked)?;
                }
                if self.acked.len() < 2 {
                    debug!("stream_read su done");
                    return Ok(()); //Only received 0 or 1 acks. Can't estimate bandwidth.
                }
                let start = self.acked.iter().next().unwrap().0.clone(); //when we got the first
                let end = self.acked.iter().next_back(); //when we got the last
                                                         //unwrap is safe because acked.len > 0.
                if let Some(d) = end.unwrap().0.checked_duration_since(start) {
                    let num_packets_in_duration = (self.acked.len() - 1) as f64;
                    let pps = num_packets_in_duration / d.as_secs_f64();
                    let inflight_target = pps * self.baserttms; //possible inflight packets estimate
                    while sent < 2 && inflight_target as usize > self.unacked.len() {
                        sent += self.send_stream(tube, k, lastacked)?; //only send up to 2 tho
                    }
                    if self.acked.len() > BURST_SIZE - 1
                        || (self.acked.len() >= 4
                            && *self.acked.iter().next_back().unwrap().1
                                < (BURST_SIZE * PAYLOAD_SIZE) as i64)
                    {
                        self.rttms = self.baserttms; //generally ignore burst rtt's; they stacked up
                        self.last_adjusted_window = inflight_target; // set new target; could jump
                        self.window = self.unacked.len() as f64; //The window we were able to reach
                        self.acked.clear(); //not used anymore
                        debug!("CCM switching to Accelerate");
                        self.congestion_mode = CongestionControlMode::Accelerate;
                    }
                }
            }
            CongestionControlMode::Accelerate => {
                if self.rttms > self.baserttms * STABILIZE_CUTOFF_MUL {
                    debug!("CCM switching to Run");
                    self.last_adjusted_window = self.window; // we overestimated & slammed the tubes
                    self.last_adjusted_time = recvd; // so we stop now
                    self.congestion_mode = CongestionControlMode::Run; // and switch to run mode
                } else if self.window >= self.last_adjusted_window {
                    self.last_adjusted_time = recvd; //reached the end of natural acceleration
                    self.congestion_mode = CongestionControlMode::Run;
                } else {
                    self.window += 1.0; //keep accelerating
                    while sent < 2 && self.window as usize > self.unacked.len() {
                        sent += self.send_stream(tube, k, lastacked)?; //still only send max 2
                    }
                }
            }
            CongestionControlMode::Run => {
                if dur_millis(&self.last_adjusted_time.elapsed()) > self.baserttms {
                    self.last_adjusted_time = recvd;
                    self.last_adjusted_window = self.window;
                } else if self.rttms < self.baserttms * RUN_LOW_BOUND {
                    if self.window < self.last_adjusted_window * RUN_MAX_MULT {
                        self.window += 1.0;
                    }
                } else if self.rttms > self.baserttms * RUN_HIGH_BOUND {
                    if self.window > self.last_adjusted_window * RUN_MIN_MULT {
                        self.window -= 1.0;
                    }
                }
                while sent < 2 && self.window as usize > self.unacked.len() {
                    sent += self.send_stream(tube, k, lastacked)?; //still only send max 2
                }
            }
        }
        debug!("stream_read done");
        Ok(())
    }
}

//Figure out what to send or resend next, and send one packet from a ReadStream
pub fn send_ack(s: i64, t: &Tube, k: Option<&SecKey>, ack: Vec<Bson>, o: i64, r: i32) -> SfRes<()> {
    debug!("send_ack acks {:?}", ack);
    let mut bdoc_bin = bdoc_to_u8vec(&doc! {"s": s, "sacks": ack, "o": o, "r": r});
    if let Some(key) = k {
        bdoc_bin = wr_crypto_secretbox_easy(&bdoc_bin, key);
    }
    t.send_vec(bdoc_bin)?;
    Ok(())
}
