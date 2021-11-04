use log::{debug, error, info};
use std::io::{Cursor, Error, ErrorKind::NotFound, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::{collections::BTreeMap, result::Result, str, thread};
use std::{marker::Sync, sync::Arc, sync::Mutex};
pub type Headers<'a> = BTreeMap<&'a str, &'a str>;

//Using a stack buffer of reserved bytes or a vector if more is desired, declares a cursor over a
//writeable u8 slice. Call into_inner to get the underlying slice. Why not smallvec? This doesn't
//re-copy once you hit the small vec size; it optimizes for a single fixed size. Slightly better
//generated assembly. I checked. Also absolves us of another dependency.
#[macro_export]
macro_rules! stack_or_vec_cursor {
    ($reserved:expr, $desired:expr, $cur:ident) => {
        let mut _macrobuf = [0; $reserved]; //Reserved stack size; works faster if it fits.
        let mut _dummybufholder = None; //Holds the allocated vec to put scope out here if needed
        let _desiredbuflen = $desired;
        let mut $cur = if _macrobuf.len() < _desiredbuflen {
            _dummybufholder = Some(vec![0; _desiredbuflen]); //buf is too small; allocate
            Cursor::new(_dummybufholder.as_deref_mut().unwrap()) //A cursor over a mut vec slice
        } else {
            Cursor::new(&mut _macrobuf[.._desiredbuflen]) //No allocation! Stack byte slice cursor
        };
    };
}

//does rcvd have a \r\n\r\n, seeking from the *end*? (one 4-byte comparison in a normal GET request)
fn has_double_crlf(rcvd: &[u8]) -> bool {
    if rcvd.len() > 3 {
        for i in (0..(rcvd.len() - 3)).rev() {
            if &rcvd[i..i + 4] == b"\r\n\r\n" {
                return true;
            }
        }
    }
    false
}

//Handles a TCP stream for the HTTP server. Loops over requests as they come in
fn handle_tcp<E: From<Error>, U, F>(mut stream: TcpStream, custom: &U, f: &F) -> Result<(), E>
where
    F: Fn(&str, &str, &Headers, &mut TcpStream, &[u8], &U) -> Result<(), E>,
{
    debug!("Got a TCP connection");
    let mut buffer = [0; 4096]; //buffer for request. We avoid memory allocation if it fits.
    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }
        debug!("Request incoming: {} bytes so far", bytes_read);
        if has_double_crlf(&buffer[0..bytes_read]) {
            let chunk = &mut buffer[0..bytes_read];
            handle_req(&mut stream, chunk, custom, f)?
        } else {
            let mut full_req = (&buffer[0..bytes_read]).to_vec();
            debug!("Long headers? {}", str::from_utf8(&full_req).unwrap_or(""));
            while {
                let bytes_read = stream.read(&mut buffer)?;
                if bytes_read == 0 {
                    return Ok(());
                }
                full_req.extend_from_slice(&buffer[0..bytes_read]);
                !has_double_crlf(&full_req)
            } {}
            handle_req(&mut stream, &mut full_req, custom, f)?
        }
        debug!("Handled request. Waiting for next.");
    }
}
//Splits a byte buffer on the first instance of a given byte or returns error.
fn split_buf_on(buf: &mut [u8], b: u8) -> std::io::Result<(&mut [u8], &mut [u8])> {
    let mut splitter = buf.splitn_mut(2, |&r| r == b);
    let first = splitter.next().ok_or(Error::from(NotFound))?;
    let after = splitter.next().ok_or(Error::from(NotFound))?;
    Ok((first, after))
}
//Handles a single request; parsing out headers
fn handle_req<U, E, F>(tcp: &mut TcpStream, rcvd: &mut [u8], custom: &U, f: &F) -> Result<(), E>
where
    F: Fn(&str, &str, &Headers, &mut TcpStream, &[u8], &U) -> Result<(), E>,
    E: From<Error>,
{
    let (method_bin, rest) = split_buf_on(rcvd, b' ')?;
    let method = str::from_utf8(method_bin).unwrap_or("");
    let (path_bin, rest) = split_buf_on(rest, b' ')?;
    let path = str::from_utf8(path_bin).unwrap_or("");
    let mut headers = BTreeMap::new();
    let (mut line, mut rest) = split_buf_on(rest, b'\n')?;
    while line.len() > 1 {
        if let Ok((header_name_bin, header_bin)) = split_buf_on(line, b':') {
            for f in header_name_bin.iter_mut() {
                if *f >= b'A' && *f <= b'Z' {
                    *f += b'a' - b'A'; //lowercase ascii header names
                }
            }
            if header_name_bin.len() > 0 && header_bin.len() > 2 {
                if let Ok(header_name) = str::from_utf8(header_name_bin) {
                    if let Ok(header_val) = str::from_utf8(&header_bin[1..header_bin.len() - 1]) {
                        headers.insert(header_name, header_val);
                    }
                }
            }
        }
        let temp = split_buf_on(rest, b'\n')?;
        line = temp.0;
        rest = temp.1;
    }
    f(method, path, &headers, tcp, rest, custom)
}

//Run the HTTP server. In combination with handle_tcp and handle_req, wraps request serving function
pub fn run_httpsrv<E, U, V, F>(address: V, start: Arc<U>, srv: &'static F) -> usize
where
    F: Fn(&str, &str, &Headers, &mut TcpStream, &[u8], &Arc<U>) -> Result<(), E> + Send + Sync,
    E: From<Error> + std::fmt::Display,
    U: Send + 'static + Sync,
    V: ToSocketAddrs,
{
    let bindres = TcpListener::bind(address);
    if let Err(e) = bindres {
        error!("FATAL server error: {}", e);
        return 5;
    }
    let readythread: Arc<Mutex<Option<SyncSender<TcpStream>>>> = Arc::new(Mutex::new(None));
    for stream_res in bindres.unwrap().incoming() {
        if let Err(e) = stream_res {
            error!("FATAL serve error: {}", e);
            break;
        }
        let mut stream = stream_res.unwrap();
        let mut rtlock = readythread.lock().unwrap(); //ready thread to handle connection
        if let Some(chan) = &*rtlock {
            stream = if let Err(e) = chan.try_send(stream) {
                rtlock.take(); //close that malfunctioning channel (probably lost a race)
                match e {
                    TrySendError::Full(s) => s, //get stream back - thread wasn't really ready
                    TrySendError::Disconnected(s) => s,
                }
            } else {
                continue; //we successfully passed the new connection to an existing thread
            };
        }
        let custom = Arc::clone(&start);
        let rtlc = Arc::clone(&readythread);
        if let Err(e) = thread::Builder::new()
            .name("httpsrvr".to_string())
            .spawn(move || {
                loop {
                    if let Err(e) = handle_tcp(stream, &custom, &srv) {
                        error!("Handling connection {}", e);
                    }
                    let mut rtl2 = rtlc.lock().unwrap();
                    if rtl2.is_some() {
                        debug!("Unnecessary thread exiting");
                        break;
                    }
                    let (snd, rcv) = sync_channel(0);
                    rtl2.replace(snd); //pass sender to server socket thread
                    drop(rtl2); //release lock so server socket can send next conn to us
                    debug!("standby thread waiting for connection");
                    stream = if let Ok(s) = rcv.recv() { s } else { return }; //blocks for a new stream
                    rtlc.lock().unwrap().take(); //and we're no longer ready
                }
            })
        {
            error!("Error starting HTTP thread {}", e);
        }
    }
	6
}

#[macro_export]
macro_rules! get_full_body {
    ($stream:ident, $hed:ident, $bod: ident, $full_body:ident) => {
        //standard read body chunk
        let cont_len_header_opt = $hed.get("content-length").and_then(|h| h.parse().ok());
        let bsize = cont_len_header_opt.unwrap_or($bod.len());
        let mut $full_body = $bod;
        let mut _placeholder = None;
        if $bod.len() < bsize {
            let mut allocated_body = Vec::with_capacity(bsize); //allocate only if we need more
            allocated_body.extend_from_slice($bod);
            allocated_body.resize(bsize, 0);
            {
                use std::io::Read;
                $stream.read_exact(&mut allocated_body[$bod.len()..])?;
            }
            _placeholder = Some(allocated_body);
            $full_body = _placeholder.as_deref().unwrap();
        }
    };
}

//Create and send a response with standard headers used for all HTTP responses, plus extra supplied.
pub fn do_reply<E: From<Error>>(tcp: &mut TcpStream, headers: &str, body: &[u8]) -> Result<(), E> {
    code_reply(tcp, 200, headers, body)
}
//Create and send a response with a custom HTTP response code, headers, and body
pub fn code_reply<E: From<Error>>(s: &mut TcpStream, cod: u16, h: &str, b: &[u8]) -> Result<(), E> {
    if cod != 200 {
        debug!("HTTP RSP {} {}", cod, str::from_utf8(b).unwrap_or(""));
    }
    let pre = "HTTP/1.1 ";
    let norm = " UH\r\n\
X-Content-Type-Options: nosniff\r\n\
Content-Security-Policy: default-src 'self'; img-src 'self' data:; media-src 'self' blob: data:;\r\n\
X-Frame-Options: DENY\r\n\
Cache-Control: no-cache\r\n\
Referrer-Policy: no-referrer\r\n\
Connection: Keep-Alive\r\n\
Keep-Alive: timeout=45, max=9999\r\n\
Content-Length: "; //normal headers
    let blen = ((b.len().max(1) as f64).log10() + 1.0) as usize; //how many digits the body len is
    let hlen = pre.len() + 3 + norm.len() + blen + 2 + h.len() + 2; //desired buf length
    stack_or_vec_cursor!(2048, hlen, cur);
    //Assemble the headers into one blob on stack if possible or heap if > 2k to send at once.
    write!(cur, "{}{}{}{}\r\n{}\r\n", pre, cod, norm, b.len(), h)?;
    let wrotelen = cur.position() as usize;
    s.write_all(&cur.into_inner()[..wrotelen])?; //Send all the headers as one chunk
    Ok(s.write_all(b)?) //Then the body as a second chunk
}

//Create a streaming response that consumes an iterator, sending out each chunk via chunked transfer
pub fn stream_resp<I, E>(stream: &mut TcpStream, extra_headers: &str, rstream: I) -> Result<(), E>
where
    I: Iterator<Item = Vec<u8>>,
    E: From<Error>,
{
    let stream_hdrs = "HTTP/1.1 200 OK\r\n\
X-Content-Type-Options: nosniff\r\n\
Content-Security-Policy: default-src 'self'; img-src 'self' data:; media-src 'self' blob:;\r\n\
X-Frame-Options: DENY\r\n\
Cache-Control: no-cache\r\n\
Referrer-Policy: no-referrer\r\n\
Connection: Keep-Alive\r\n\
Keep-Alive: timeout=45, max=9999\r\n\
Transfer-Encoding: chunked\r\n";
    stream.write_all(stream_hdrs.as_bytes())?;
    stream.write_all(extra_headers.as_bytes())?;
    stream.write_all("\r\n".as_bytes())?;
    let mut prefix = "";

    let mut buf = [0; 16]; //just for the chunk headers
    for chunk in rstream {
        debug!("chunk len {}", chunk.len());
        if chunk.len() > 0 {
            let mut cur = Cursor::new(&mut buf[..]);
            write!(cur, "{}{:X}\r\n", prefix, chunk.len())?;
            let end = cur.position() as usize;
            stream.write_all(&buf[..end])?;
            stream.write_all(&chunk)?;
            prefix = "\r\n";
        }
    }
    stream.write_all(&b"\r\n0\r\n\r\n"[2 - prefix.len()..])?;
    debug!("stream_resp complete");
    Ok(())
}

//Wraps up getting the POST body all at once and converting exceptions to HTTP exceptions
pub fn post_wrap<E, F, G, H: AsRef<[u8]>>(
    stream: &mut TcpStream,
    body: &[u8],
    headers: &Headers,
    context: &G,
    mut inner: F,
) -> Result<(), E>
where
    F: FnMut(&Headers, &[u8], &G) -> Result<H, E> + std::marker::Send,
    E: From<Error> + std::fmt::Display,
{
    get_full_body!(stream, headers, body, full_body);
    match inner(headers, full_body, context) {
        Err(e) => {
            info!("POST error {}", e);
            let th = "Content-Type: text/plain\r\n";
            code_reply(stream, 400, th, format!("{}", e).as_bytes())?
        }
        Ok(bytes) => do_reply::<E>(stream, "Content-Type: text/plain\r\n", bytes.as_ref())?,
    };
    Ok(())
}

//Wraps up getting the GET response converting exceptions to HTTP exceptions
pub fn get_wrap<E, F, G, H: AsRef<[u8]>>(
    stream: &mut TcpStream,
    headers: &Headers,
    uri: &str,
    context: &G,
    mut callback: F,
) -> Result<(), E>
where
    F: FnMut(&Headers, &str, &G) -> Result<H, E>,
    E: From<Error> + std::fmt::Display,
{
    match callback(headers, uri, context) {
        Err(e) => {
            info!("GET error {}", e);
            let th = "Content-Type: text/plain\r\n";
            code_reply::<E>(stream, 400, th, format!("{}", e).as_bytes())?
        }
        Ok(bytes) => do_reply::<E>(stream, "Content-Type: text/plain\r\n", bytes.as_ref())?,
    };
    Ok(())
}
