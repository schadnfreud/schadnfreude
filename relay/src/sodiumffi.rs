// simple FFI wrappers for libsodium for rust
// yes, there are crates that do similar, but we are using a patched libsodium, so we explicitly do not want the default versions
// the link directives and compilation are done by build.rs

#[allow(non_camel_case_types)]
use crate::*;
use std::convert::AsMut;

pub const CRYPTO_SECRETBOX_KEYBYTES: usize = 32;
pub const CRYPTO_BOX_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_SIGN_PUBLICKEYBYTES: usize = 32;
pub const CRYPTO_BOX_NONCEBYTES: usize = 24;
pub const CRYPTO_BOX_MACBYTES: usize = 16;
pub const CRYPTO_BOX_SEALBYTES: usize = 48;
pub const CRYPTO_SIGN_BYTES: usize = 64;

#[link(name = "sodium")]
extern "C" {
    pub fn sodium_init() -> i32;
    pub fn randombytes_buf(buf: *mut u8, bufsize: usize);
    pub fn crypto_box_easy(
        c: *mut u8,
        m: *const u8,
        mlen: u64,
        n: *const u8,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    //Returns 0 when signature is valid
    pub fn crypto_box_open_easy(
        m: *mut u8,
        c: *const u8,
        clen: u64,
        n: *const u8,
        pk: *const u8,
        sk: *const u8,
    ) -> i32;
    //anonymous variety
    pub fn crypto_box_seal(c: *mut u8, m: *const u8, mlen: u64, recipient_pk: *const u8) -> i32;
    pub fn crypto_box_seal_open(
        m: *mut u8,
        c: *const u8,
        clen: u64,
        recipient_pk: *const u8,
        recipient_sk: *const u8,
    ) -> i32;
    //secret variety
    pub fn crypto_secretbox_easy(
        c: *mut u8,
        m: *const u8,
        mlen: u64,
        n: *const u8,
        k: *const u8,
    ) -> i32;
    //Returns 0 when valid
    pub fn crypto_secretbox_open_easy(
        m: *mut u8,
        c: *const u8,
        clen: u64,
        n: *const u8,
        k: *const u8,
    ) -> i32;
    //Signatures sadly a different key format/curve. UGH
    pub fn crypto_sign_ed25519_seed_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8);
    pub fn crypto_sign(
        sm: *mut u8,
        smlen: *const u64,
        m: *const u8,
        mlen: u64,
        sk: *const u8,
    ) -> i32;
    pub fn crypto_sign_verify_detached(s: *const u8, m: *const u8, mlen: u64, pk: *const u8)
        -> i32;
    //convert to box from sign keypair
    pub fn crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: *mut u8, ed25519_pk: *const u8);
    pub fn crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: *mut u8, ed25519_skpk: *const u8);
    //hashing
    pub fn crypto_hash_sha256(out: *mut u8, inb: *const u8, inlen: u64) -> i32;
    //key blinding for HS
    pub fn crypto_blind_ed25519_public_key(
        new_pk: *mut u8,
        inp_pk: *const u8,
        param: *const u8,
    ) -> i32;
    pub fn crypto_blind_ed25519_secret_key(
        new_sk: *mut u8,
        inp_sk: *const u8,
        param: *const u8,
    ) -> i32;
    //HMAC
    pub fn crypto_auth(out: *mut u8, inp: *const u8, inlen: u64, k: *const u8) -> i32;
}

pub type SignPKey = [u8; 32];
pub type SignSKey = [u8; 64];
pub type BoxPKey = [u8; 32];
pub type BoxSKey = [u8; 32];
pub type SecKey = [u8; 32];
pub type AuthTag = [u8; 32];
pub type Sha256Hash = [u8; 32];
pub type Nonce = [u8; 24];

#[derive(Copy, Clone)]
pub struct BoxKeys {
    pub sk: BoxSKey,
    pub pk: BoxPKey,
}

#[derive(Copy, Clone)]
pub struct SignKeys {
    pub sk: SignSKey,
    pub pk: SignPKey,
}

#[derive(Copy, Clone)]
pub struct Keys {
    pub bx: BoxKeys,
    pub sign: SignKeys,
}

pub fn wr_sodium_init() -> i32 {
    unsafe {
        return sodium_init();
    }
}

pub fn copy_to_array<A, T: Copy>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
    a
}

pub fn wr_crypto_auth(inp: &[u8], k: &SecKey) -> AuthTag {
    let mut res: AuthTag = [0; 32];
    unsafe {
        crypto_auth(&mut res[0], inp.as_ptr(), inp.len() as u64, &k[0]);
    }
    res
}

pub fn wr_crypto_hash_sha256(inp: &[u8]) -> Sha256Hash {
    let mut res: Sha256Hash = [0; 32];
    unsafe {
        crypto_hash_sha256(&mut res[0], inp.as_ptr(), inp.len() as u64);
    }
    res
}

pub fn wr_crypto_blind_ed25519_public_key(inp_pk: &SignPKey, param: &str) -> SignPKey {
    let mut paramseed: [u8; 64] = [0; 64];
    let mut pkvec = [0; 32];
    unsafe {
        crypto_hash_sha256(&mut paramseed[0], param.as_ptr(), param.len() as u64);
        (&mut paramseed[32..]).copy_from_slice(&inp_pk[..]);
        let mut parambin: [u8; 32] = [0; 32]; // hash of input public key and param hash
        crypto_hash_sha256(&mut parambin[0], paramseed.as_ptr(), paramseed.len() as u64);
        crypto_blind_ed25519_public_key(
            pkvec.as_mut_ptr(),
            inp_pk.as_ptr(),
            parambin.as_ref().as_ptr(),
        );
    }
    pkvec
}

pub fn wr_crypto_blind_ed25519_secret_key(inp_sk: &SignSKey, param: &str) -> SignSKey {
    let mut sk: SignSKey = [0; 64];
    let mut paramseed: [u8; 64] = [0; 64];
    let mut parambin: [u8; 32] = [0; 32]; // hash of input public key and param hash
    unsafe {
        crypto_hash_sha256(&mut paramseed[0], param.as_ptr(), param.len() as u64);
        (&mut paramseed[32..]).copy_from_slice(&inp_sk[32..64]); //public key is 2nd block of 32 bytes in inp_sk
        crypto_hash_sha256(&mut parambin[0], paramseed.as_ptr(), paramseed.len() as u64);
        crypto_blind_ed25519_secret_key(
            sk.as_mut_ptr(),
            inp_sk.as_ptr(),
            parambin.as_ref().as_ptr(),
        );
    }
    sk
}

// Sign
pub fn wr_crypto_sign(m: &[u8], sk: &SignSKey) -> Vec<u8> {
    let smbytes = m.len() + CRYPTO_SIGN_BYTES;
    let mut smvec = Vec::with_capacity(smbytes);
    unsafe {
        crypto_sign(
            smvec.as_mut_ptr(),
            std::ptr::null(),
            m.as_ptr(),
            m.len() as u64,
            sk.as_ptr(),
        );
        smvec.set_len(smbytes);
    }
    smvec
}

// Sign in-place; must have exactly the right number of bytes in output slice
pub fn wr_crypto_sign_inplace(m: &[u8], signed: &mut [u8], sk: &SignSKey) -> SfRes<()> {
    if signed.len() != m.len() + CRYPTO_SIGN_BYTES {
        return Err(SfErr::BadSignatureErr);
    }
    unsafe {
        crypto_sign(
            signed.as_mut_ptr(),
            std::ptr::null(),
            m.as_ptr(),
            m.len() as u64,
            sk.as_ptr(),
        );
    }
    Ok(())
}

//If they used the default, sig will be the first 64 bytes so no need to copy
pub fn wr_crypto_sign_open_inplace<'a>(sm: &'a [u8], pk: &SignPKey) -> SfRes<&'a [u8]> {
    let mbytes = sm.len() as i64 - CRYPTO_SIGN_BYTES as i64;
    if mbytes < 0 {
        return Err(SfErr::BadSignatureErr);
    }
    let msg = &sm[CRYPTO_SIGN_BYTES..];
    unsafe {
        let (sp, mp) = (sm.as_ptr(), msg.as_ptr());
        if 0 != crypto_sign_verify_detached(sp, mp, msg.len() as u64, pk.as_ptr()) {
            error!("Bad sign open {} bytes not {}", sm.len(), b64spk(pk));
            return Err(SfErr::BadSignatureErr);
        }
    }
    Ok(msg)
}

//Rustifies crypto_box_open_easy
pub fn wr_crypto_box_open_easy(c: &[u8], pk: &BoxPKey, sk: &BoxSKey) -> SfRes<Vec<u8>> {
    if c.len() < CRYPTO_BOX_MACBYTES + CRYPTO_BOX_NONCEBYTES {
        return Err(SfErr::BadSignatureErr);
    }
    let nvec = &c[0..CRYPTO_BOX_NONCEBYTES];
    let cptr = &c[CRYPTO_BOX_NONCEBYTES..];
    let mbytes = cptr.len() - CRYPTO_BOX_MACBYTES;
    let mut mvec = Vec::with_capacity(mbytes);
    unsafe {
        if 0 != crypto_box_open_easy(
            mvec.as_mut_ptr(),
            cptr.as_ptr(),
            cptr.len() as u64,
            nvec.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        ) {
            error!("Bad box open {} bytes k {}", c.len(), b64sk(sk));
            return Err(SfErr::BadSignatureErr); //error
        }
        mvec.set_len(mbytes);
    }
    Ok(mvec)
}

pub fn rand_array<A: Sized + Default + AsMut<[u8]>>() -> A {
    let mut a = Default::default();
    let a_mut_ref = <A as AsMut<[u8]>>::as_mut(&mut a);
    unsafe {
        randombytes_buf(a_mut_ref.as_mut_ptr(), a_mut_ref.len());
    }
    a
}

//convenience typed method for rand_array in most common dimension
pub fn wr_randomkey() -> [u8; 32] {
    rand_array()
}

// encrypt into new vector
pub fn wr_crypto_box_easy(m: &[u8], pk: &BoxPKey, sk: &BoxSKey) -> Vec<u8> {
    let cbytes = CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES + m.len();
    let mut nvec = Vec::with_capacity(cbytes);
    nvec.extend_from_slice(&rand_array::<[u8; CRYPTO_BOX_NONCEBYTES]>()[..]);
    nvec.push(0);
    unsafe {
        crypto_box_easy(
            (&mut nvec[CRYPTO_BOX_NONCEBYTES..]).as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            nvec.as_ptr(),
            pk.as_ptr(),
            sk.as_ptr(),
        );
        nvec.set_len(cbytes);
    }
    nvec
}

// encrypt into existing bytes with symmetric key and given nonce
pub fn wr_crypto_secretbox_inplace_n(m: &[u8], c: &mut [u8], nonce: &Nonce, key: &SecKey) {
    let cbytes = CRYPTO_BOX_MACBYTES + m.len();
    if c.len() < cbytes {
        return; //bad.
    }
    unsafe {
        crypto_secretbox_easy(
            c.as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            (&nonce[..]).as_ptr(),
            key.as_ptr(),
        );
    }
}

// encrypt into new vector with symmetric key and given nonce
pub fn wr_crypto_secretbox_easy_n(m: &[u8], nonce: &Nonce, key: &SecKey) -> Vec<u8> {
    let cbytes = CRYPTO_BOX_MACBYTES + m.len();
    let mut cvec = Vec::with_capacity(cbytes);
    unsafe {
        crypto_secretbox_easy(
            cvec.as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            (&nonce[..]).as_ptr(),
            key.as_ptr(),
        );
        cvec.set_len(cbytes);
    }
    cvec
}

// decrypt into new vector with symmetric key and given nonce
pub fn wr_crypto_secretbox_open_easy_n(cptr: &[u8], nonce: &Nonce, key: &SecKey) -> SfRes<Vec<u8>> {
    if cptr.len() < CRYPTO_BOX_MACBYTES {
        return Err(SfErr::BadSignatureErr);
    }
    let mbytes = cptr.len() - CRYPTO_BOX_MACBYTES;
    let mut mvec = Vec::with_capacity(mbytes);
    unsafe {
        if 0 != crypto_secretbox_open_easy(
            mvec.as_mut_ptr(),
            cptr.as_ptr(),
            cptr.len() as u64,
            (&nonce[..]).as_ptr(),
            key.as_ptr(),
        ) {
            error!("Bad secretbox open {} bytes k {}", cptr.len(), b64sk(key));
            return Err(SfErr::BadSignatureErr); //error
        }
        mvec.set_len(mbytes);
    }
    Ok(mvec)
}

// encrypt into new vector with symmetric key
pub fn wr_crypto_secretbox_easy(m: &[u8], key: &SecKey) -> Vec<u8> {
    let cbytes = CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES + m.len();
    let mut cvec = Vec::with_capacity(cbytes);
    cvec.extend_from_slice(&rand_array::<[u8; CRYPTO_BOX_NONCEBYTES]>()[..]);
    let (nonce, ciphertext) = cvec.split_at_mut(CRYPTO_BOX_NONCEBYTES);
    unsafe {
        crypto_secretbox_easy(
            ciphertext.as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        );
        cvec.set_len(cbytes);
    }
    cvec
}

// symmetric encrypt, no allocation
pub fn wr_crypto_secretbox_inplace(m: &[u8], c: &mut [u8], key: &SecKey) -> usize {
    let clen = m.len() + CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES;
    if c.len() < clen {
        return 0;
    }
    unsafe {
        randombytes_buf(c.as_mut_ptr(), CRYPTO_BOX_NONCEBYTES);
        crypto_secretbox_easy(
            (&mut c[CRYPTO_BOX_NONCEBYTES..]).as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            c.as_ptr(),
            key.as_ptr(),
        );
    }
    clen
}

// symmetric decrypt, no allocation; in-place
pub fn wr_crypto_secretbox_open<'a>(c: &'a mut [u8], key: &SecKey) -> SfRes<&'a mut [u8]> {
    if c.len() < CRYPTO_BOX_NONCEBYTES + CRYPTO_BOX_MACBYTES {
        return Err(SfErr::BadSignatureErr);
    }
    let (nvec, cptr) = c.split_at_mut(CRYPTO_BOX_NONCEBYTES);
    let ptr = cptr.as_mut_ptr();
    let len = cptr.len() as u64;
    unsafe {
        if 0 != crypto_secretbox_open_easy(ptr, ptr, len, nvec.as_ptr(), key.as_ptr()) {
            error!("Bad secretbox {}", len as usize + CRYPTO_BOX_NONCEBYTES);
            return Err(SfErr::BadSignatureErr);
        }
    }
    Ok(&mut cptr[..len as usize - CRYPTO_BOX_MACBYTES])
}

// decrypt into new vector with symmetric key
pub fn wr_crypto_secretbox_open_easy(c: &[u8], key: &SecKey) -> SfRes<Vec<u8>> {
    if c.len() < CRYPTO_BOX_MACBYTES + CRYPTO_BOX_NONCEBYTES {
        return Err(SfErr::BadSignatureErr);
    }
    let nvec = &c[0..CRYPTO_BOX_NONCEBYTES];
    let cptr = &c[CRYPTO_BOX_NONCEBYTES..];
    let mbytes = cptr.len() - CRYPTO_BOX_MACBYTES;
    let mut mvec = Vec::with_capacity(mbytes);
    unsafe {
        if 0 != crypto_secretbox_open_easy(
            mvec.as_mut_ptr(),
            cptr.as_ptr(),
            cptr.len() as u64,
            nvec.as_ptr(),
            key.as_ptr(),
        ) {
            error!("Bad secretbox open {} bytes k {}", c.len(), b64sk(key));
            return Err(SfErr::BadSignatureErr); //error
        }
        mvec.set_len(mbytes);
    }
    Ok(mvec)
}

// encrypt into new vector with single pubkey
pub fn wr_crypto_box_seal(m: &[u8], pubkey: &BoxPKey) -> Vec<u8> {
    let numbytes = CRYPTO_BOX_SEALBYTES + m.len();
    let mut cvec = Vec::with_capacity(numbytes);
    unsafe {
        crypto_box_seal(
            cvec.as_mut_ptr(),
            m.as_ptr(),
            m.len() as u64,
            pubkey.as_ptr(),
        );
        cvec.set_len(numbytes);
    }
    cvec
}

// decrypt into new vector with one keypair
pub fn wr_crypto_box_seal_open(c: &[u8], bkeys: &BoxKeys) -> SfRes<Vec<u8>> {
    if c.len() < CRYPTO_BOX_SEALBYTES {
        return Err(SfErr::BadSignatureErr);
    }
    let mbytes = c.len() - CRYPTO_BOX_SEALBYTES;
    let mut mvec = Vec::with_capacity(mbytes);
    unsafe {
        if 0 != crypto_box_seal_open(
            mvec.as_mut_ptr(),
            c.as_ptr(),
            c.len() as u64,
            bkeys.pk.as_ptr(),
            bkeys.sk.as_ptr(),
        ) {
            error!("Bad seal open {} bytes", c.len()); //no pubkey-sign key is recognizable, not box
            return Err(SfErr::BadSignatureErr); //error
        }
        mvec.set_len(mbytes);
    }
    Ok(mvec)
}

pub fn wr_crypto_sign_pk_to_box(inp_pk: &SignPKey) -> BoxPKey {
    let mut pk: BoxPKey = [0; 32];
    unsafe {
        crypto_sign_ed25519_pk_to_curve25519(pk.as_mut_ptr(), inp_pk.as_ptr());
    }
    pk
}
pub fn wr_crypto_sign_sk_to_box(inp_sk: &SignSKey) -> BoxSKey {
    let mut sk: BoxSKey = [0; 32];
    unsafe {
        crypto_sign_ed25519_sk_to_curve25519(sk.as_mut_ptr(), inp_sk.as_ptr());
    }
    sk
}

// Generate a new keypair. We do almost exactly the same as libsodium default, but we clear one bit.
// This ensures our key blinding doesn't cause trouble later.
pub fn wr_crypto_sign_keypair() -> SignKeys {
    wr_crypto_sign_seed_keypair(wr_randomkey())
}
pub fn wr_crypto_sign_seed_keypair(mut seed: [u8; 32]) -> SignKeys {
    let mut sk: SignSKey = [0; 64];
    let mut pk: SignPKey = [0; 32];
    unsafe {
        seed[31] &= 0b11011111_u8; // clear third most significant seed bit
        crypto_sign_ed25519_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), &mut seed[0]);
    }
    SignKeys { pk: pk, sk: sk }
}
