use std::ptr;

/// c: ciphertext (`mlen` long)
/// mac: authenticaton tag, 16 bytes
/// mlen: plaintext length
/// m: plaintext (`mlen` long)
/// aad1: additional authentication data, `aadlen` long
/// aadlen: length of additional auth data
/// k1: key, 32 bytes
/// n1: nonce, 8 bytes
#[link(name = "hacl")]
extern "C" {
    fn Chacha20Poly1305_aead_encrypt(c: *const u8,
                                     mac: *const u8,
                                     m: *const u8,
                                     mlen: u32,
                                     aad1: *const u8,
                                     aadlen: u32,
                                     k1: *const u8,
                                     n1: *const u8)
                                     -> u32;
}

pub fn encrypt(ciphertext: &[u8], mac: &[u8], message: &[u8], mlen: u32, key: &[u8], nonce: &[u8]) -> u32 {
	let p: *const u8 = ptr::null();	
	unsafe {
		        Chacha20Poly1305_aead_encrypt(ciphertext.as_ptr(),
                                      mac.as_ptr(),
                                      message.as_ptr(),
                                      mlen,
                                      p,
                                      0,
                                      key.as_ptr(),
                                      nonce.as_ptr())
	}
} 


/// m: plaintext (`mlen` long)
/// c: ciphertext (`mlen` long)
/// mlen: ciphertext length
/// mac: authenticaton tag, 16 bytes
/// aad1: additional authentication data, `aadlen` long
/// aadlen: length of additional auth data
/// k1: key, 32 bytes
/// n1: nonce, 8 bytes
#[link(name = "hacl")]
extern "C" {
    fn Chacha20Poly1305_aead_decrypt(m: *const u8,
                                     c: *const u8,
                                     mlen: u32,
                                     mac: *const u8,
                                     aad1: *const u8,
                                     aadlen: u32,
                                     k1: *const u8,
                                     n1: *const u8)
                                     -> u32;
}

pub fn decrypt(ciphertext: &[u8], mac: &[u8], message: &[u8], mlen: u32, key: &[u8], nonce: &[u8]) -> u32 {
	let p: *const u8 = ptr::null();
	unsafe {
        Chacha20Poly1305_aead_decrypt(message.as_ptr(),
                                      ciphertext.as_ptr(),
                                      mlen,
                                      mac.as_ptr(),
                                      p,
                                      0,
                                      key.as_ptr(),
                                      nonce.as_ptr())
	}
}

/// mypublic: generated public key, 32 bytes
/// secret: secret key, 32 bytes
/// basepoint: initial point, 32 bytes
#[link(name = "hacl")]
extern "C" {
    fn Curve25519_crypto_scalarmult(mypublic: *const u8, secret: *const u8, basepoint: *const u8);
}


/// signature: 64 bytes
/// secret: secret key, 32 bytes
/// msg: message to sign
/// len: lentgh of the message 
#[link(name = "hacl")]
extern "C" {
    fn Ed25519_sign(signature: *const u8, secret: *const u8, msg: *const u8, len: u32);
}

/// hash: resulting hash, 64 bytes
/// input: input to be hashed, `input_len` long
/// input_len: input length
#[link(name = "hacl")]
extern "C" {
    fn SHA2_512_hash(hash: *const u8, input: *const u8, input_len: u32);
}

