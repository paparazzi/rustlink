// FOR GEC COMMS
//use std::io::BufReader;
//use rand::Rng;
//use rand::os::OsRng;

const KEY_LEN: usize = 32;
const SIGN_LEN: usize = 64;
const MAC_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CRYPTO_OVERHEAD: usize = 20;
const COUNTER_LEN: usize = 4;



struct Ed25519Signature {
    sign: [u8; SIGN_LEN],
}

#[derive(Debug)]
struct GecPrivKey {
    privkey: [u8; KEY_LEN],
    pubkey: [u8; KEY_LEN],
}

impl GecPrivKey {
    pub fn new() -> GecPrivKey {
        let q = [0; KEY_LEN];
        let p = [0; KEY_LEN];
        GecPrivKey {
            privkey: q,
            pubkey: p,
        }
    }
}

#[derive(Debug)]
struct GecPubKey {
    pubkey: [u8; KEY_LEN],
}

impl GecPubKey {
    pub fn new() -> GecPubKey {
        let p = [0; KEY_LEN];
        GecPubKey { pubkey: p }
    }
}

#[derive(Debug)]
struct GecSymKey {
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    ctr: u32,
}

impl GecSymKey {
    pub fn new() -> GecSymKey {
        let k = [0; KEY_LEN];
        let n = [0; NONCE_LEN];
        let c = 0;
        GecSymKey {
            key: k,
            nonce: n,
            ctr: c,
        }
    }
}

#[derive(Debug)]
enum StsParty {
    Initiator = 0,
    Responder = 1,
}

#[allow(dead_code)]
#[derive(Debug)]
#[derive(PartialEq)]
enum StsStage {
    Init,
    WaitMsg1,
    WaitMsg2,
    WaitMsg3,
    CryptoOK,
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[derive(PartialEq)]
enum StsMsgType {
    P_AE = 0,
    P_BE = 1,
    SIG = 2,
}

#[allow(non_camel_case_types,dead_code)]
#[derive(Debug)]
enum StsError {
    ERROR_NONE,
    // RESPONDER ERRORS
    MSG1_TIMEOUT_ERROR,
    MSG1_ENCRYPT_ERROR,
    MSG3_TIMEOUT_ERROR,
    MSG3_DECRYPT_ERROR,
    MSG3_SIGNVERIFY_ERROR,
    // INITIATOR ERRORS
    MSG2_TIMEOUT_ERROR,
    MSG2_DECRYPT_ERROR,
    MSG2_SIGNVERIFY_ERROR,
    MSG3_ENCRYPT_ERROR,
    // BOTH PARTIES
    UNEXPECTED_MSG_TYPE_ERROR,
    UNEXPECTED_STS_STAGE_ERROR,
    UNEXPECTED_MSG_ERROR,
}

#[derive(Debug)]
pub struct GecSts {
    party: StsParty,
    stage: StsStage,
    last_error: StsError,
    their_public_key: GecPubKey,
    my_private_key: GecPrivKey,
    their_public_ephemeral: GecPubKey,
    my_private_ephemeral: GecPrivKey,
    their_symmetric_key: GecSymKey,
    my_symmetric_key: GecSymKey,
}

impl GecSts {
    pub fn new(p_a: &[u8; 32], q_a: &[u8; 32], p_b: &[u8; 32]) -> GecSts {
        GecSts {
            party: StsParty::Initiator,
            stage: StsStage::Init,
            last_error: StsError::ERROR_NONE,
            their_public_key: GecPubKey { pubkey: p_b.clone() },
            my_private_key: GecPrivKey {
                privkey: q_a.clone(),
                pubkey: p_a.clone(),
            },
            their_public_ephemeral: GecPubKey::new(),
            my_private_ephemeral: GecPrivKey::new(),
            their_symmetric_key: GecSymKey::new(),
            my_symmetric_key: GecSymKey::new(),
        }
    }
}
