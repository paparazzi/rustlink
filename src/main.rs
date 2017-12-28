#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate serial;
extern crate ivyrust;
extern crate pprzlink;
extern crate clap;
extern crate rusthacl;
extern crate rand;

use clap::{Arg, App};
use std::env;
use ivyrust::*;
use std::{thread, time};
use std::io::prelude::*;
use serial::prelude::*;
use std::time::Duration;
use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use pprzlink::parser;
use pprzlink::parser::{PprzDictionary, PprzMsgClassID, PprzMessage, PprzMsgBaseType};
use pprzlink::transport::PprzTransport;
use std::sync::Mutex;
use std::sync::Arc;
use time::*;
use regex::Regex;
use std::collections::VecDeque;
use std::io::BufReader;
use rand::Rng;
use rand::os::OsRng;

lazy_static! {
    static ref MSG_QUEUE: Mutex<VecDeque<PprzMessage>> = Mutex::new(VecDeque::new());
    static ref DICTIONARY: Mutex<Vec<PprzDictionary>> = Mutex::new(vec![]);
    static ref PING_TIME: Mutex<Instant> = Mutex::new(Instant::now());
    static ref RE_DATALINK: Regex = Regex::new("ground_dl .*").unwrap(); // TODO: factor out?
    static ref PING_TIME_VALUE: Mutex<f32> = Mutex::new(-1.0);
}

const KEY_LEN: usize = 32;
const SIGN_LEN: usize = 64;
const MAC_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const CRYPTO_OVERHEAD: usize = 20;
const COUNTER_LEN: usize = 4;

//struct Ed25519Signature {
//    sign: [u8; SIGN_LEN],
//}

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

#[derive(Debug)]
#[derive(PartialEq)]
enum StsStage {
    Init,
    //WaitMsg1,
    WaitMsg2,
    //WaitMsg3,
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
struct GecSts {
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

#[allow(dead_code)]
fn print_array(b: &[u8]) {
    print!("data=[");
    for i in b {
        print!("0x{:x},", i);
    }
    println!("];");

}


fn transform_u32_to_array_of_u8(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b4, b3, b2, b1];
}



/// Main serial thread
///
/// Manages reading/writing to/from the serial port `port_name`
/// at given `baudrate`, and requires a dictionary of messages.
///
/// Every SYNC_PERIOD ms it sends SYNC/CHANNEL message and any pending
/// messages stored in the message queue.
///
/// Otherwise reads from serial port, and if receives a new message it sends
/// it over IVY bus.
///
/// If new message from IVY bus is to be send, it saves it to the message queue (FIFO).
fn thread_main(
    port_name: OsString,
    baudrate: usize,
    dictionary: Arc<PprzDictionary>,
    status_report_period: u64,
    p_a: [u8; KEY_LEN],
    q_a: [u8; KEY_LEN],
    p_b: [u8; KEY_LEN],
) -> Result<(), Box<Error>> {
    let port = serial::open(&port_name)?;
    let mut port = match configure_port(port, baudrate) {
        Ok(port) => port,
        Err(e) => return Err(e),
    };

    // initialize variables LINK_REPORT
    let mut status_report_timer = Instant::now();
    let status_report_period = Duration::from_millis(status_report_period);
    let mut report_msg = dictionary
        .find_msg_by_name(String::from("LINK_REPORT").as_ref())
        .expect("LINK_REPORT message not found");
    let mut status_report = RustlinkStatusReport {
        tx_bytes: 0,
        rx_bytes: 0,
        rx_msgs: 0,
        tx_msgs: 0,
        last_tx_bytes: 0,
        last_rx_bytes: 0,
        last_rx_msgs: 0,
        last_tx_msgs: 0,
    };

    // initialize an emty buffer
    let mut buf = [0; 255]; // still have to manually allocate an array
    let mut rx = PprzTransport::new();

    // get debug time
    let debug_time = RustlinkTime { time: Instant::now() };

    // initialize sts struct
    let mut sts = GecSts::new(&p_a, &q_a, &p_b);

    // get current time
    //let mut instant = Instant::now();


    loop {

        if sts.stage == StsStage::CryptoOK {
            // process messages from the queue and encrypt them before sending
            let mut lock = MSG_QUEUE.lock();
            if let Ok(ref mut msg_queue) = lock {
                //println!("{} MSG_queue locked", debug_time.elapsed());
                while !msg_queue.is_empty() {
                    // get a message from the front of the queue
                    let new_msg = msg_queue.pop_front().unwrap();
                    println!("Sending {}", new_msg.to_string().unwrap());

                    // get a transort
                    let mut tx = PprzTransport::new();
                    let mut buf = vec![];

                    // construct a message from the transport

                    // update counter
                    sts.my_symmetric_key.ctr = sts.my_symmetric_key.ctr + 1;
                    let counter = transform_u32_to_array_of_u8(sts.my_symmetric_key.ctr.to_le());
                    sts.my_symmetric_key.nonce[0] = counter[0];
                    sts.my_symmetric_key.nonce[1] = counter[1];
                    sts.my_symmetric_key.nonce[2] = counter[2];
                    sts.my_symmetric_key.nonce[3] = counter[3];
                    
                    //println!("my key: {:?}", sts.my_symmetric_key.key);

                    // transport handles STX + len + checksum (4 bytes)
                    // COUNTER 4 bytes
                    buf.push(counter[0]);
                    buf.push(counter[1]);
                    buf.push(counter[2]);
                    buf.push(counter[3]);

                    // encrypt message
                    let plaintext = new_msg.to_bytes();
                    let mut ciphertext = plaintext.clone();
                    let mut mac = vec![0; MAC_LEN];
                    let aad = vec![];

                    let success = match rusthacl::chacha20poly1305_aead_encrypt(
                        ciphertext.as_mut_slice(),
                        mac.as_mut_slice(),
                        &plaintext,
                        &aad,
                        &sts.my_symmetric_key.key,
                        &sts.my_symmetric_key.nonce,
                    ) {
                        Ok(val) => val,
                        Err(msg) => panic!("Error! {}", msg),
                    };
                    
                    if !success {
                    	println!("error encrypting message");
                    	break;
                    }
                    
                    // add ciphertext
                    buf.append(&mut ciphertext);
                    
                    // add mac
                    buf.append(&mut mac);

                    tx.construct_pprz_msg(&buf);
                    //println!("message len = {}", tx.buf.len());
                    //print_array(&tx.buf);

                    let len = port.write(&tx.buf)?;
                    status_report.tx_bytes += len;
                    status_report.tx_msgs += 1;
                    if len != tx.buf.len() {
                        println!(
                            "{} Written {} bytes, but the message was {} bytes",
                            debug_time.elapsed(),
                            len,
                            tx.buf.len()
                        );
                    }
                }
            }
        } else {
            // match the protocol stage and send messages if needed
            match sts.stage {
                StsStage::Init => {
                    // set to MSG 1
                    // initiate sts
                    // 1. A generates an ephemeral (random) curve25519 key pair (Pae, Qae) and sends Pae.
                    // generate public and private keys
                    let mut rng = match OsRng::new() {
                        Ok(gen) => gen,
                        Err(e) => panic!("Failed to obtain OS RNG: {}", e),
                    };

                    let mut p_ae: [u8; KEY_LEN] = [0; KEY_LEN];
                    let mut q_ae: [u8; KEY_LEN] = [0; KEY_LEN];
                    let mut basepoint: [u8; KEY_LEN] = [0; KEY_LEN];
                    basepoint[0] = 9;

                    rng.fill_bytes(&mut q_ae);

                    rusthacl::curve25519_crypto_scalarmult(&mut p_ae, &q_ae, &basepoint).unwrap();

                    let my_ephemeral = GecPrivKey {
                        privkey: q_ae,
                        pubkey: p_ae,
                    };
                    // set the ephemeral keys
                    sts.my_private_ephemeral = my_ephemeral;

                    // create a new message
                    let mut msg1 = dictionary
                        .find_msg_by_name(String::from("KEY_EXCHANGE_GCS").as_ref())
                        .unwrap();

                    // lets build the buffer manually (TODO: add proper handlers to pprzlink)
                    // source=0 (GCS), msg_id, type, p_ae
                    let mut msg1_buf: Vec<u8> =
                        vec![0, msg1.id, StsMsgType::P_AE as u8, KEY_LEN as u8];
                    for idx in 0..KEY_LEN {
                        msg1_buf.push(sts.my_private_ephemeral.pubkey[idx]);
                    }
                    msg1.update(&msg1_buf);

                    // get a transort
                    let mut tx = PprzTransport::new();
                    tx.construct_pprz_msg(&msg1.to_bytes());
                    println!("MSG1: {:?}", tx.buf);

                    let len = port.write(&tx.buf)?;
                    status_report.tx_bytes += len;
                    status_report.tx_msgs += 1;
                    if len != tx.buf.len() {
                        println!(
                            "{} Written {} bytes, but the message was {} bytes",
                            debug_time.elapsed(),
                            len,
                            tx.buf.len()
                        );
                    }

                    // if OK
                    sts.stage = StsStage::WaitMsg2; // will be handled upon receiving a message
                }
                StsStage::WaitMsg2 => {
                    // check for timeout
                    // if OK
                    // sts.stage = StsStage::CryptoOK;
                }
                _ => {
                    // illegal states, shouldn't ever happen
                }
            }
        }


        // read data (no timeout right now)
        let len = match port.read(&mut buf[..]) {
            Ok(len) => len,
            Err(_) => continue,
        };
        status_report.rx_bytes += len;
        println!("received {} bytes", len);

        // parse received data and optionally send a message
        // spprz_check_and_parse()
        for idx in 0..len {
            //println!("byte = {:x}", buf[idx]);
            if rx.parse_byte(buf[idx]) {
                //
                if sts.stage == StsStage::CryptoOK {
                    // handle encrypted messages
                    // and continue as normal
                    // the format is
                    // COUNTER (4 bytes)
                    // encrypted SENDER_ID
                    // encrypted MSG_ID
                    // encrypted MSG_PAYLOAD (messages.xml)
                    // TAG (16 bytes)
                    //println!("Got encrypted message!");
                    //print_array(&rx.buf);

                    // check counter
                    let counter: u32 = u32::from_le(
                        rx.buf[0] as u32 | (rx.buf[1] as u32) << 8 | (rx.buf[2] as u32) << 16 |
                            (rx.buf[3] as u32) << 24,
                    );
                    if counter <= sts.their_symmetric_key.ctr {
                        println!(
                            "Counter error: curret = {}, received = {}",
                            sts.their_symmetric_key.ctr,
                            counter
                        );
                    } else {
                        // update counter
                        sts.their_symmetric_key.ctr = counter;
                    }

                    // update nonce
                    sts.their_symmetric_key.nonce[0] = rx.buf[0];
                    sts.their_symmetric_key.nonce[1] = rx.buf[1];
                    sts.their_symmetric_key.nonce[2] = rx.buf[2];
                    sts.their_symmetric_key.nonce[3] = rx.buf[3];

                    // get length
                    let clen: usize = rx.length as usize;
                    /*
                    println!("clen={}", clen);
                    println!("rx.length={}", rx.length);
                    println!("counter={}", sts.their_symmetric_key.ctr);
                    println!("rx.buf=");
                    print_array(&rx.buf);
                    println!("nonce=");
                    print_array(&sts.their_symmetric_key.nonce);
                    println!("mac=");
                    print_array(&rx.buf[clen - MAC_LEN..clen]);
                    println!("ciphertext=");
                    print_array(&rx.buf[COUNTER_LEN..clen - MAC_LEN]);
                    println!("my nonce: {:?}", sts.my_symmetric_key.nonce);
                    println!("their nonce: {:?}", sts.their_symmetric_key.nonce);
*/

                    let mut pt: Vec<u8> = vec![0; clen - CRYPTO_OVERHEAD];
                    let aad = vec![];
                    let sucess = match rusthacl::chacha20poly1305_aead_decrypt(
                        pt.as_mut_slice(), // plaintext
                        &rx.buf[clen - MAC_LEN..clen], // mac
                        &rx.buf[COUNTER_LEN..clen - MAC_LEN], // ciphertext
                        &aad,
                        &sts.their_symmetric_key.key,
                        &sts.their_symmetric_key.nonce,
                    ) {
                        Ok(val) => val,
                        Err(msg) => panic!("Error! {}", msg),
                    };

                    if sucess {
                        // copy over to rx.buf
                        //println!("Decrypt ok, buf={:?}", rx.buf);
                        rx.buf.resize(pt.len(), 0);
                        rx.buf.clone_from_slice(pt.as_slice());

                    } else {
                        // drop the message
                        println!("decrypt not sucessful");
                        continue;
                    }
                } else {
                    // process unencrypted messages
                    // spprz_process_sts_msg()
                    match sts.stage {
                        StsStage::WaitMsg2 => {
                            // expecting KEY_EXCHANGE_UAV, type P_BE
                            // assume it came with the right AC_ID
                            // create a new message
                            let mut msg2 = dictionary
                                .find_msg_by_name(String::from("KEY_EXCHANGE_UAV").as_ref())
                                .unwrap();
                            // the buffer contains all the data
                            if msg2.id != rx.buf[1] {
                                println!("expected msg id = {}, received {}", msg2.id, rx.buf[1]);
                                continue;
                            }

                            if StsMsgType::P_BE as u8 != rx.buf[2] {
                                println!(
                                    "expected msg type = {:?}, received {}",
                                    StsMsgType::P_BE as u8,
                                    rx.buf[2]
                                );
                                continue;
                            }
                            // update message ?
                            //msg2.update(&rx.buf);

                            // message2 = [ Pbe (32 bytes) | Encrypted Signature (64 bytes) | MAC (16 bytes) ]
                            let payload_len = 112;
                            if payload_len != rx.buf[3] {
                                println!(
                                    "expected payload len = {}, received {}",
                                    payload_len,
                                    rx.buf[3]
                                );
                                continue;
                            }
                            let payload = &rx.buf[4..payload_len as usize + 4];
                            let p_be = &payload[0..KEY_LEN];
                            sts.their_public_ephemeral.pubkey.clone_from_slice(p_be);
                            let encrypted_sign = &payload[KEY_LEN..KEY_LEN + SIGN_LEN];
                            let mac = &payload[KEY_LEN + SIGN_LEN..KEY_LEN + SIGN_LEN + MAC_LEN];

                            // 7. A computes the shared secret: z = scalar_multiplication(Qae, Pbe)
                            let mut z: [u8; KEY_LEN] = [0; KEY_LEN];
                            // Curve25519_crypto_scalarmult(z, sts.myPrivateKeyEphemeral.priv, sts.theirPublicKeyEphemeral.pub);
                            rusthacl::curve25519_crypto_scalarmult(
                                &mut z,
                                &sts.my_private_ephemeral.privkey,
                                &p_be,
                            ).unwrap();

                            // 8. A uses the key derivation function kdf(z,1) to compute Kb || Sb, kdf(z,0) to compute Ka || Sa, and kdf(z,2)
                            // kdf(z,0) to compute Ka || Sa
                            let mut ka_sa = vec![0; 64];
                            let mut input = z.to_vec();
                            input.push(StsParty::Initiator as u8);
                            assert_eq!(
                                rusthacl::sha2_512_hash(ka_sa.as_mut_slice(), input.as_slice()),
                                Ok(())
                            );
                            input.pop();
                            // update my symmetric key
                            sts.my_symmetric_key.key.clone_from_slice(
                                &ka_sa[0..KEY_LEN],
                            );
                            sts.my_symmetric_key.nonce.clone_from_slice(
                                &ka_sa[KEY_LEN..
                                           KEY_LEN + NONCE_LEN],
                            );

                            // kdf(z,1) to compute Kb || Sb
                            let mut kb_sb = vec![0; 64];
                            input.push(StsParty::Responder as u8);
                            assert_eq!(
                                rusthacl::sha2_512_hash(kb_sb.as_mut_slice(), input.as_slice()),
                                Ok(())
                            );
                            // update their symmetric key
                            sts.their_symmetric_key.key.clone_from_slice(
                                &kb_sb[0..KEY_LEN],
                            );
                            sts.their_symmetric_key.nonce.clone_from_slice(
                                &kb_sb[KEY_LEN..
                                           KEY_LEN + NONCE_LEN],
                            );

                            // 9. A decrypts the remainder of the message, verifies the signature.
                            // Pbe || Ekey=Kb,IV=Sb||zero(sig)
                            let mut sig = [0; SIGN_LEN];
                            let aad = vec![];
                            let success = match rusthacl::chacha20poly1305_aead_decrypt(
                                &mut sig,
                                mac,
                                encrypted_sign,
                                &aad,
                                &sts.their_symmetric_key.key,
                                &sts.their_symmetric_key.nonce,
                            ) {
                                Ok(val) => val,
                                Err(msg) => panic!("Error! {}", msg),
                            };
                            assert_eq!(success, true);

                            println!(">>>>  9. verifies the signature.");
                            let mut pbe_pae: Vec<u8> = vec![];
                            pbe_pae.extend_from_slice(&sts.their_public_ephemeral.pubkey); // p_be
                            pbe_pae.extend_from_slice(&sts.my_private_ephemeral.pubkey); // p_ae

                            let success = match rusthacl::ed25519_verify(
                                &sts.their_public_key.pubkey,
                                &pbe_pae,
                                &sig,
                            ) {
                                Ok(val) => val,
                                Err(msg) => panic!("Error! {}", msg),
                            };
                            assert_eq!(success, true);
                            println!("A signature verified: {}", success);

                            // 10. A computes the ed25519 signature: sig = signQa(Pbe || Pae)
                            println!(
                                ">>>>  10. A computes the ed25519 signature: sig = signQa(Pbe || Pae)"
                            );
                            let mut sig: [u8; SIGN_LEN] = [0; SIGN_LEN];
                            assert_eq!(
                                rusthacl::ed25519_sign(
                                    &mut sig,
                                    &sts.my_private_key.privkey,
                                    pbe_pae.as_slice(),
                                ),
                                Ok(())
                            );

                            // 11. A computes and sends the message Ekey=Ka,IV=Sa||zero(sig)
                            println!(
                                ">>>>  11. A computes and sends the message Ekey=Ka,IV=Sa||zero(sig)"
                            );
                            let mut mac: [u8; MAC_LEN] = [0; MAC_LEN];
                            let aad = vec![];
                            let mut ciphertext: [u8; SIGN_LEN] = [0; SIGN_LEN];

                            let success = match rusthacl::chacha20poly1305_aead_encrypt(
                                &mut ciphertext,
                                &mut mac,
                                &sig,
                                &aad,
                                &sts.my_symmetric_key.key,
                                &sts.my_symmetric_key.nonce,
                            ) {
                                Ok(val) => val,
                                Err(msg) => panic!("Error! {}", msg),
                            };
                            assert_eq!(success, true);

                            // send the message
                            // create a new message
                            let mut msg3 = dictionary
                                .find_msg_by_name(String::from("KEY_EXCHANGE_GCS").as_ref())
                                .unwrap();

                            // lets build the buffer manually (TODO: add proper handlers to pprzlink)
                            // source=0 (GCS), msg_id, type, signature
                            let mut msg3_buf: Vec<u8> = vec![
                                0,
                                msg3.id,
                                StsMsgType::SIG as u8,
                                (SIGN_LEN + MAC_LEN) as u8,
                            ];
                            for idx in 0..SIGN_LEN {
                                msg3_buf.push(ciphertext[idx]);
                            }
                            for idx in 0..MAC_LEN {
                                msg3_buf.push(mac[idx]);
                            }
                            msg3.update(&msg3_buf);

                            // get a transort
                            let mut tx = PprzTransport::new();
                            tx.construct_pprz_msg(&msg3.to_bytes());
                            println!("MSG3: {:?}", tx.buf);

                            let len = port.write(&tx.buf)?;
                            status_report.tx_bytes += len;
                            status_report.tx_msgs += 1;
                            if len != tx.buf.len() {
                                println!(
                                    "{} Written {} bytes, but the message was {} bytes",
                                    debug_time.elapsed(),
                                    len,
                                    tx.buf.len()
                                );
                            }
                            // set status to crypto ok
                            sts.stage = StsStage::CryptoOK;
                        }
                        _ => {
                            // ignore other states and log error
                        }
                    }
                    // and continue with `continue;` to skip the rest of the loop
                    continue;
                }

                //
                //  REGULAR COMMUNICATION
                //
                // we get here if we decrypted the message sucessfully
                //println!("msg_id={}", rx.buf[1]);

                status_report.rx_msgs += 1;
                let name = dictionary
                    .get_msg_name(PprzMsgClassID::Telemetry, rx.buf[1])
                    .unwrap();
                let mut msg = dictionary.find_msg_by_name(&name).unwrap();

                //println!("Found message: {}", msg.name);
                //println!("Found sender: {}", rx.buf[0]);

                // update message fields with real values
                msg.update(&rx.buf);

                // check for PONG
                if msg.name == "PONG" {
                    // update time
                    pong_ivy_callback(vec![]);
                }

                // send the message
//                println!(
//                    "{} Received new msg: {}",
//                    debug_time.elapsed(),
//                    msg.to_string().unwrap()
//                );
                ivyrust::ivy_send_msg(msg.to_string().unwrap());
            } // end parse byte
        } // end for idx in 0..len


        // update status & send status message if needed
        if status_report_timer.elapsed() >= status_report_period {
            report_msg = update_status(report_msg, &mut status_report, status_report_period);

            // reset the timer
            status_report_timer = Instant::now();
        }

    } // end-loop
}




/// Configure port to given settings
///
/// We can specify the device name and the baudrate
/// The default timeout is zero (non-blocking read/write)
fn configure_port(
    mut port: serial::SystemPort,
    baud: usize,
) -> Result<serial::SystemPort, Box<Error>> {
    let baud = serial::core::BaudRate::from_speed(baud);
    let settings = serial::core::PortSettings {
        baud_rate: baud,
        char_size: serial::Bits8,
        parity: serial::ParityNone,
        stop_bits: serial::Stop1,
        flow_control: serial::FlowNone,
    };

    port.configure(&settings)?;
    // sleeping for on millisecond seems to be a good compromise
    port.set_timeout(Duration::from_millis(1))?;

    Ok(port)
}


/// Main IVY loop
///
/// This thread only launchees `IvyMainLoop()` and loops forever
/// Uses the optional argument specifying a non-default bus address
fn thread_ivy_main(ivy_bus: String) -> Result<(), Box<Error>> {
    ivyrust::ivy_init(String::from("Link"), String::from("Ready"));
    if !ivy_bus.is_empty() {
        ivyrust::ivy_start(Some(ivy_bus));
    } else {
        ivyrust::ivy_start(None);
    }
    ivyrust::ivy_main_loop()
}


/// Match with PONG message
/// that way we can update the ping time
/// NOTE: it is not super exact (depending on how fast
/// is the IVY bus, but it seems to be easier and probably
/// good enough at least for now);
fn pong_ivy_callback(_: Vec<String>) {
    //println!("Got PONG callback");
    // we just got PONG back

    let mut ping_value_s = -1.0;

    // update the ping time
    let mut time_lock = PING_TIME.lock();
    if let Ok(ref mut ping_time) = time_lock {
        let start_time = **ping_time;
        let duration = start_time.elapsed();
        **ping_time = start_time;

        ping_value_s = duration.as_secs() as f32 + (duration.subsec_nanos() as f32 * 1e-9);
    } // PING_TIME mutex unlock

    // update the value
    let mut time_lock = PING_TIME_VALUE.lock();
    if let Ok(ref mut ping_time) = time_lock {
        // update the value (exponential moving average)
        let alpha = 0.1;
        **ping_time = alpha * ping_value_s + (1.0 - alpha) * **ping_time;
        //println!("PONG TIME: new: {}, cumm: {}", ping_value_s, **ping_time);
    }
}

/// Send PING message
///
/// Push PING at the beginning of the queue
/// and then sleep for `period` ms
fn thread_ping(period: u64, dictionary: Arc<PprzDictionary>) {
    // subscribe the message
    let pong_msg = dictionary
        .find_msg_by_name(String::from("PONG").as_ref())
        .unwrap();

    //println!("Bindinfg with {}", pong_msg.to_ivy_regexpr());
    let _ = ivy_bind_msg(pong_ivy_callback, pong_msg.to_ivy_regexpr());

    // we need to send SYNC: get sync message
    let ping_msg = dictionary
        .find_msg_by_name(String::from("PING").as_ref())
        .expect("Ping message not found");
    loop {
        // the sender ID is set to zero by default

        // add at the beginning of the message gueue
        {
            let mut msg_lock = MSG_QUEUE.lock();
            if let Ok(ref mut msg_queue) = msg_lock {
                // push to front
                //println!("Pushing PING message");
                msg_queue.push_front(ping_msg.clone());

                //println!("PING: Message queue len: {}", msg_queue.len());

                // update the ping time
                let mut time_lock = PING_TIME.lock();
                if let Ok(ref mut ping_time) = time_lock {
                    let start_time = Instant::now();
                    **ping_time = start_time;
                    //println!("Updating PING TIME");
                }
            }
        }

        thread::sleep(time::Duration::from_millis(period));
    }
}


/// This global callback is just a cludge,
/// because we can not currently bind individual messages separately
/// like `ivy_bind_msg(my_msg.callback(), my_msg.to_ivy_regexpr())`
///
/// Instead, we use a shared static variable as `Vec<PprzMessage>` and
/// another static variable for a `Vec<PprzDictionary>` to hold the parsed
/// messages. When a callback is received, it will be a single string containing
/// the whole message, for example '1 RTOS_MON 15 0 76280 0 495.53').
///
/// We parse the name and match it with regexpr for Datalink class, if it matches
/// the global vec of messages will be updated.
fn global_ivy_callback(mut data: Vec<String>) {
    // TODO: we don't really need a regexpr, can just split and match the individual strings...
    let data = &(data.pop().unwrap());
    let mut lock = DICTIONARY.try_lock();

    // continue only if the message came from the ground
    if !RE_DATALINK.is_match(data) {
        return;
    }

    if let Ok(ref mut dictionary_vector) = lock {
        if !dictionary_vector.is_empty() {
            let dictionary = dictionary_vector.pop().unwrap();
            if dictionary.contains(PprzMsgClassID::Datalink) {
                let msgs = dictionary
                    .get_msgs(PprzMsgClassID::Datalink)
                    .unwrap()
                    .messages;

                // iterate over messages
                for mut msg in msgs {
                    //let pattern = msg.to_ivy_regexpr();
                    let pattern = String::from("ground_dl ") + &msg.name + " .*";
                    let re = Regex::new(&pattern).unwrap();
                    if re.is_match(data) {
                        // parse the message and push it into the message queue
                        let values: Vec<&str> = data.split(' ').collect();

                        // set the sender to be 0 (that is default)

                        // set msg name (but we already know it)

                        // update from strig
                        msg.update_from_string(&values);
                        //println!("new message is: {}", msg);

                        // if found, update the global msg
                        let mut msg_lock = MSG_QUEUE.lock();
                        if let Ok(ref mut msg_vector) = msg_lock {
                            // append at the end of vector
                            msg_vector.push_back(msg);
                            //println!("Global callback: msg vector len = {}", msg_vector.len());
                        }
                        break;
                    }
                }

            } else {
                println!("Dictionary doesn't contain Datalink message class");
            }

            // push the dictionary back (sight)
            dictionary_vector.push(dictionary);
        }
    }
}

struct RustlinkStatusReport {
    tx_bytes: usize,
    rx_bytes: usize,
    rx_msgs: usize,
    tx_msgs: usize,
    last_tx_bytes: usize,
    last_rx_bytes: usize,
    last_rx_msgs: usize,
    last_tx_msgs: usize,
}

struct RustlinkTime {
    time: Instant,
}

impl RustlinkTime {
    fn elapsed(&self) -> f64 {
        let duration = self.time.elapsed();
        duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9
    }
}



/// Update status is called every time we get new data, we just store the new values
fn update_status(
    mut msg: PprzMessage,
    status_report: &mut RustlinkStatusReport,
    status_msg_period: Duration,
) -> PprzMessage {

    let dt_seconds = status_msg_period.as_secs() as f32 +
        (status_msg_period.subsec_nanos() as f32 * 1e-9);

    for field in &mut msg.fields {
        match field.name.as_ref() {
            "ac_id" => {
                // this is AC_ID, we can leave blank for now
                field.value = PprzMsgBaseType::String(String::from("4"));
            }
            "link_id" => {
                // link ID will be -1 unless we explicitly set it
                field.value = PprzMsgBaseType::String(String::from("-1"));

            }
            "run_time" => {
                // increment runtime
                if let PprzMsgBaseType::Uint32(v) = field.value {
                    field.value = PprzMsgBaseType::Uint32((v as f32 + dt_seconds) as u32);
                }
            }
            "rx_lost_time" => {
                if status_report.rx_msgs == status_report.last_rx_msgs {
                    // no new messages
                    if let PprzMsgBaseType::Uint32(v) = field.value {
                        field.value = PprzMsgBaseType::Uint32((v as f32 + dt_seconds) as u32);
                    }
                }
            }
            "rx_bytes" => {
                field.value = PprzMsgBaseType::Uint32(status_report.rx_bytes as u32);
            }
            "rx_msgs" => {
                field.value = PprzMsgBaseType::Uint32(status_report.rx_msgs as u32);
            }
            "rx_err" => {
                // we dont really have a way to tell the errors, so keep as zero
                field.value = PprzMsgBaseType::Uint32(0);
            }
            "rx_bytes_rate" => {
                let byte_rate = (status_report.rx_bytes - status_report.last_rx_bytes) as f32 /
                    dt_seconds;
                field.value = PprzMsgBaseType::Float(byte_rate);
            }
            "rx_msgs_rate" => {
                let byte_rate = (status_report.rx_msgs - status_report.last_rx_msgs) as f32 /
                    dt_seconds;
                field.value = PprzMsgBaseType::Float(byte_rate);
            }
            "tx_msgs" => {
                field.value = PprzMsgBaseType::Uint32(status_report.tx_msgs as u32);
            }
            "ping_time" => {
                let mut ping = -1.0;

                // acquire last ping time
                let mut time_lock = PING_TIME_VALUE.lock();
                if let Ok(ref mut ping_time) = time_lock {
                    ping = **ping_time;
                }
                field.value = PprzMsgBaseType::Float(ping * 1000.0); // convert to ms
            }
            _ => {
                println!("update_status: Unknown field");
            }
        } // end match
    } // end for

    //println!("Status message: {}", msg);

    // time is up, send the report
    let mut s = msg.to_string().unwrap();
    s.remove(0);
    s.insert_str(0, "link");
    ivyrust::ivy_send_msg(s);

    // update the report
    status_report.last_rx_bytes = status_report.rx_bytes;
    status_report.last_tx_bytes = status_report.tx_bytes;
    status_report.last_rx_msgs = status_report.rx_msgs;
    status_report.last_tx_msgs = status_report.tx_msgs;

    msg
}


fn main() {
    // Construct command line arguments
    let matches = App::new("Rustlink for Paparazzi")
        .version("0.1")
        .arg(
            Arg::with_name("ivy_bus")
                .short("b")
                .value_name("ivy_bus")
                .help("Default is 127.255.255.255:2010")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("d")
                .value_name("port")
                .help("Default is /dev/ttyUSB0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("baudrate")
                .short("s")
                .value_name("baudrate")
                .help("Default is 9600")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("status_period")
                .short("t")
                .long("status_period")
                .value_name("status_period")
                .help(
                    "Sets the period (in ms) of the LINK_REPORT status message. Default is 1000",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ping_period")
                .short("n")
                .long("ping_period")
                .value_name("ping_period")
                .help(
                    "Sets the period (in ms) of the PING message sent to aircrafs. Default is 5000",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ac_name")
                .short("a")
                .value_name("aircraft name")
                .help("Name of the aircraft (to find keys_gcs.h)")
                .takes_value(true),
        )
        .get_matches();

    let ivy_bus = matches.value_of("ivy_bus").unwrap_or(
        "127.255.255.255:2010",
    );
    let ivy_bus = String::from(ivy_bus);
    println!("Value for ivy_bus: {}", ivy_bus);

    let ping_period = matches.value_of("ping_period").unwrap_or("1000");
    let ping_period = ping_period.parse::<u64>().expect("Incorrect ping period");
    println!("Value for ping_period: {}", ping_period);

    let status_period = matches.value_of("status_period").unwrap_or("5000");
    let status_period = status_period.parse::<u64>().expect(
        "Incorrect status period",
    );
    println!("Value for status_period: {}", status_period);

    let baudrate = matches.value_of("baudrate").unwrap_or("9600");
    let baudrate = baudrate.parse::<usize>().expect("Incorrect baudrate");
    println!("Value for baudrate: {}", baudrate);

    let port = matches.value_of("port").unwrap_or("/dev/ttyUSB0");
    let port = OsString::from(port);
    println!("Value for port: {:?}", port);

    let ac_name = matches.value_of("ac_name").expect("AC name not found");
    println!("Value for aircraft name: {:?}", ac_name);

    let pprz_root = match env::var("PAPARAZZI_SRC") {
        Ok(var) => var,
        Err(e) => {
            println!("Error getting PAPARAZZI_SRC environment variable: {}", e);
            return;
        }
    };

    // spin the main IVY loop
    let _ = thread::spawn(move || if let Err(e) = thread_ivy_main(ivy_bus) {
        println!("Error starting ivy thread: {}", e);
    } else {
        println!("Ivy thread finished");
    });


    // open the GCS keys file
    let keys_file = pprz_root.clone() + "/var/aircrafts/" + ac_name + "/ap/generated/keys_gcs.h";
    let file = File::open(keys_file).unwrap();
    let file = BufReader::new(&file);

    let pattern_my_pubkey = String::from("#define GCS_PUBLIC") + " .*";
    let re_p_a = Regex::new(&pattern_my_pubkey).unwrap();
    let pattern_my_privkey = String::from("#define GCS_PRIVATE") + " .*";
    let re_q_a = Regex::new(&pattern_my_privkey).unwrap();
    let pattern_their_pubkey = String::from("#define UAV_PUBLIC") + " .*";
    let re_p_b = Regex::new(&pattern_their_pubkey).unwrap();

    // initialize asymetric keys
    let mut p_a: [u8; 32] = [0; 32];
    let mut q_a: [u8; 32] = [0; 32];
    let mut p_b: [u8; 32] = [0; 32];

    for (_, line) in file.lines().enumerate() {
        let line = line.unwrap();
        if re_p_a.is_match(&line) {
            let mut data: Vec<&str> = line.split(|c| c == ' ').collect();
            let data = data.pop().unwrap();
            let mut data: Vec<&str> = data.split(|c| c == ',' || c == '{' || c == '}').collect();

            let mut idx = 0;
            for value in data {
                match value.parse::<u8>() {
                    Ok(v) => {
                        p_a[idx] = v;
                        idx = idx + 1;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            continue;
        }

        let mut idx = 0;
        if re_q_a.is_match(&line) {
            let mut data: Vec<&str> = line.split(|c| c == ' ').collect();
            let data = data.pop().unwrap();
            let mut data: Vec<&str> = data.split(|c| c == ',' || c == '{' || c == '}').collect();

            for value in data {
                match value.parse::<u8>() {
                    Ok(v) => {
                        q_a[idx] = v;
                        idx = idx + 1;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            continue;
        }

        let mut idx = 0;
        if re_p_b.is_match(&line) {
            let mut data: Vec<&str> = line.split(|c| c == ' ').collect();
            let data = data.pop().unwrap();
            let mut data: Vec<&str> = data.split(|c| c == ',' || c == '{' || c == '}').collect();

            for value in data {
                match value.parse::<u8>() {
                    Ok(v) => {
                        p_b[idx] = v;
                        idx = idx + 1;
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
            continue;
        }
    }

    // prepare the dictionary
    let xml_file = pprz_root + "/sw/ext/pprzlink/message_definitions/v1.0/messages.xml";
    let file = File::open(xml_file.clone()).unwrap();
    let dictionary = parser::build_dictionary(file);

    // push into the callback dictionary
    DICTIONARY.lock().unwrap().push(dictionary);

    // construct a dictionary
    let file = File::open(xml_file).unwrap();
    let dictionary = parser::build_dictionary(file);
    let dictionary = Arc::new(dictionary);
    let dictionary_scheduler = Arc::clone(&dictionary);
    let dictionary_ping = Arc::clone(&dictionary);
    // spin the serial loop
    let t = thread::spawn(move || if let Err(e) = thread_main(
        port,
        baudrate,
        dictionary_scheduler,
        status_period,
        p_a,
        q_a,
        p_b,
    )
    {
        println!("Error starting main thread: {}", e);
    } else {
        println!("Main thread finished");
    });

    // ping periodic
    let _ = thread::spawn(move || thread_ping(ping_period, dictionary_ping));

    // bind global callback
    let _ = ivy_bind_msg(global_ivy_callback, String::from("(.*)"));

    // close
    t.join().expect("Error waiting for serial thread to finish");

    // end program
    ivyrust::ivy_stop();
}
