#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate serial;
extern crate ivyrust;
extern crate pprzlink;
extern crate rand;

mod comms;
mod configs;

use comms::*;
use configs::*;

use ivyrust::*;
use std::{thread, time};
use std::error::Error;

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


#[allow(dead_code)]
fn print_array(b: &[u8]) {
    print!("data=[");
    for i in b {
        print!("0x{:x},", i);
    }
    println!("];");

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
    config: Arc<LinkConfig>,
    dictionary: Arc<PprzDictionary>,
) -> Result<(), Box<Error>> {
    
    let mut port = match LinkComm::new(Arc::clone(&config)) {
    	Ok(p) => p,
    	Err(e) => panic!("Comm initialization failed: {}", e),
    };

    // initialize variables LINK_REPORT
    let mut status_report_timer = Instant::now();
    let status_report_period = Duration::from_millis(config.status_period);
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

    // get current time
    //let mut instant = Instant::now();

    loop {
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
                    let mut buf = new_msg.to_bytes();

                    // construct a message from the transport
                    tx.construct_pprz_msg(&buf);
                    //println!("message len = {}", tx.buf.len());
                    //print_array(&tx.buf);

                    let len = port.com_write(tx.buf.as_mut_slice())?;
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


        // read data (no timeout right now)
        let len = match port.com_read(&mut buf[..]) {
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
                //  REGULAR COMMUNICATION
                //
                // we get here if we decrypted the message sucessfully
                //println!("msg_id={}", rx.buf[1]);

                status_report.rx_msgs += 1;
                let name = dictionary
                    .get_msg_name(
                    	PprzMsgClassID::Telemetry,
                    	PprzMessage::get_msg_id_from_buf(&rx.buf, dictionary.protocol))
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
fn thread_ping(config: Arc<LinkConfig>, dictionary: Arc<PprzDictionary>) {
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

        thread::sleep(time::Duration::from_millis(config.ping_period));
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


fn start_ivy_main_loop(config: Arc<LinkConfig>) {
	// spin the main IVY loop
    let _ = thread::spawn(move || if let Err(e) = thread_ivy_main(config.ivy_bus.clone()) {
        println!("Error starting ivy thread: {}", e);
    } else {
        println!("Ivy thread finished");
    });
}


/// PprzDictionary is always borrowed immutably, no need for a mutex
fn build_dictionary(config: Arc<LinkConfig>) -> Arc<PprzDictionary> {
	// construct a dictionary
	let xml_file = config.pprz_root.clone() + "/sw/ext/pprzlink/message_definitions/v1.0/messages.xml";
    let file = File::open(xml_file).unwrap();
    Arc::new(parser::build_dictionary(file,config.pprzlink_version))
}

fn main() {
	// Initialize
	let config = init_and_configure();
	let dictionary = build_dictionary(Arc::clone(&config));
	
	// spin ivy main loop
	let conf = Arc::clone(&config);
	start_ivy_main_loop(conf);
	
    // spin the serial loop
    let conf = Arc::clone(&config);
    let dict = Arc::clone(&dictionary);
    let t = thread::spawn(move || if let Err(e) = thread_main(
        conf,
        dict,
    )
    {
        println!("Error starting main thread: {}", e);
    } else {
        println!("Main thread finished");
    });

    // ping periodic
    let conf = Arc::clone(&config);
    let dict = Arc::clone(&dictionary);
    let _ = thread::spawn(move || thread_ping(conf, dict));

    // bind global callback
    //let _ = ivy_bind_msg(global_ivy_callback, String::from("(.*)"));

    // close
    t.join().expect("Error waiting for serial thread to finish");

    // end program
    ivyrust::ivy_stop();
}
