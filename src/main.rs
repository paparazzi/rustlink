#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate serial;
extern crate ivyrust;
extern crate pprzlink;




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

lazy_static! {
    static ref MSG_QUEUE: Mutex<Vec<PprzMessage>> = Mutex::new(vec![]);
    static ref DICTIONARY: Mutex<Vec<PprzDictionary>> = Mutex::new(vec![]);
    static ref RE_DATALINK: Regex = Regex::new("ground_dl .*").unwrap();
}

const PERIOD_MS: u64 = 50;
const CHANNEL_LEN: u64 = 7;
const MS_PER_BYTE: f32 = 0.17;
const PROTECTION_PERIOD: u64 = 6;
const MAX_MSG_SIZE: usize = 256;

/// Max number of bytes we can send before we can forfeit two way communication
/// Includes the size of SYNC/CHANNEL message (7 bytes)
const MSG_ONE_WAY_THRESHOLD: usize = 223;

//const USAGE: &'static str = "
//Usage:
//  link -d <port> -s <baudrate>
//  link -d <port> -s <baudrate> -b <ivy-bus>
//  link (-h | --help)
// ";


#[derive(Debug)]
struct Args {
    flag_h: bool,
    flag_help: bool,
    flag_b: bool,
    flag_d: bool,
    arg_ivy_bus: String,
    arg_port: String,
    arg_baudrate: Option<i32>,
    flag_ping: bool,
    flag_datalink: bool,
    arg_ping_period_ms: Option<u64>,
    arg_datalink_period_ms: Option<u64>,
}


/// Configure port to given settings
///
/// We can specify the device name and the baudrate
/// The default timeout is zero (non-blocking read/write)
fn configure_port(mut port: serial::SystemPort,
                  baud: usize)
                  -> Result<serial::SystemPort, Box<Error>> {
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
    ivyrust::ivy_init(String::from("RustLink"), String::from("Ready"));
    if !ivy_bus.is_empty() {
        ivyrust::ivy_start(Some(ivy_bus));
    } else {
        ivyrust::ivy_start(None);
    }
    ivyrust::ivy_main_loop()
}

fn thread_ping(period: u64) {
	
	
	loop {
		
		
		thread::sleep(time::Duration::from_millis(period));
	}
}

fn thread_status_report(period: i32) {
	
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
                            msg_vector.push(msg);
                            //println!("msg vector len = {}", msg_vector.len());
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
fn thread_scheduler(port_name: OsString,
                 baudrate: usize,
                 dictionary: Arc<PprzDictionary>)
                 -> Result<(), Box<Error>> {
    let port = serial::open(&port_name)?;
    let mut port = match configure_port(port, baudrate) {
        Ok(port) => port,
        Err(e) => return Err(e),
    };

    // initialize an emty buffer
    let mut buf = [0; 255]; // still have to manually allocate an array
    let mut rx = PprzTransport::new();

    // get current time
    let mut instant = Instant::now();

    // proceed to read messages
    loop {
        if instant.elapsed() >= Duration::from_millis(PERIOD_MS) {
            // update time
            instant = Instant::now();

            // we need to send SYNC: get sync message
            let mut sync_msg = dictionary
                .find_msg_by_name(String::from("CHANNEL").as_ref())
                .unwrap();

            // look at how many messages are in the queue
            let mut len = 0;
            let mut msg_buf: Vec<PprzTransport> = vec![];

            // try lock and don't wait
            let mut lock = MSG_QUEUE.try_lock();
            if let Ok(ref mut msg_queue) = lock {
                while !msg_queue.is_empty() && (len <= MAX_MSG_SIZE) {
                    // get a message from the queue
                    let new_msg = msg_queue.pop().unwrap();

                    // get a transort
                    let mut tx = PprzTransport::new();

                    // construct a message from the transport
                    tx.construct_pprz_msg(&new_msg.to_bytes());

                    // validate message length
                    if (len + tx.get_message_length()) <= MAX_MSG_SIZE {
                        // increment lenght
                        len += tx.get_message_length();
                        // we have room for the message, so push it in
                        msg_buf.push(tx);
                    } else {
                        // we should abort counting here
                        println!("too many messages, breaking from len={}", len);
                        break;
                    }
                    //println!("Message queue len: {}", msg_queue.len());
                }
            }

            // calculate the field value
            let mut delay = PERIOD_MS as f32 -
                            ((CHANNEL_LEN as f32 + len as f32) as f32 * MS_PER_BYTE);
            if len >= MSG_ONE_WAY_THRESHOLD {
                // only one delay (rx only)
                delay = delay - PROTECTION_PERIOD as f32 * 1.0;
            } else {
                // double protection period (tx/rx)
                delay = delay - PROTECTION_PERIOD as f32 * 2.0;
            }
            //println!("delay ={}, rounded to {}", delay, delay as u8);

            // Set delay value
            sync_msg.fields[0].value = PprzMsgBaseType::Uint8(delay as u8);

            // Send CHANNEL message
            let mut tx = PprzTransport::new();
            tx.construct_pprz_msg(&sync_msg.to_bytes());
            let _ = port.write(&tx.buf)?;
            //println!("Written {} bytes", len);

            // Send our messages
            for msg_to_send in msg_buf {
                let len = port.write(&msg_to_send.buf)?;
                if len != msg_to_send.buf.len() {
                    println!("Written {} bytes, but the message was {} bytes",
                             len,
                             msg_to_send.buf.len());
                }

            }

        }

        // read data (no timeout right now)
        let len = match port.read(&mut buf[..]) {
            Ok(len) => len,
            Err(_) => continue,
        };

        // parse received data and optionally send a message
        for idx in 0..len {
            if rx.parse_byte(buf[idx]) {
                let name = dictionary
                    .get_msg_name(PprzMsgClassID::Telemetry, rx.buf[1])
                    .unwrap();
                let mut msg = dictionary.find_msg_by_name(&name).unwrap();

                // update message fields with real values
                msg.update(&rx.buf);
                
                // check for PONG
                
                // check for DATALINK_REPORT 

                // send the message
                ivyrust::ivy_send_msg(msg.to_string().unwrap());
            }
        }
    }
}


fn main() {
    let args = Args {
        flag_h: false,
        flag_help: false,
        flag_b: false,
        flag_d: false,
        arg_ivy_bus: String::new(),
        arg_port: String::from("/dev/ttyUSB0"),
        arg_baudrate: Some(57_600),
        flag_ping: false,
        flag_datalink: false,
        arg_ping_period_ms: Some(1000 as u64),
        arg_datalink_period_ms: Some(1000 as u64),
    };



    // HACK: rather than implementing Clone for the dictionary, we just build another dictionary
    let file = File::open("/home/podhrad/Documents/Paparazzi/pprzlink/message_definitions/v1.0/messages.xml")
        .unwrap();
    // push into the callback dictionary
    DICTIONARY
        .lock()
        .unwrap()
        .push(parser::build_dictionary(file));
        
            // construct a dictionary
    let file = File::open("/home/podhrad/Documents/Paparazzi/pprzlink/message_definitions/v1.0/messages.xml")
        .unwrap();
    let dictionary = parser::build_dictionary(file);
    let dictionary = Arc::new(dictionary);
    let dictionary_scheduler = Arc::clone(&dictionary);
    let dictionary_ping = Arc::clone(&dictionary);
    let dictionary_status = Arc::clone(&dictionary);

    // spin the main loop
    let ivy_bus = args.arg_ivy_bus;
    let t1 = thread::spawn(move || if let Err(e) = thread_ivy_main(ivy_bus) {
                               println!("Error starting ivy thread: {}", e);
                           } else {
                               println!("Ivy thread finished");
                           });

    // spin the serial loop
    let port = OsString::from(args.arg_port);
    let baudrate = args.arg_baudrate.unwrap() as usize;
    let t2 = thread::spawn(move || if let Err(e) = thread_scheduler(port, baudrate, dictionary_scheduler) {
                               println!("Error starting serial thread: {}", e);
                           } else {
                               println!("Serial thread finished");
                           });

    let _ = ivy_bind_msg(global_ivy_callback, String::from("(.*)"));

    // close
    t1.join().expect("Error waiting for ivy thread to finish");
    t2.join()
        .expect("Error waiting for serial thread to finish");
    ivyrust::ivy_stop();

}
