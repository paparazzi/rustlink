#[macro_use]
extern crate docopt;
extern crate regex;
extern crate serial;
extern crate ivyrust;
extern crate pprzlink;

use docopt::Docopt;
use ivyrust::*;
use std::{thread, time};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::prelude::*;
use serial::prelude::*;
use std::time::Duration;
use std::error::Error;
use std::ffi::{OsString, OsStr};
use std::fs::File;
use pprzlink::parser;
use pprzlink::parser::{PprzDictionary, PprzMsgClassID, PprzMessage, PprzMsgBaseType};
use pprzlink::transport::PprzTransport;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::mpsc;
use time::*;

#[derive(Debug, PartialEq)]
enum LinkControlStatus {
    Sending,
    Receiving,
}

const PERIOD_MS: u64 = 50;
const CHANNEL_LEN: u64 = 7;
const MS_PER_BYTE: f32 = 0.17;
const PROTECTION_PERIOD: u64 = 6;
const MAX_MSG_SIZE: usize = 256;

/// Max number of bytes we can send before we can forfeit two way communication
/// Includes the size of SYNC/CHANNEL message (7 bytes)
const MSG_ONE_WAY_THRESHOLD: usize = 223;

const USAGE: &'static str = "
Usage: 
  link -d <port> -s <baudrate>
  link -d <port> -s <baudrate> -b <ivy-bus>
  link (-h | --help)
 ";


#[derive(Debug)]
struct Args {
    flag_h: bool,
    flag_help: bool,
    flag_b: bool,
    flag_d: bool,
    arg_ivy_bus: String,
    arg_port: String,
    arg_baudrate: Option<i32>,
    //arg_status_period: Option<i32>,
    //arg_ping_period: Option<i32>,
    //flag_status_period: bool,
    //flag_ping_period: bool,
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
    port.set_timeout(Duration::from_millis(0))?;

    Ok(port)
}


/// Main IVY loop
///
/// This thread only launchees `IvyMainLoop()` and loops forever
/// Uses the optional argument specifying a non-default bus address
fn ivy_main_thread(ivy_bus: String, tx: mpsc::Receiver<PprzMessage>) -> Result<(), Box<Error>> {
    // connect to IVY bus
    ivyrust::ivy_init(String::from("RustLink"), String::from("Ready"));
    if !ivy_bus.is_empty() {
        ivyrust::ivy_start(Some(ivy_bus));
    } else {
        ivyrust::ivy_start(None);
    }
    
    let x = PprzMessage::new();
    
    tx.send(PprzMessage::new());

    ivyrust::ivy_main_loop()
}




/// Ivy bind thread
///
/// We bind to all Ivy messages, and then filter then using regexpr
/// over the datalink messages.
/// Ideally we would have a callback for each message, but that is currently
/// not possible.
fn ivy_listener_thread(dictionary: Arc<PprzDictionary>) -> Result<(), Box<Error>> {

    Ok(())
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
fn serial_thread(port_name: OsString,
                 baudrate: usize,
                 dictionary: Arc<PprzDictionary>, rx: mpsc::Receiver<PprzMessage>)
                 -> Result<(), Box<Error>> {
    let port = serial::open(&port_name)?;
    let mut port = match configure_port(port, baudrate) {
        Ok(port) => port,
        Err(e) => return Err(e),
    };

    // initialize an emty buffer
    let mut buf = [0; 255]; // still have to manually allocate an array
    let mut rx = PprzTransport::new();

    // initialize message queue
    let mut msg_queue: Vec<PprzMessage> = vec![];

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
            let mut msg_buf = vec![];
            for msg in &msg_queue {
                // get a transort
                let mut tx = PprzTransport::new();
                // now we have a full message
                tx.construct_pprz_msg(&msg.to_bytes());

                // validate message length
                if (len + tx.get_message_length()) <= MAX_MSG_SIZE {
                    // increment lenght
                    len += tx.get_message_length();
                    // we have room for the message, so push it in
                    msg_buf.push(tx);
                } else {
                    // we should abort counting here
                    println!("too many message");
                }

                // See what happened with the message queue - are we actually removing data?
                println!("Message queue: {:?}", msg_queue);
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
            println!("delay ={}, rounded to {}", delay, delay as u8);

            // Set delay value
            sync_msg.fields[0].value = PprzMsgBaseType::Uint8(delay as u8);

            // Send CHANNEL message
            let mut tx = PprzTransport::new();
            tx.construct_pprz_msg(&sync_msg.to_bytes());
            let len = port.write(&tx.buf)?;
            println!("Written {} bytes", len);

            // Send our messages
            for msg_to_send in msg_buf {
                let len = port.write(&msg_to_send.buf)?;
                println!("Written {} bytes", len);
            }

        }

        // read data
        let len = match port.read(&mut buf[..]) {
            Ok(len) => len,
            Err(e) => {
                continue;
            } 
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

                // send the message
                ivyrust::ivy_send_msg(msg.to_string().unwrap());
            }
        }
        
        // check for messages from Ivy bus
        rx.recv().unwrap();
        /*
        match rx.recv() {
        	Ok(msg) => {
        		println!("received a message!");
        		msg_queue.push(msg);
        	}
        	Err(_) => {
        		// this is a timeout error, so do nothing
        	}
        }
        */
    }

    Ok(())
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
    };
    /*
    let args: Args = Docopt::new(USAGE);
    println!("{:?}", args);

    if args.flag_h {
        println!("{}", USAGE);
        return;
    }
    */

    // construct a dictionary
    let file = File::open("/xxx/v1.0/messages.xml")
        .unwrap();
    let dictionary = parser::build_dictionary(file);
    let dictionary = Arc::new(dictionary);
    let d1 = Arc::clone(&dictionary);
    let d2 = Arc::clone(&dictionary);


	// construct a channel
	let (tx, rx) = mpsc::channel();

    // spin the main loop
    let ivy_bus = args.arg_ivy_bus;
    let t1 = thread::spawn(move || if let Err(e) = ivy_main_thread(ivy_bus, tx) {
                               println!("Error starting ivy thread: {}", e);
                           } else {
                               println!("Ivy thread finished");
                           });

    // spin the serial loop
    let port = OsString::from(args.arg_port);
    let baudrate = args.arg_baudrate.unwrap() as usize;
    let t2 = thread::spawn(move || if let Err(e) = serial_thread(port, baudrate, d2, rx) {
                               println!("Error starting serial thread: {}", e);
                           } else {
                               println!("Serial thread finished");
                           });

    //let t3 = thread::spawn

    // close
    t1.join().expect("Error waiting for ivy thread to finish");
    t2.join()
        .expect("Error waiting for serial thread to finish");
    ivyrust::ivy_stop();

}
