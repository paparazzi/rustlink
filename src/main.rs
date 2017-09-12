#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate serial;
extern crate ivyrust;
extern crate pprzlink;
extern crate clap;

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

lazy_static! {
    static ref MSG_QUEUE: Mutex<VecDeque<PprzMessage>> = Mutex::new(VecDeque::new());
    static ref DICTIONARY: Mutex<Vec<PprzDictionary>> = Mutex::new(vec![]);
    static ref PING_TIME: Mutex<Vec<Instant>> = Mutex::new(vec![Instant::now()]);
    static ref RE_DATALINK: Regex = Regex::new("ground_dl .*").unwrap(); // TODO: factor out?
    static ref PING_TIME_VALUE: Mutex<f32> = Mutex::new(-1.0);
}

const PERIOD_MS: u64 = 50;
const CHANNEL_LEN: u64 = 7;
const MS_PER_BYTE: f32 = 0.17;
const PROTECTION_PERIOD: u64 = 6;
const MAX_MSG_SIZE: usize = 256;

/// Max number of bytes we can send before we can forfeit two way communication
/// Includes the size of SYNC/CHANNEL message (7 bytes)
const MSG_ONE_WAY_THRESHOLD: usize = 223;


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


/// Match with PONG message
/// that way we can update the ping time
/// NOTE: it is not super exact (depending on how fast
/// is the IVY bus, but it seems to be easier and probably
/// good enough at least for now);
fn pong_ivy_callback(_: Vec<String>) {
    println!("Got PONG callback");
    // we just got PONG back
    
    let mut ping_value_s = -1.0;
    
    // update the ping time
    let mut time_lock = PING_TIME.lock();
    if let Ok(ref mut ping_time) = time_lock {
        if !ping_time.is_empty() {
            let start_time = ping_time.pop().expect("PONG CALLBACK unwrap()");
            let duration = start_time.elapsed();
            ping_time.push(start_time);
            
            ping_value_s = duration.as_secs() as f32 + (duration.subsec_nanos() as f32 * 1e-9); 
        }
    } // PING_TIME mutex unlock
    
    // update the value
    let mut time_lock = PING_TIME_VALUE.lock();
    if let Ok(ref mut ping_time) = time_lock {
    	// update the value
    	**ping_time = ping_value_s;
    	println!("PONG TIME: {}",ping_value_s); 
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
                println!("Pushing ping message");
                msg_queue.push_front(ping_msg.clone());

                println!("PING: Message queue len: {}", msg_queue.len());

                // update the ping time
                let mut time_lock = PING_TIME.lock();
                if let Ok(ref mut ping_time) = time_lock {
                    ping_time.pop().expect("PING_TIME is empty");
                    let start_time = Instant::now();
                    ping_time.push(start_time);
                    println!("Updating PING TIME");
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
                        println!("new message is: {}", msg);

                        // if found, update the global msg
                        let mut msg_lock = MSG_QUEUE.lock();
                        if let Ok(ref mut msg_vector) = msg_lock {
                            // append at the end of vector
                            msg_vector.push_back(msg);
                            println!("Global callback: msg vector len = {}", msg_vector.len());
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
                    dictionary: Arc<PprzDictionary>,
                    status_report_period: u64)
                    -> Result<(), Box<Error>> {
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
                    // get a message from the front of the queue
                    let new_msg = msg_queue.pop_front().unwrap();

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
                    println!("Scheduler: Message queue len: {}", msg_queue.len());
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
                status_report.tx_bytes += len;
                status_report.tx_msgs += 1;
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
        status_report.rx_bytes += len;

        // parse received data and optionally send a message
        for idx in 0..len {
            if rx.parse_byte(buf[idx]) {
                status_report.rx_msgs += 1;
                let name = dictionary
                    .get_msg_name(PprzMsgClassID::Telemetry, rx.buf[1])
                    .unwrap();
                let mut msg = dictionary.find_msg_by_name(&name).unwrap();

                // update message fields with real values
                msg.update(&rx.buf);

                // check for PONG
                if msg.name == "PONG" {
                    // update time
                    pong_ivy_callback(vec![]);
                }

                // send the message
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

/*
let send_status_msg =
  let start = Unix.gettimeofday () in
  fun () ->
    Hashtbl.iter (fun ac_id status ->
      let dt = float !status_msg_period /. 1000. in
      let t = int_of_float (Unix.gettimeofday () -. start) in
      let byte_rate = float (status.rx_byte - status.last_rx_byte) /. dt
      and msg_rate = float (status.rx_msg - status.last_rx_msg) /. dt in
      status.last_rx_msg <- status.rx_msg;
      status.last_rx_byte <- status.rx_byte;
      let vs = ["ac_id", PprzLink.String (string_of_int ac_id);
                "link_id", PprzLink.String (string_of_int !link_id);
                "run_time", PprzLink.Int64 (Int64.of_int t);
                "rx_lost_time", PprzLink.Int64 (Int64.of_int (status.ms_since_last_msg / 1000));
                "rx_bytes", PprzLink.Int64 (Int64.of_int status.rx_byte);
                "rx_msgs", PprzLink.Int64 (Int64.of_int status.rx_msg);
                "rx_err", PprzLink.Int64 (Int64.of_int status.rx_err);
                "rx_bytes_rate", PprzLink.Float byte_rate;
                "rx_msgs_rate", PprzLink.Float msg_rate;
                "tx_msgs", PprzLink.Int64 (Int64.of_int status.tx_msg);
                "ping_time", PprzLink.Float (1000. *. (status.last_pong -. status.last_ping))
               ] in
      send_ground_over_ivy "link" "LINK_REPORT" vs)
      statuss
      
          <message name="LINK_REPORT" id="36">
      <description>Datalink status reported by Link for the Server</description>
      <field name="ac_id" type="string"/>
      <field name="link_id" type="string"/>
      <field name="run_time" type="uint32" unit="s"/>
      <field name="rx_lost_time" type="uint32" unit="s"/>
      <field name="rx_bytes" type="uint32"/>
      <field name="rx_msgs" type="uint32"/>
      <field name="rx_err" type="uint32"/>
      <field name="rx_bytes_rate" type="float" format="%.1f" unit="bytes/s"/>
      <field name="rx_msgs_rate" type="float" format="%.1f" unit="msgs/s"/>
      <field name="tx_msgs" type="uint32"/>
      <field name="ping_time" type="float" format="%.2f" unit="ms"/>
    </message>
*/
/// Update status is called every time we get new data, we just store the new values
fn update_status(mut msg: PprzMessage,
                 status_report: &mut RustlinkStatusReport,
                 status_msg_period: Duration)
                 -> PprzMessage {

    let dt_seconds = status_msg_period.as_secs() as f32 +
                     (status_msg_period.subsec_nanos() as f32 * 1e-9);

    for field in &mut msg.fields {
        match field.name.as_ref() {
            "ac_id" => {
                // this is AC_ID, we can leave blank for now
                field.value = PprzMsgBaseType::String(String::from("1"));
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
            	// acquire last ping time
            	
            	// set to -1 if not sucessfull
            }
            _ => {
                println!("update_status: Unknown field");
            }
        } // end match
    } // end for
    
    // time is up, send the report
    ivyrust::ivy_send_msg(msg.to_string().unwrap());
    
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
        .arg(Arg::with_name("ivy_bus")
                 .short("b")
                 .value_name("ivy_bus")
                 .help("Default is 127.255.255.255:2010")
                 .takes_value(true))
        .arg(Arg::with_name("port")
                 .short("d")
                 .value_name("port")
                 .help("Default is /dev/ttyUSB0")
                 .takes_value(true))
        .arg(Arg::with_name("baudrate")
                 .short("s")
                 .value_name("baudrate")
                 .help("Default is 9600")
                 .takes_value(true))
        .arg(Arg::with_name("status_period")
                 .short("t")
                 .long("status_period")
                 .value_name("status_period")
                 .help("Sets the period (in ms) of the LINK_REPORT status message. Default is 1000")
                 .takes_value(true))
        .arg(Arg::with_name("ping_period")
                 .short("n")
                 .long("ping_period")
                 .value_name("ping_period")
                 .help("Sets the period (in ms) of the PING message sent to aircrafs. Default is 5000")
                 .takes_value(true))
        .get_matches();



    let ivy_bus = matches
        .value_of("ivy_bus")
        .unwrap_or("127.255.255.255:2010");
    let ivy_bus = String::from(ivy_bus);
    println!("Value for ivy_bus: {}", ivy_bus);

    let ping_period = matches.value_of("ping_period").unwrap_or("1000");
    let ping_period = ping_period.parse::<u64>().expect("Incorrect ping period");
    println!("Value for ping_period: {}", ping_period);

    let status_period = matches.value_of("status_period").unwrap_or("5000");
    let status_period = status_period
        .parse::<u64>()
        .expect("Incorrect status period");
    println!("Value for status_period: {}", status_period);

    let baudrate = matches.value_of("baudrate").unwrap_or("9600");
    let baudrate = baudrate.parse::<usize>().expect("Incorrect baudrate");
    println!("Value for baudrate: {}", baudrate);

    let port = matches.value_of("port").unwrap_or("/dev/ttyUSB0");
    let port = OsString::from(port);
    println!("Value for port: {:?}", port);

    let pprz_root = match env::var("PAPARAZZI_SRC") {
        Ok(var) => var,
        Err(e) => {
            println!("Error getting PAPARAZZI_SRC environment variable: {}", e);
            return;
        }
    };


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

    // spin the main IVY loop
    let _ = thread::spawn(move || if let Err(e) = thread_ivy_main(ivy_bus) {
                              println!("Error starting ivy thread: {}", e);
                          } else {
                              println!("Ivy thread finished");
                          });

    // spin the serial loop
    let t2 = thread::spawn(move || if let Err(e) = thread_scheduler(port,
                                                                    baudrate,
                                                                    dictionary_scheduler,
                                                                    status_period) {
                               println!("Error starting serial thread: {}", e);
                           } else {
                               println!("Serial thread finished");
                           });



    // ping periodic
    let _ = thread::spawn(move || thread_ping(ping_period, dictionary_ping));

    // bind global callback
    let _ = ivy_bind_msg(global_ivy_callback, String::from("(.*)"));

    // close
    t2.join()
        .expect("Error waiting for serial thread to finish");
    ivyrust::ivy_stop();

}
