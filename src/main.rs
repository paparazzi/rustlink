extern crate serial;
extern crate ivyrust;
extern crate pprzlink;
extern crate rand;
extern crate libc;


mod comms;
mod configs;
mod ivy;

use comms::*;
use configs::*;
use ivy::*;

use ivyrust::IvyMessage;

use std::{thread, time};

use std::error::Error;

use std::sync::Mutex;
use std::sync::Arc;

use std::collections::VecDeque;

use pprzlink::parser::{PprzDictionary, PprzMsgClassID, PprzMessage};
use pprzlink::transport::PprzTransport;

use time::*;

// FOR GEC COMMS
//use std::io::BufReader;
//use rand::Rng;
//use rand::os::OsRng;


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
    msg_queue: Arc<Mutex<VecDeque<PprzMessage>>>
) -> Result<(), Box<Error>> {
    
    let mut port = match LinkComm::new(Arc::clone(&config)) {
    	Ok(p) => p,
    	Err(e) => panic!("Comm initialization failed: {}", e),
    };

    // initialize variables in LINK_REPORT
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
    
    // instantiate a ping time and callback
    let mut ping_cb = LinkIvyPing::new(0.1);
    let ping_msg_id = dictionary
        .find_msg_by_name("PING")
        .expect("Ping message not found").id;
    
    // initialize ivy global callback struct
    let mut ivy_cb = IvyMessage::new();
    // subsribe to all ivy messages coming from "ground_dl"
    ivy_cb.ivy_bind_msg(IvyMessage::callback, String::from("ground_dl (.*)"));
    
    // initialize an emty buffer
    let mut buf = [0; 255]; // still have to manually allocate an array
    let mut rx = PprzTransport::new();

    // get debug time
    let debug_time = RustlinkTime::new();

    loop {  
    	// TODO: refactor msg sending so it can handle priority/encryption
            // process messages from the queue and encrypt them before sending
            let mut lock = msg_queue.lock();
            if let Ok(ref mut msg_queue) = lock {
                // process ivy_messages first, and push them into the message queue
		    	let mut ivy_lock = ivy_cb.data.lock();
			    if let Ok(ref mut ivy_msgs) = ivy_lock {
					while !ivy_msgs.is_empty() {
						{
							let mut values: Vec<&str> = ivy_msgs[0][0].split(' ').collect();
							values.insert(0,""); // the parser expects a sender field
	
							match dictionary.find_msg_by_name(values[1]) {
						        Some(mut msg) => {
						        	msg.update_from_string(&values);
						        	// append at the end (no priority)
						        	msg_queue.push_back(msg);
						        }
						        None => {
							        println!("Message not found: {}",&ivy_msgs[0][0]);
							    }
							}
						}
						ivy_msgs.pop();
					}
			    }
                
                while !msg_queue.is_empty() {
                    // get a message from the front of the queue
                    let new_msg = msg_queue.pop_front().unwrap();

                    // check for ping
                    if new_msg.id == ping_msg_id {
                    	// this message is a PING message, update the ping time
                    	ping_cb.reset();
                    }

                    // get a transort
                    let mut tx = PprzTransport::new();
                    let mut buf = new_msg.to_bytes();

                    // construct a message from the transport
                    tx.construct_pprz_msg(&buf);

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

        // parse received data and optionally send a message
        for idx in 0..len {
            if rx.parse_byte(buf[idx]) {
                //
                //  REGULAR COMMUNICATION
                //
                // let buf = parse_incoming_messages(buf);                     
                status_report.rx_msgs += 1;
                let name = dictionary
                    .get_msg_name(
                    	PprzMsgClassID::Telemetry,
                    	PprzMessage::get_msg_id_from_buf(&rx.buf, dictionary.protocol))
                    .expect("thread main: message name not found");
                let mut msg = dictionary.find_msg_by_name(&name).expect("thread main: no message found");

                // update message fields with real values
                msg.update(&rx.buf);

                // check for PONG
                if msg.name == "PONG" {
                    // update time
                    ping_cb.update();
                }
                ivyrust::ivy_send_msg(msg.to_string().unwrap());
            } // end parse byte
        } // end for idx in 0..len

        // update status & send status message if needed
        if status_report_timer.elapsed() >= status_report_period {
            report_msg = link_update_status(report_msg, 
							            	&mut status_report,
								            status_report_period,
								            ping_cb.ping_time_ema);

		    // time is up, send the report
			let mut s = report_msg.to_string().unwrap();
		    s.remove(0);
		    s.insert_str(0, "link");
		    ivyrust::ivy_send_msg(s);

            // reset the timer
            status_report_timer = Instant::now();
        }
    } // end-loop
}


/// Send PING message
///
/// Push PING at the beginning of the queue
/// and then sleep for `period` ms
/// The ping time is updated once the message is sent from the main thread
fn thread_ping(
	config: Arc<LinkConfig>,
	dictionary: Arc<PprzDictionary>,
	msg_queue: Arc<Mutex<VecDeque<PprzMessage>>>) {

    let ping_msg = dictionary
        .find_msg_by_name("PING")
        .expect("Ping message not found");
    loop {
        // the sender ID is set to zero by default (GCS)
        // add at the beginning of the message gueue
        {
            let mut msg_lock = msg_queue.lock();
            if let Ok(ref mut msg_queue) = msg_lock {
                // push to front
                msg_queue.push_front(ping_msg.clone());
            }
        }
        thread::sleep(time::Duration::from_millis(config.ping_period));
    }
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

fn main() {
	// Initialize
	let config = link_init_and_configure();
	let dictionary = link_build_dictionary(Arc::clone(&config));
	let msg_queue = link_build_msg_queue();
	
	// spin ivy main loop
	let conf = Arc::clone(&config);
	start_ivy_main_loop(conf);
	
    // spin the serial loop
    let conf = Arc::clone(&config);
    let dict = Arc::clone(&dictionary);
    let queue = Arc::clone(&msg_queue);
    let t = thread::spawn(move || if let Err(e) = thread_main(
        conf,
        dict,
        queue,
    )
    {
        println!("Error starting main thread: {}", e);
    } else {
        println!("Main thread finished");
    });

    // ping periodic
    let conf = Arc::clone(&config);
    let dict = Arc::clone(&dictionary);
    let queue = Arc::clone(&msg_queue);
    let _ = thread::spawn(move || thread_ping(conf, dict, queue));

    // close
    t.join().expect("Error waiting for serial thread to finish");

    // end program
    ivyrust::ivy_stop();
}
