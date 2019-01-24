extern crate ivyrust;
extern crate libc;
extern crate pprzlink;
extern crate rand;
extern crate regex;
extern crate serial;

mod comms;
mod configs;
mod ivy;
mod transport;

use comms::*;
use configs::*;
use ivy::*;

use std::thread;

use std::error::Error;

use std::sync::Mutex;
use std::sync::Arc;

use std::collections::VecDeque;

use pprzlink::{PprzMessage, PprzMessageTelemetry};

use transport::PprzTransport;

#[allow(dead_code)]
fn print_array(b: &[u8]) {
    print!("data=[");
    for i in b {
        print!("0x{:x},", i);
    }
    println!("];");
}

fn thread_main(
    config: Arc<LinkConfig>,
    msg_queue: Arc<Mutex<VecDeque<PprzMessage>>>,
) -> Result<(), Box<Error>> {
    println!("Starting regular datalink...");

    let mut port = match LinkComm::new(Arc::clone(&config)) {
        Ok(p) => p,
        Err(e) => panic!("{}: Comm initialization failed: {}", config.link_name, e),
    };


    // initialize an emty buffer
    let mut buf = [0; 255]; // still have to manually allocate an array
    // use regular transport
    let mut rx = PprzTransport::new();

    loop {
        // process messages from the queue and encrypt them before sending
        let mut lock = msg_queue.lock();
        if let Ok(ref mut msg_queue) = lock {
            while !msg_queue.is_empty() {
                // get a message from the front of the queue
                let msg = msg_queue.pop_front().unwrap();
                //println!("Locking ivy queue, msg = {:?}", msg);
                if let PprzMessage::Datalink(msg) = msg {
                    println!("Ivy2Serial=> Sending msg: {:?}",msg);

                    // get a transort
                    let mut tx = PprzTransport::new();
                    let buf = msg.ser();

                    // construct a message from the transport
                    tx.construct_pprz_msg(&buf);

                    let len = port.com_write(tx.buf.as_mut_slice())?;
                    if len != tx.buf.len() {
                        println!(
                            "Written {} bytes, but the message was {} bytes",
                            len,
                            tx.buf.len()
                        );
                    }
                }
            }
        }

        // read data (1ms timeout right now)
        let len = match port.com_read(&mut buf[..]) {
            Ok(len) => len,
            Err(_) => continue,
        };
        process_incoming_messages(&buf[0..len], &config, &mut rx);
    } // end-loop
}

/// process new data, return number of new messages
fn process_incoming_messages(
    buf: &[u8],
    config: &Arc<LinkConfig>,
    rx: &mut PprzTransport,
) -> usize {
    let mut new_msgs = 0;
    // parse received data and optionally send a message
    for byte in buf {
        if rx.parse_byte(*byte) {
            new_msgs += 1;
            //println!("Serial2Ivy=> Buffer: {:?}",rx.buf);
            let sender = rx.buf.remove(0);
            if sender != config.ac_id {
                println!("Different sender. Expected {}, received {}", config.ac_id, sender);
            }
            if let Some(msg) = PprzMessageTelemetry::deser(&rx.buf) {
                //println!("Serial2Ivy=> Received: {:?}",msg);
                let ivy_msg = config.ac_id.to_string() + " " + &msg.to_string();
                ivyrust::ivy_send_msg(ivy_msg);
            }
        } // end parse byte
    } // end for idx in 0..len
    new_msgs
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
    let _ = thread::spawn(move || {
        if let Err(e) = thread_ivy_main(config.ivy_bus.clone()) {
            println!("Error starting ivy thread: {}", e);
        } else {
            println!("Ivy thread finished");
        }
    });
}

fn main() {
    // Initialize
    let config = link_init_and_configure();
    let msg_queue = link_build_msg_queue();

    // spin ivy main loop
    let conf = Arc::clone(&config);
    start_ivy_main_loop(conf);

    // spin the serial loop
    let conf = Arc::clone(&config);
    let queue = Arc::clone(&msg_queue);
    let t = thread::spawn(move || {
                if let Err(e) = thread_main(conf, queue) {
                    println!("Error starting main thread: {}", e);
                } else {
                    println!("Main thread finished");
                }
            });

    // bind global ivy callback
    let queue = Arc::clone(&msg_queue);
    let mut ivy_cb = LinkIvySubscriber::new(queue, &config.sender_id);
    ivy_cb.ivy_bind_to_sender(
        LinkIvySubscriber::ivy_callback,
        String::from("(.*)")
        //String::from("^") + &config.sender_id + " (.*)",
    );
    // close
    t.join().expect("Error waiting for serial thread to finish");

    // end program
    ivyrust::ivy_stop();
}
