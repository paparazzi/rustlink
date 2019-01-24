extern crate clap;

use crate::PprzMessage;
use crate::comms::*;
use self::clap::{Arg, App};

use std::env;

use std::sync::Arc;
use std::sync::Mutex;

use std::ffi::OsString;

use std::collections::VecDeque;

/// Initialize the message queue
pub fn link_build_msg_queue() -> Arc<Mutex<VecDeque<PprzMessage>>> {
    Arc::new(Mutex::new(VecDeque::new()))
}


fn link_get_arguments() -> clap::ArgMatches<'static> {
    App::new("Rustlink for Paparazzi")
        .version("0.2")
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
                .long("status_period")
                .value_name("status_period")
                .help(
                    "Sets the period (in ms) of the LINK_REPORT status message. Default is 1000",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ping_period")
                .long("ping_period")
                .value_name("ping_period")
                .help(
                    "Sets the period (in ms) of the PING message sent to aircrafs. Default is 5000",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("version")
	            .short("v")
                .long("version")
                .value_name("version")
                .help(
                    "Sets the pprzlink version (1.0 or 2.0). Default is 2",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("udp")
                .long("udp")
                .value_name("udp")
                .help(
                    "Listen a UDP connection on <udp_port>",
                )
                .takes_value(false),
        )
        .arg(
            Arg::with_name("udp_broadcast")
                .long("udp_broadcast")
                .value_name("udp broadcast")
                .help(
                    "Enable UDP broadcast",
                )
                .takes_value(false),
        )
        .arg(
            Arg::with_name("udp_port")
                .long("udp_port")
                .value_name("udp port")
                .help(
                    "Default is 4242",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("udp_uplink_port")
                .long("udp_uplink_port")
                .value_name("udp uplink port")
                .help(
                    "Default is 4243",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("remote_addr")
                .short("r")
                .value_name("remote IP addr")
                .help("Default is 127.0.0.1 and can be set to a broadcast address if
the broadcast flag is specified")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sender_id")
                .long("sender_id")
                .value_name("sender id")
                .help(
                    "Sender ID used when sending messages over port (not over Ivy)
Can be numeric (like AC_ID) or a string (\"ground_dl\") in which case it
gets translated to zero. Sender ID is also used to filter ivy callback messages,
only those matching \"^sender_id (.*)\" regexpr are received. Default is \"ground_dl\"",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rx_msg_class")
                .long("rx_msg_class")
                .value_name("rx message class")
                .help(
                    "Message class that is expected to be received over the port.
Default is Telemetry, possible options are Datalink, Ground, Alert, Intermcu",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("link_name")
                .value_name("link name")
                .help(
                    "Program name, for debugging purposes",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ac_name")
                .short("n")
                .value_name("aircraft name")
                .help("Name of the aircraft (to find keys_gcs.h). Can be empty, unless 'crypto' is enabled.")
                .takes_value(true),
		)
        .arg(
            Arg::with_name("ac_id")
                .short("a")
                .value_name("aircraft ID")
                .help("ID for the aircraft. Has to be specified.")
                .takes_value(true),
		)
        .arg(
            Arg::with_name("crypto")
	            .short("c")
                .long("crypto")
                .help(
                    "Enables encrypted communication. Default is false",
                )
                .takes_value(false),
        )
        .get_matches()
}

/// Take command line arguments and create a LinkCondig struct
pub fn link_init_and_configure() -> Arc<LinkConfig> {
    let matches = link_get_arguments();

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

    let udp = match matches.occurrences_of("udp") {
        0 => false,
        1 | _ => true,
    };
    println!("Use UDP: {}", udp);

    let udp_broadcast = match matches.occurrences_of("udp_broadcast") {
        0 => false,
        1 | _ => true,
    };
    println!("Use UDP broadcast: {}", udp_broadcast);

    let udp_port = matches.value_of("udp_port").unwrap_or("4242");
    let udp_port = udp_port.parse::<u16>().expect("Incorrect udp_port");
    let udp_uplink_port = matches.value_of("udp_uplink_port").unwrap_or("4243");
    let udp_uplink_port = udp_uplink_port
        .parse::<u16>()
        .expect("Incorrect udp_uplink_port");

    // if the remote address is not specified, assume localhost
    let remote_addr = String::from(matches.value_of("remote_addr").unwrap_or("127.0.0.1"));
    println!("Value for remote_addr: {}", remote_addr);

    let pprzlink_version = matches.value_of("version").unwrap_or("2.0");
    let pprzlink_version = pprzlink_version
        .parse::<f32>()
        .expect("Supported versions are 1.0 or 2.0");

    let rx_msg_class = matches
        .value_of("rx_msg_class")
        .unwrap_or("Telemetry")
        .to_lowercase();

    let sender_id = matches.value_of("sender_id").unwrap_or("ground_dl");
    println!("Sender id: {}", sender_id);

    let link_name = matches.value_of("name").unwrap_or("");
    println!("Link name: {}", link_name);

    let ac_name = matches.value_of("ac_name");
    println!("Value for aircraft name: {:?}", ac_name);

    let ac_id = matches.value_of("ac_id").expect("AC_ID not specified");
    let ac_id = ac_id
        .parse::<u8>()
        .expect("AC_ID cannot be parsed. Make sure it is between 1 and 254");
    println!("Value for aircraft ID: {}", ac_id);


    let pprz_root = match env::var("PAPARAZZI_SRC") {
        Ok(var) => var,
        Err(e) => {
            panic!("Error getting PAPARAZZI_SRC environment variable: {}", e);
        }
    };

    Arc::new(LinkConfig {
        ping_period: ping_period,
        status_period: status_period,
        baudrate: baudrate,
        port: port,
        udp: udp,
        udp_port: udp_port,
        udp_uplink_port: udp_uplink_port,
        ivy_bus: ivy_bus,
        pprz_root: pprz_root,
        remote_addr: remote_addr,
        sender_id: String::from(sender_id),
        link_name: String::from(link_name),
        udp_broadcast: udp_broadcast,
        ac_id: ac_id,
    })
}
