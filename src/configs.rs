extern crate clap;

use comms::*;

use self::clap::{Arg, App};
use std::env;
use std::sync::Arc;
use pprzlink::parser::PprzProtocolVersion;
use std::ffi::OsString;


pub fn init_and_configure() -> Arc<LinkConfig> {
	// Construct command line arguments
    let matches = App::new("Rustlink for Paparazzi")
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

	let udp = match matches.occurrences_of("udp") {
        0 => false,
        1 | _ => true,
    };
	
	let udp_port = matches.value_of("udp_port").unwrap_or("4242");
	let udp_port = udp_port.parse::<u16>().expect("Incorrect udp_port");
	let udp_uplink_port = matches.value_of("udp_uplink_port").unwrap_or("4243");
	let udp_uplink_port = udp_uplink_port.parse::<u16>().expect("Incorrect udp_uplink_port");
	
	let pprzlink_version = matches.value_of("version").unwrap_or("2.0");
    let pprzlink_version = pprzlink_version.parse::<f32>().expect("Supported versions are 1.0 or 2.0");
    let pprzlink_version = match pprzlink_version as u32 {
    	1 => {
    		PprzProtocolVersion::ProtocolV1
    	},
    	2 => {
    		PprzProtocolVersion::ProtocolV2
    	}
    	_ => {
    		panic!("Unknown PprzProtocolVersion version: {}",pprzlink_version);
    	}
    };    
    println!("Value for pprzlink version: {}", pprzlink_version);
    
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
		pprzlink_version: pprzlink_version,
		ivy_bus: ivy_bus,
		pprz_root: pprz_root,
	})
}
