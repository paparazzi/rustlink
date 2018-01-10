extern crate clap;

use comms::*;
use self::clap::{Arg, App};

use std::env;

use std::sync::Arc;
use std::sync::Mutex;

use std::ffi::OsString;

use std::fs::File;

use pprzlink::parser::{PprzProtocolVersion,PprzDictionary,PprzMessage,PprzMsgBaseType,build_dictionary, PprzMsgClassID};

use std::collections::VecDeque;

use std::time::{Instant, Duration};



/// Initialize the message queue
pub fn link_build_msg_queue() -> Arc<Mutex<VecDeque<PprzMessage>>> {
	Arc::new(Mutex::new(VecDeque::new()))
}

/// PprzDictionary is always borrowed immutably, no need for a mutex
pub fn link_build_dictionary(config: Arc<LinkConfig>) -> Arc<PprzDictionary> {
	// construct a dictionary
	let xml_file = config.pprz_root.clone() + "/sw/ext/pprzlink/message_definitions/v1.0/messages.xml";
    let file = File::open(xml_file).expect("Messages.xml file not found");
    Arc::new(build_dictionary(file,config.pprzlink_version))
}

/// Take command line arguments and create a LinkCondig struct
pub fn link_init_and_configure() -> Arc<LinkConfig> {
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
        .arg(
            Arg::with_name("remote_addr")
                .short("r")
                .value_name("remote IP addr")
                .help("Default is localhost")
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
            Arg::with_name("name")
                .short("n")
                .value_name("name")
                .help(
                    "Program name, for debugging purposes",
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
	println!("Use UDP: {}",udp);
	
	let udp_port = matches.value_of("udp_port").unwrap_or("4242");
	let udp_port = udp_port.parse::<u16>().expect("Incorrect udp_port");
	let udp_uplink_port = matches.value_of("udp_uplink_port").unwrap_or("4243");
	let udp_uplink_port = udp_uplink_port.parse::<u16>().expect("Incorrect udp_uplink_port");

	// if the remote address is not specified, assume localhost
    let remote_addr = String::from(matches.value_of("remote_addr").unwrap_or("127.0.0.1"));
    println!("Value for remote_addr: {}", remote_addr);

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

	let rx_msg_class = matches.value_of("rx_msg_class").unwrap_or("Telemetry").to_lowercase();
	let rx_msg_class = match rx_msg_class.as_ref() {
		"telemetry" => PprzMsgClassID::Telemetry,
		"datalink" => PprzMsgClassID::Datalink,
		"ground" => PprzMsgClassID::Ground,
		"alert" => PprzMsgClassID::Alert,
		"intermcu" => PprzMsgClassID::Intermcu,
		_ => panic!("Unknown rx message class: {}", rx_msg_class),
	};
	println!("Global message class is set to {}", rx_msg_class);

	let sender_id = matches.value_of("sender_id").unwrap_or("ground_dl");
	println!("Sender id: {}", sender_id);

	let name = matches.value_of("name").unwrap_or("");
	println!("Rustlink name: {}", name);

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
		remote_addr: remote_addr,
		sender_id: String::from(sender_id),
		rx_msg_class: rx_msg_class,
		name: name,
	})
}


/// Status report data
pub struct RustlinkStatusReport {
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub rx_msgs: usize,
    pub tx_msgs: usize,
    pub last_tx_bytes: usize,
    pub last_rx_bytes: usize,
    pub last_rx_msgs: usize,
    pub last_tx_msgs: usize,
}

/// Convenience time structure
pub struct RustlinkTime {
    time: Instant,
}

/// Convenience time functions
impl RustlinkTime {
	pub fn new() -> RustlinkTime {
		RustlinkTime { time: Instant::now() }
	}
	
	/// Resets the time to current time
	pub fn reset(&mut self) {
		self.time = Instant::now();
	}
	
	/// Returns elapsed time since creation or reset of the time instant [s]
    pub fn elapsed(&self) -> f64 {
        let duration = self.time.elapsed();
        duration.as_secs() as f64 + duration.subsec_nanos() as f64 * 1e-9
    }
}

/// Update status is called at defined period,
/// update with new data and return a new message to be sent
pub fn link_update_status(
    mut msg: PprzMessage,
    status_report: &mut RustlinkStatusReport,
    status_msg_period: Duration,
    ping_time: f64,
) -> PprzMessage {

    let dt_seconds = status_msg_period.as_secs() as f32 +
        (status_msg_period.subsec_nanos() as f32 * 1e-9);

    for field in &mut msg.fields {
        match field.name.as_ref() {
            "ac_id" => {
                // this is AC_ID, we can leave blank for now TODO: has to match the AC id
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
                field.value = PprzMsgBaseType::Float(ping_time as f32 * 1000.0); // convert to ms
            }
            _ => {
                println!("update_status: Unknown field");
            }
        } // end match
    } // end for

    // update the report
    status_report.last_rx_bytes = status_report.rx_bytes;
    status_report.last_tx_bytes = status_report.tx_bytes;
    status_report.last_rx_msgs = status_report.rx_msgs;
    status_report.last_tx_msgs = status_report.tx_msgs;

    msg
}
