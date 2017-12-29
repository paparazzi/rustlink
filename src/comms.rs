
extern crate serial;

use std::net::{SocketAddr, UdpSocket};
use std::io::ErrorKind as IOErrorKind;
use std::io::Error as IOError;
use std::io::prelude::*;
use serial::prelude::*;
use std::ffi::OsString;
use pprzlink::parser::PprzProtocolVersion;
use std::time::Duration;
use std::error::Error;
use std::sync::Arc;


pub struct LinkConfig {
	/// [ms]
	pub ping_period: u64,
	/// [ms]
	pub status_period: u64,
	pub baudrate: usize,
	pub port: OsString,
	/// if true, communicate over UDP
	pub udp: bool,
	/// communication received here
	pub udp_port: u16,
	/// uplink messages sent to here
	pub udp_uplink_port: u16,
	/// Version of Pprzlink this link is using
	pub pprzlink_version: PprzProtocolVersion,
	/// Ivy bus address
	pub ivy_bus: String,
	/// PAPARAZZ_SRC path
	pub pprz_root: String,
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

pub enum LinkCommType {
	Serial,
	Udp,
}

pub struct LinkComm {
	com_type: LinkCommType,
	port: Option<serial::SystemPort>,
	socket: Option<UdpSocket>,
}

impl LinkComm {
	pub fn new(config: Arc<LinkConfig>) -> Result<LinkComm,Box<Error>> {
		if config.udp {
			// use sockets
			let mut com = LinkComm {
				com_type: LinkCommType::Udp,
				port: None,
				socket: None,
			};
			// let the OS decide to which interface to bind/connect, specify only the port
			let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], config.udp_port as u16)))?;
			socket.connect(SocketAddr::from(([0, 0, 0, 0], config.udp_uplink_port as u16)))?;
		    com.socket = Some(socket);
		    return Ok(com)
			
		} else {
			// use serial port
			let mut com = LinkComm {
				com_type: LinkCommType::Serial,
				port: None,
				socket: None,
			};
			let port = serial::open(&config.port)?;
		    let port = match configure_port(port, config.baudrate) {
		        Ok(port) => port,
		        Err(e) => return Err(e),
		    };
		    com.port = Some(port);
		    return Ok(com)
		}
		
		
	}
	
	/// write data from buffer to the device
	pub fn com_write(&mut self, buf: &mut [u8]) -> Result<usize, IOError> {
		match self.com_type {
			LinkCommType::Serial => {
				match self.port {
					Some(ref mut port) => {
						port.write(buf)
					}
					None => {
						Err(IOError::new(IOErrorKind::Other, "Port not initialized"))
					}
				}
			},
			LinkCommType::Udp => {
				match self.socket {
					Some(ref mut socket) => {
						socket.send(buf)
					}
					None => {
						Err(IOError::new(IOErrorKind::Other, "Tx socket not initialized"))
					}
				}
			}
		}
	}
	
	/// read data from the device into the buffer
	pub fn com_read(&mut self, buf: &mut [u8]) -> Result<usize, IOError> {
		match self.com_type {
			LinkCommType::Serial => {
				match self.port {
					Some(ref mut port) => {
						port.read(buf)
					}
					None => {
						Err(IOError::new(IOErrorKind::Other, "Port not initialized"))
					}
				}
			},
			LinkCommType::Udp => {
				match self.socket {
					Some(ref mut socket) => {
						socket.recv(buf)
					}
					None => {
						Err(IOError::new(IOErrorKind::Other, "Tx socket not initialized"))
					}
				}
			}
		}	
	}
}