// =========================
// Ppprzlink Transport
// =========================
const PPRZ_STX: u8 = 0x99;

/// Pprzlink parser
enum PprzParserState {
    WaitSTX,
    GotSTX,
    GotLength,
    GotPayload,
    GotCRC1,
}

/// can be used for for tx and rx
pub struct PprzTransport {
    state: PprzParserState,
    pub length: u8,
    pub buf: Vec<u8>,
    ck_a: u8,
    ck_b: u8,
    hdr_err: u32,
}

impl PprzTransport {
    pub fn new() -> PprzTransport {
        PprzTransport {
            state: PprzParserState::WaitSTX,
            length: 0,
            buf: vec![],
            ck_a: 0,
            ck_b: 0,
            hdr_err: 0,
        }
    }

    pub fn reset(&mut self) {
        self.buf.clear();
        self.ck_a = 0;
        self.ck_b = 0;
        self.length = 0;
        self.state = PprzParserState::WaitSTX;
    }

    pub fn get_message_length(&self) -> usize {
        self.length as usize
    }

    /// parse new byte, return True when a new full message is available
    pub fn parse_byte(&mut self, b: u8) -> bool {
        match self.state {
            PprzParserState::WaitSTX => {
                if b == PPRZ_STX {
                    self.reset();
                    self.state = PprzParserState::GotSTX;
                //println!("Got STX");
                } else {
                    self.hdr_err += 1;
                }
            }
            PprzParserState::GotSTX => {
                // minimal size of a message is 6
                if b >= 6 {
                    self.length = b - 4;
                    self.ck_a = b;
                    self.ck_b = b;
                    self.state = PprzParserState::GotLength;
                //println!("Got length of {}",b);
                } else {
                    self.hdr_err += 1;
                    self.state = PprzParserState::WaitSTX;
                }
            }
            PprzParserState::GotLength => {
                self.buf.push(b);
                //println!("byte: 0x{:x}",b);
                self.ck_a = self.ck_a.wrapping_add(b);
                self.ck_b = self.ck_b.wrapping_add(self.ck_a);
                if self.buf.len() == self.length as usize {
                    //println!("Got payload");
                    self.state = PprzParserState::GotPayload;
                }
            }
            PprzParserState::GotPayload => {
                if self.ck_a == b {
                    self.state = PprzParserState::GotCRC1;
                } else {
                    //println!("self.ck_a = 0x{:x}, b=0x{:x}",self.ck_a,b);
                    self.state = PprzParserState::WaitSTX;
                }
            }
            PprzParserState::GotCRC1 => {
                self.state = PprzParserState::WaitSTX;
                //println!("Got checksum");
                if self.ck_b == b {
                    //println!("Checksum ok");
                    return true;
                }
                //println!("self.ck_b = 0x{:x}, b=0x{:x}",self.ck_b,b);
            }
        }
        return false;
    }

    /// call on a finished packet
    fn calculate_checksum(&mut self) -> (u8, u8) {
        let mut ck_a: u8 = 0;
        let mut ck_b: u8 = 0;
        // start char not included in checksum for pprz protocol
        for idx in 1..self.buf.len() {
            let c = self.buf[idx];
            ck_a = ck_a.wrapping_add(c);
            ck_b = ck_b.wrapping_add(ck_a);
        }
        (ck_a, ck_b)
    }

    /// construct a message from payload data
    /// i.e. append header and crc
    pub fn construct_pprz_msg(&mut self, payload: &[u8]) {
        self.reset();
        self.buf.push(PPRZ_STX);
        self.buf.push(payload.len() as u8 + 4); // add 4 bytes of the header
        for byte in payload {
            self.buf.push(*byte);
        }
        let (ck_a, ck_b) = self.calculate_checksum();
        self.buf.push(ck_a);
        self.buf.push(ck_b);
        self.length = self.buf.len() as u8;
    }
}
