//! The identity object (class 0x01) and the ListIdentity reply item.

use crate::config::{ConfigError, IdentityConfig};

#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub vendor: u16,
    pub product_type: u16,
    pub product_code: u16,
    pub revision: [u8; 2],
    pub status: u16,
    pub serial: u32,
    pub product_name: String,
    pub state: u8,
    pub ip: [u8; 4],
}

impl Identity {
    pub(crate) fn build(config: &IdentityConfig) -> Result<Self, ConfigError> {
        let serial = u32::from_str_radix(&config.serial, 16).map_err(|_| {
            ConfigError::new(format!("serial {:?} is not 8 hex digits", config.serial))
        })?;
        // status word bytes as the driver decodes the keyswitch: low byte mode, high byte key position
        let status = match config.status {
            Some(status) => status,
            None => match config.keyswitch.as_str() {
                "RUN" => u16::from_le_bytes([0x60, 0x10]),
                "REMOTE RUN" => u16::from_le_bytes([0x60, 0x30]),
                "PROG" => u16::from_le_bytes([0x70, 0x20]),
                "REMOTE PROG" => u16::from_le_bytes([0x70, 0x30]),
                other => {
                    return Err(ConfigError::new(format!(
                        "keyswitch {other:?} is not RUN, REMOTE RUN, PROG or REMOTE PROG"
                    )));
                }
            },
        };
        let ip: std::net::Ipv4Addr = config.ip_address.parse().map_err(|_| {
            ConfigError::new(format!(
                "ip_address {:?} is not an IPv4 address",
                config.ip_address
            ))
        })?;
        if config.product_name.len() > 255 || !config.product_name.is_ascii() {
            return Err(ConfigError::new(
                "product_name must be ASCII, at most 255 characters",
            ));
        }
        Ok(Identity {
            vendor: config.vendor,
            product_type: config.product_type,
            product_code: config.product_code,
            revision: config.revision,
            status,
            serial,
            product_name: config.product_name.clone(),
            state: config.state,
            ip: ip.octets(),
        })
    }

    /// Get_Attributes_All: vendor, device type, product code, revision, status, serial, product name.
    pub(crate) fn attributes_all(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.product_name.len());
        out.extend(self.vendor.to_le_bytes());
        out.extend(self.product_type.to_le_bytes());
        out.extend(self.product_code.to_le_bytes());
        out.extend(self.revision);
        out.extend(self.status.to_le_bytes());
        out.extend(self.serial.to_le_bytes());
        out.push(self.product_name.len() as u8);
        out.extend(self.product_name.as_bytes());
        out
    }

    /// Get_Attribute_Single of attributes 1 to 7.
    pub(crate) fn attribute(&self, attribute: u32) -> Option<Vec<u8>> {
        Some(match attribute {
            1 => self.vendor.to_le_bytes().to_vec(),
            2 => self.product_type.to_le_bytes().to_vec(),
            3 => self.product_code.to_le_bytes().to_vec(),
            4 => self.revision.to_vec(),
            5 => self.status.to_le_bytes().to_vec(),
            6 => self.serial.to_le_bytes().to_vec(),
            7 => {
                let mut out = vec![self.product_name.len() as u8];
                out.extend(self.product_name.as_bytes());
                out
            }
            _ => return None,
        })
    }

    /// The ListIdentity reply data: item count, then the CIP identity item (0x0C).
    pub(crate) fn list_identity(&self, port: u16) -> Vec<u8> {
        let mut item = Vec::with_capacity(40 + self.product_name.len());
        item.extend(1u16.to_le_bytes()); // encapsulation protocol version
        item.extend(2u16.to_be_bytes()); // sockaddr: AF_INET, port and address big-endian
        item.extend(port.to_be_bytes());
        item.extend(self.ip);
        item.extend([0u8; 8]);
        item.extend(self.attributes_all());
        item.push(self.state);
        let mut out = Vec::with_capacity(6 + item.len());
        out.extend(1u16.to_le_bytes());
        out.extend(0x0Cu16.to_le_bytes());
        out.extend((item.len() as u16).to_le_bytes());
        out.extend(item);
        out
    }
}
