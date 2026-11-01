//! STAMP test packets, unauthenticated mode (RFC 8762 §4.2.1 and §4.3.1).
//!
//! Both packet types are 44 octets so a reflected packet is the same size as
//! the one that triggered it (no amplification). Longer packets are allowed;
//! the extra octets are zero padding.

pub const PORT: u16 = 862;
pub const BASE_LEN: usize = 44;
/// 1500-octet MTU minus IPv4 (20) and UDP (8) headers.
pub const MAX_LEN: usize = 1472;

/// Session-Sender test packet.
///
/// ```text
///  0..4   Sequence Number
///  4..12  Timestamp (T1)
/// 12..14  Error Estimate
/// 14..44  MBZ
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderPacket {
    pub seq: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
}

impl SenderPacket {
    /// Writes the packet into `buf` (which must be at least [`BASE_LEN`]) and
    /// zeroes everything else in `buf`.
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= BASE_LEN, "STAMP buffer too short");
        buf.fill(0);
        buf[0..4].copy_from_slice(&self.seq.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < BASE_LEN {
            return None;
        }
        Some(Self {
            seq: u32::from_be_bytes(buf[0..4].try_into().ok()?),
            timestamp: u64::from_be_bytes(buf[4..12].try_into().ok()?),
            error_estimate: u16::from_be_bytes(buf[12..14].try_into().ok()?),
        })
    }
}

/// Session-Reflector test packet.
///
/// ```text
///  0..4   Sequence Number (reflector's own counter in stateful mode)
///  4..12  Timestamp (T3, transmit)
/// 12..14  Error Estimate
/// 14..16  MBZ
/// 16..24  Receive Timestamp (T2)
/// 24..28  Session-Sender Sequence Number
/// 28..36  Session-Sender Timestamp (T1)
/// 36..38  Session-Sender Error Estimate
/// 38..40  MBZ
/// 40      Session-Sender TTL
/// 41..44  MBZ
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorPacket {
    pub seq: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub receive_timestamp: u64,
    pub sender_seq: u32,
    pub sender_timestamp: u64,
    pub sender_error_estimate: u16,
    pub sender_ttl: u8,
}

impl ReflectorPacket {
    pub fn encode(&self, buf: &mut [u8]) {
        assert!(buf.len() >= BASE_LEN, "STAMP buffer too short");
        buf.fill(0);
        buf[0..4].copy_from_slice(&self.seq.to_be_bytes());
        buf[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[12..14].copy_from_slice(&self.error_estimate.to_be_bytes());
        buf[16..24].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        buf[24..28].copy_from_slice(&self.sender_seq.to_be_bytes());
        buf[28..36].copy_from_slice(&self.sender_timestamp.to_be_bytes());
        buf[36..38].copy_from_slice(&self.sender_error_estimate.to_be_bytes());
        buf[40] = self.sender_ttl;
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < BASE_LEN {
            return None;
        }
        Some(Self {
            seq: u32::from_be_bytes(buf[0..4].try_into().ok()?),
            timestamp: u64::from_be_bytes(buf[4..12].try_into().ok()?),
            error_estimate: u16::from_be_bytes(buf[12..14].try_into().ok()?),
            receive_timestamp: u64::from_be_bytes(buf[16..24].try_into().ok()?),
            sender_seq: u32::from_be_bytes(buf[24..28].try_into().ok()?),
            sender_timestamp: u64::from_be_bytes(buf[28..36].try_into().ok()?),
            sender_error_estimate: u16::from_be_bytes(buf[36..38].try_into().ok()?),
            sender_ttl: buf[40],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_round_trip_and_mbz() {
        let p = SenderPacket { seq: 0xDEAD_BEEF, timestamp: 0x0123_4567_89AB_CDEF, error_estimate: 0x8001 };
        let mut buf = [0xFF_u8; 64];
        p.encode(&mut buf);
        assert_eq!(SenderPacket::decode(&buf), Some(p));
        assert!(buf[14..].iter().all(|b| *b == 0), "MBZ and padding must be zero");
    }

    #[test]
    fn reflector_round_trip_and_layout() {
        let p = ReflectorPacket {
            seq: 7,
            timestamp: 1,
            error_estimate: 2,
            receive_timestamp: 3,
            sender_seq: 4,
            sender_timestamp: 5,
            sender_error_estimate: 6,
            sender_ttl: 61,
        };
        let mut buf = [0xFF_u8; BASE_LEN];
        p.encode(&mut buf);
        assert_eq!(ReflectorPacket::decode(&buf), Some(p));
        assert_eq!(buf[40], 61);
        assert_eq!(&buf[14..16], &[0, 0]);
        assert_eq!(&buf[38..40], &[0, 0]);
        assert_eq!(&buf[41..44], &[0, 0, 0]);
    }

    #[test]
    fn short_packets_are_rejected() {
        assert!(SenderPacket::decode(&[0; BASE_LEN - 1]).is_none());
        assert!(ReflectorPacket::decode(&[0; BASE_LEN - 1]).is_none());
    }
}
