//! STAMP test packets: RFC 8762 base packets in unauthenticated and
//! authenticated mode, and the RFC 8972 extensions buffmon uses (Session-Sender
//! Identifier, TLVs, Extra Padding, HMAC TLV).
//!
//! Layouts (octet offsets), from RFC 8762 Figures 3-6 and RFC 8972 Figures 1-4:
//!
//! ```text
//! Session-Sender     unauthenticated       authenticated
//!   Sequence Number  0..4                  0..4    (MBZ 4..16)
//!   Timestamp        4..12                 16..24
//!   Error Estimate   12..14                24..26
//!   SSID             14..16                26..28
//!   MBZ              16..44                28..96
//!   HMAC             -                     96..112  over octets 0..96
//!   TLVs             44..                  112..
//!
//! Session-Reflector  unauthenticated       authenticated
//!   Sequence Number  0..4                  0..4    (MBZ 4..16)
//!   Timestamp        4..12                 16..24
//!   Error Estimate   12..14                24..26
//!   SSID             14..16                26..28  (MBZ 28..32)
//!   Receive Timestamp 16..24               32..40  (MBZ 40..48)
//!   S-S Seq Number   24..28                48..52  (MBZ 52..64)
//!   S-S Timestamp    28..36                64..72
//!   S-S Error Est.   36..38                72..74  (MBZ 74..80)
//!   S-S TTL          40                    80      (MBZ 81..96)
//!   HMAC             -                     96..112  over octets 0..96
//!   TLVs             44..                  112..
//! ```
//!
//! HMAC is HMAC-SHA-256 truncated to 128 bits. The base HMAC covers the first
//! 96 octets; the HMAC TLV (type 8) covers the base packet's Sequence Number
//! followed by every TLV before it, and only Extra Padding TLVs may follow it
//! (RFC 8972 §4.8). A reflected packet is the same size as the packet that
//! triggered it, and carries the received TLVs back with the reflector's flags.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;

pub const PORT: u16 = 862;
/// Base packet length, unauthenticated mode.
pub const BASE_LEN: usize = 44;
/// Base packet length, authenticated mode.
pub const AUTH_BASE_LEN: usize = 112;
/// 1500-octet MTU minus IPv4 (20) and UDP (8) headers.
pub const MAX_LEN: usize = 1472;
pub const HMAC_LEN: usize = 16;
const AUTH_HMAC_AT: usize = 96;
pub const TLV_HEADER: usize = 4;

/// TLV types (IANA "STAMP TLV Types").
pub mod tlv_type {
    pub const EXTRA_PADDING: u8 = 1;
    pub const HMAC: u8 = 8;
    /// RFC 10052 Reflected Test Packet Control.
    pub const REFLECTED_CONTROL: u8 = 12;
}

/// STAMP TLV Flags (RFC 8972 Figure 6, RFC 10052 §3). Bit 0 is the most significant.
pub mod flag {
    /// Unrecognized: the sender sets it; the reflector clears it for TLVs it processed.
    pub const U: u8 = 0x80;
    /// Malformed.
    pub const M: u8 = 0x40;
    /// Integrity: the extensions failed HMAC verification.
    pub const I: u8 = 0x20;
    /// Conformant Reflected Packet (RFC 10052): the reflector could not honour the request.
    pub const C: u8 = 0x10;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Unauthenticated,
    Authenticated,
}

impl Mode {
    pub const fn base_len(self) -> usize {
        match self {
            Mode::Unauthenticated => BASE_LEN,
            Mode::Authenticated => AUTH_BASE_LEN,
        }
    }
}

/// An HMAC key. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(Vec<u8>);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key(<{} octets>)", self.0.len())
    }
}

impl Key {
    pub const MIN_LEN: usize = 16;

    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < Self::MIN_LEN || bytes.len() > 64 {
            return Err(format!("an HMAC key must be {}-64 octets, got {}", Self::MIN_LEN, bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// Parses a hex string (whitespace ignored).
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("an HMAC key must be hex digits".into());
        }
        let bytes = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect::<Result<Vec<u8>, _>>()?;
        Self::new(bytes)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn mac(&self) -> Hmac<Sha256> {
        // HMAC accepts keys of any length; new_from_slice cannot fail here.
        <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC takes any key length")
    }

    /// HMAC-SHA-256 over the concatenation of `parts`, truncated to 128 bits.
    pub fn tag(&self, parts: &[&[u8]]) -> [u8; HMAC_LEN] {
        let mut m = self.mac();
        for p in parts {
            m.update(p);
        }
        let full = m.finalize().into_bytes();
        let mut out = [0_u8; HMAC_LEN];
        out.copy_from_slice(&full[..HMAC_LEN]);
        out
    }

    /// Constant-time check of a truncated tag.
    pub fn verify(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        if tag.len() != HMAC_LEN {
            return false;
        }
        let mut m = self.mac();
        for p in parts {
            m.update(p);
        }
        m.verify_truncated_left(tag).is_ok()
    }
}

// -- TLVs --------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    pub flags: u8,
    pub typ: u8,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn new(typ: u8, value: Vec<u8>) -> Self {
        Self { flags: 0, typ, value }
    }

    pub fn encoded_len(&self) -> usize {
        TLV_HEADER + self.value.len()
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.flags);
        out.push(self.typ);
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
    }
}

/// TLVs found after a base packet.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Extensions {
    pub tlvs: Vec<Tlv>,
    /// Bytes from the first malformed TLV to the end of the packet, if any.
    pub malformed: Option<Vec<u8>>,
}

impl Extensions {
    pub fn is_empty(&self) -> bool {
        self.tlvs.is_empty() && self.malformed.is_none()
    }

    pub fn find(&self, typ: u8) -> Option<&Tlv> {
        self.tlvs.iter().find(|t| t.typ == typ)
    }
}

/// Parses the TLVs in `buf` (the part of a packet after its base).
pub fn parse_tlvs(buf: &[u8]) -> Extensions {
    let mut ext = Extensions::default();
    let mut at = 0;
    while at < buf.len() {
        if buf.len() - at < TLV_HEADER {
            ext.malformed = Some(buf[at..].to_vec());
            break;
        }
        let len = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        if buf.len() - at - TLV_HEADER < len {
            ext.malformed = Some(buf[at..].to_vec());
            break;
        }
        ext.tlvs.push(Tlv {
            flags: buf[at],
            typ: buf[at + 1],
            value: buf[at + TLV_HEADER..at + TLV_HEADER + len].to_vec(),
        });
        at += TLV_HEADER + len;
    }
    ext
}

fn encode_tlvs(tlvs: &[Tlv]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tlvs.iter().map(Tlv::encoded_len).sum());
    for t in tlvs {
        t.write(&mut out);
    }
    out
}

/// Outcome of the RFC 8972 §4.8 integrity check of a packet's extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtIntegrity {
    /// No TLVs that need protecting (none, or a lone Extra Padding TLV) and no HMAC TLV.
    NotNeeded,
    Valid,
    /// Missing where required, misplaced, or wrong.
    Failed,
}

/// Checks the HMAC TLV of `ext` against `seq_field` (the base packet's
/// Sequence Number octets). `required` is true in authenticated mode, or when
/// the session protects its extensions in unauthenticated mode.
pub fn check_ext_hmac(ext: &Extensions, seq_field: &[u8], key: Option<&Key>, required: bool) -> ExtIntegrity {
    let protected = ext.tlvs.iter().any(|t| t.typ != tlv_type::EXTRA_PADDING) || ext.malformed.is_some();
    let Some(h) = ext.tlvs.iter().position(|t| t.typ == tlv_type::HMAC) else {
        return if required && protected { ExtIntegrity::Failed } else { ExtIntegrity::NotNeeded };
    };
    let Some(key) = key else { return ExtIntegrity::Failed };
    // Only Extra Padding TLVs may follow the HMAC TLV.
    if ext.tlvs[h + 1..].iter().any(|t| t.typ != tlv_type::EXTRA_PADDING) || ext.malformed.is_some() {
        return ExtIntegrity::Failed;
    }
    let covered = encode_tlvs(&ext.tlvs[..h]);
    if key.verify(&[seq_field, &covered], &ext.tlvs[h].value) {
        ExtIntegrity::Valid
    } else {
        ExtIntegrity::Failed
    }
}

/// RFC 10052 Reflected Test Packet Control TLV (type 12): asks the reflector
/// to answer one test packet with `count` packets of `len` octets, `interval_ns`
/// apart (0 = back to back).
///
/// Length note: RFC 10052 §3 says the TLV Length "MUST NOT be smaller than 12
/// octets", but its fixed fields are 8 octets of value, and RFC 8972 defines
/// Length as the Value only (12 looks like it counts the 4-octet header). We
/// send 8 and accept 8 or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectedControl {
    pub len: u16,
    pub count: u16,
    pub interval_ns: u32,
}

impl ReflectedControl {
    pub const VALUE_LEN: usize = 8;

    pub fn tlv(&self) -> Tlv {
        let mut v = Vec::with_capacity(Self::VALUE_LEN);
        v.extend_from_slice(&self.len.to_be_bytes());
        v.extend_from_slice(&self.count.to_be_bytes());
        v.extend_from_slice(&self.interval_ns.to_be_bytes());
        Tlv::new(tlv_type::REFLECTED_CONTROL, v)
    }

    pub fn parse(t: &Tlv) -> Option<Self> {
        if t.typ != tlv_type::REFLECTED_CONTROL || t.value.len() < Self::VALUE_LEN {
            return None;
        }
        let v = &t.value;
        Some(Self {
            len: u16::from_be_bytes([v[0], v[1]]),
            count: u16::from_be_bytes([v[2], v[3]]),
            interval_ns: u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
        })
    }

    /// Length of each reflected packet (RFC 10052 §3): the larger of the base
    /// reflector packet plus the received TLVs other than Extra Padding (and the
    /// HMAC TLV the reflector adds back), and the requested length rounded up to
    /// a multiple of 4.
    pub fn reflected_len(&self, mode: Mode, tlvs_without_padding: &[Tlv]) -> usize {
        let min = mode.base_len() + tlvs_without_padding.iter().map(Tlv::encoded_len).sum::<usize>();
        let want = usize::from(self.len).div_ceil(4) * 4;
        let len = min.max(want);
        // Room for an Extra Padding TLV, or exactly the minimum.
        if len > min && len < min + TLV_HEADER {
            min + TLV_HEADER
        } else {
            len
        }
    }
}

/// The TLVs a reflector sends back (RFC 8972 §4): every received TLV, U cleared
/// on the ones it processed (`understood`), U set on the others, and U and I set
/// on all of them when the extensions failed HMAC verification.
pub fn reflect_tlvs(ext: &Extensions, integrity: ExtIntegrity, understood: impl Fn(u8) -> bool) -> Vec<Tlv> {
    ext.tlvs
        .iter()
        .map(|t| {
            let mut flags = t.flags & !(flag::U | flag::M | flag::I | flag::C);
            if integrity == ExtIntegrity::Failed {
                flags |= flag::U | flag::I;
            } else if !understood(t.typ) {
                flags |= flag::U;
            }
            Tlv { flags, ..t.clone() }
        })
        .collect()
}

/// Fills `buf` with pseudorandom octets (RFC 8972 §4.1: padding SHOULD be
/// pseudorandom). Not cryptographic; it keeps padding incompressible, so a
/// compressing WAN optimiser cannot shrink test packets and skew capacity.
pub fn fill_pseudorandom(buf: &mut [u8], seed: u64) {
    let mut x = seed ^ 0x9E37_79B9_7F4A_7C15;
    for chunk in buf.chunks_mut(8) {
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_be_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
}

/// Appends TLVs, an HMAC TLV when `key` is set and anything needs protecting,
/// and Extra Padding up to `len`. `seq_field` is the base packet's Sequence
/// Number octets. Errors when `len` cannot be met.
fn append_extensions(
    out: &mut Vec<u8>,
    seq_field: [u8; 4],
    tlvs: &[Tlv],
    key: Option<&Key>,
    len: usize,
    pad_seed: u64,
) -> Result<(), String> {
    let base = out.len();
    let mut ext = encode_tlvs(tlvs);
    if let Some(k) = key {
        if !tlvs.is_empty() {
            let tag = k.tag(&[&seq_field, &ext]);
            Tlv { flags: flag::U, typ: tlv_type::HMAC, value: tag.to_vec() }.write(&mut ext);
        }
    }
    out.extend_from_slice(&ext);
    if out.len() < len {
        let room = len - out.len();
        if room < TLV_HEADER {
            return Err(format!("cannot pad {} octets to {len}: an Extra Padding TLV needs at least 4", out.len()));
        }
        let mut pad = vec![0_u8; room - TLV_HEADER];
        fill_pseudorandom(&mut pad, pad_seed);
        Tlv { flags: flag::U, typ: tlv_type::EXTRA_PADDING, value: pad }.write(out);
    }
    if out.len() > len {
        return Err(format!("packet needs {} octets (base {base} + extensions), more than {len}", out.len()));
    }
    Ok(())
}

/// Smallest packet that can carry `tlvs` in `mode` (with an HMAC TLV when keyed).
pub fn min_len(mode: Mode, tlvs: &[Tlv], keyed: bool) -> usize {
    let ext: usize = tlvs.iter().map(Tlv::encoded_len).sum();
    mode.base_len() + ext + if keyed && !tlvs.is_empty() { TLV_HEADER + HMAC_LEN } else { 0 }
}

/// True if a packet of `len` octets can be built: exactly the base and
/// extensions, or with room for an Extra Padding TLV.
pub fn len_ok(min: usize, len: usize) -> bool {
    len == min || len >= min + TLV_HEADER
}

/// How one session's packets are built and checked.
#[derive(Debug, Clone)]
pub struct SessionAuth {
    pub mode: Mode,
    pub key: Option<Key>,
    /// RFC 8972 SSID; 0 = not used.
    pub ssid: u16,
}

impl SessionAuth {
    pub fn none() -> Self {
        Self { mode: Mode::Unauthenticated, key: None, ssid: 0 }
    }

    pub fn authenticated(ssid: u16, key: Key) -> Self {
        Self { mode: Mode::Authenticated, key: Some(key), ssid }
    }

    /// A complete Session-Sender packet of `len` octets.
    pub fn sender_packet(
        &self,
        seq: u32,
        timestamp: u64,
        error_estimate: u16,
        tlvs: &[Tlv],
        len: usize,
    ) -> Result<Vec<u8>, String> {
        SenderPacket { seq, timestamp, error_estimate, ssid: self.ssid }.build(self.mode, self.key.as_ref(), tlvs, len)
    }

    /// Parses a reflected packet; in authenticated mode a bad HMAC is an error.
    pub fn parse_reflected(&self, buf: &[u8]) -> Result<(ReflectorPacket, Extensions), ParseError> {
        ReflectorPacket::parse(buf, self.mode, self.key.as_ref())
    }
}

// -- Session-Sender packet -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenderPacket {
    pub seq: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    /// RFC 8972 Session-Sender Identifier; 0 = not used.
    pub ssid: u16,
}

impl SenderPacket {
    /// Writes the base packet (no HMAC) into `buf[..mode.base_len()]`, zeroing MBZ.
    fn write_base(&self, mode: Mode, buf: &mut [u8]) {
        let b = &mut buf[..mode.base_len()];
        b.fill(0);
        b[0..4].copy_from_slice(&self.seq.to_be_bytes());
        let (ts, err, ssid) = match mode {
            Mode::Unauthenticated => (4, 12, 14),
            Mode::Authenticated => (16, 24, 26),
        };
        b[ts..ts + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        b[err..err + 2].copy_from_slice(&self.error_estimate.to_be_bytes());
        b[ssid..ssid + 2].copy_from_slice(&self.ssid.to_be_bytes());
    }

    fn read_base(mode: Mode, buf: &[u8]) -> Option<Self> {
        if buf.len() < mode.base_len() {
            return None;
        }
        let (ts, err, ssid) = match mode {
            Mode::Unauthenticated => (4, 12, 14),
            Mode::Authenticated => (16, 24, 26),
        };
        Some(Self {
            seq: u32::from_be_bytes(buf[0..4].try_into().ok()?),
            timestamp: u64::from_be_bytes(buf[ts..ts + 8].try_into().ok()?),
            error_estimate: u16::from_be_bytes(buf[err..err + 2].try_into().ok()?),
            ssid: u16::from_be_bytes(buf[ssid..ssid + 2].try_into().ok()?),
        })
    }

    /// A complete Session-Sender packet of exactly `len` octets: base, `tlvs`
    /// (sent with the U flag set, RFC 8972 §4), an HMAC TLV when keyed and there
    /// are TLVs, and pseudorandom Extra Padding up to `len`. In authenticated
    /// mode `key` is required and the base HMAC is filled in.
    pub fn build(&self, mode: Mode, key: Option<&Key>, tlvs: &[Tlv], len: usize) -> Result<Vec<u8>, String> {
        if mode == Mode::Authenticated && key.is_none() {
            return Err("authenticated mode needs a key".into());
        }
        let mut out = vec![0_u8; mode.base_len()];
        self.write_base(mode, &mut out);
        let sent: Vec<Tlv> = tlvs.iter().map(|t| Tlv { flags: flag::U, ..t.clone() }).collect();
        append_extensions(&mut out, self.seq.to_be_bytes(), &sent, key, len, u64::from(self.seq) ^ self.timestamp)?;
        if mode == Mode::Authenticated {
            let tag = key.expect("checked above").tag(&[&out[..AUTH_HMAC_AT]]);
            out[AUTH_HMAC_AT..AUTH_BASE_LEN].copy_from_slice(&tag);
        }
        Ok(out)
    }

    /// Parses a Session-Sender packet. In authenticated mode the base HMAC is
    /// verified first with the key `key_for` returns for the packet's SSID;
    /// nothing in a packet that fails is used.
    pub fn parse<'k>(
        buf: &[u8],
        mode: Mode,
        key_for: impl Fn(u16) -> Option<&'k Key>,
    ) -> Result<(Self, Extensions, Option<&'k Key>), ParseError> {
        let p = Self::read_base(mode, buf).ok_or(ParseError::Short)?;
        let key = key_for(p.ssid);
        if mode == Mode::Authenticated {
            let k = key.ok_or(ParseError::UnknownSsid(p.ssid))?;
            if !k.verify(&[&buf[..AUTH_HMAC_AT]], &buf[AUTH_HMAC_AT..AUTH_BASE_LEN]) {
                return Err(ParseError::BadHmac);
            }
        }
        Ok((p, parse_tlvs(&buf[mode.base_len()..]), key))
    }

    /// Unauthenticated, no extensions: the classic 44-octet-plus packet.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        Self::read_base(Mode::Unauthenticated, buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Short,
    UnknownSsid(u16),
    BadHmac,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Short => write!(f, "shorter than the base packet"),
            ParseError::UnknownSsid(s) => write!(f, "no key for SSID {s}"),
            ParseError::BadHmac => write!(f, "HMAC verification failed"),
        }
    }
}

// -- Session-Reflector packet ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectorPacket {
    pub seq: u32,
    pub timestamp: u64,
    pub error_estimate: u16,
    pub ssid: u16,
    pub receive_timestamp: u64,
    pub sender_seq: u32,
    pub sender_timestamp: u64,
    pub sender_error_estimate: u16,
    pub sender_ttl: u8,
}

struct ReflectorOffsets {
    ts: usize,
    err: usize,
    ssid: usize,
    rx: usize,
    sseq: usize,
    sts: usize,
    serr: usize,
    ttl: usize,
}

const fn reflector_offsets(mode: Mode) -> ReflectorOffsets {
    match mode {
        Mode::Unauthenticated => {
            ReflectorOffsets { ts: 4, err: 12, ssid: 14, rx: 16, sseq: 24, sts: 28, serr: 36, ttl: 40 }
        }
        Mode::Authenticated => {
            ReflectorOffsets { ts: 16, err: 24, ssid: 26, rx: 32, sseq: 48, sts: 64, serr: 72, ttl: 80 }
        }
    }
}

impl ReflectorPacket {
    fn write_base(&self, mode: Mode, buf: &mut [u8]) {
        let b = &mut buf[..mode.base_len()];
        b.fill(0);
        let o = reflector_offsets(mode);
        b[0..4].copy_from_slice(&self.seq.to_be_bytes());
        b[o.ts..o.ts + 8].copy_from_slice(&self.timestamp.to_be_bytes());
        b[o.err..o.err + 2].copy_from_slice(&self.error_estimate.to_be_bytes());
        b[o.ssid..o.ssid + 2].copy_from_slice(&self.ssid.to_be_bytes());
        b[o.rx..o.rx + 8].copy_from_slice(&self.receive_timestamp.to_be_bytes());
        b[o.sseq..o.sseq + 4].copy_from_slice(&self.sender_seq.to_be_bytes());
        b[o.sts..o.sts + 8].copy_from_slice(&self.sender_timestamp.to_be_bytes());
        b[o.serr..o.serr + 2].copy_from_slice(&self.sender_error_estimate.to_be_bytes());
        b[o.ttl] = self.sender_ttl;
    }

    fn read_base(mode: Mode, buf: &[u8]) -> Option<Self> {
        if buf.len() < mode.base_len() {
            return None;
        }
        let o = reflector_offsets(mode);
        Some(Self {
            seq: u32::from_be_bytes(buf[0..4].try_into().ok()?),
            timestamp: u64::from_be_bytes(buf[o.ts..o.ts + 8].try_into().ok()?),
            error_estimate: u16::from_be_bytes(buf[o.err..o.err + 2].try_into().ok()?),
            ssid: u16::from_be_bytes(buf[o.ssid..o.ssid + 2].try_into().ok()?),
            receive_timestamp: u64::from_be_bytes(buf[o.rx..o.rx + 8].try_into().ok()?),
            sender_seq: u32::from_be_bytes(buf[o.sseq..o.sseq + 4].try_into().ok()?),
            sender_timestamp: u64::from_be_bytes(buf[o.sts..o.sts + 8].try_into().ok()?),
            sender_error_estimate: u16::from_be_bytes(buf[o.serr..o.serr + 2].try_into().ok()?),
            sender_ttl: buf[o.ttl],
        })
    }

    /// A complete reflected packet: base, then `tlvs` as the reflector returns
    /// them (flags already set by the caller), a recomputed HMAC TLV where the
    /// received packet had one, the malformed tail copied back with M set, and
    /// Extra Padding up to `len`. In authenticated mode the base HMAC is filled in.
    pub fn build(
        &self,
        mode: Mode,
        key: Option<&Key>,
        tlvs: &[Tlv],
        malformed: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, String> {
        if mode == Mode::Authenticated && key.is_none() {
            return Err("authenticated mode needs a key".into());
        }
        let mut out = vec![0_u8; mode.base_len()];
        self.write_base(mode, &mut out);
        // The HMAC TLV is recomputed over what this packet carries; TLVs after
        // it (Extra Padding only, by rule) are copied after it.
        let (before, after): (Vec<Tlv>, Vec<Tlv>) = match tlvs.iter().position(|t| t.typ == tlv_type::HMAC) {
            Some(h) => (tlvs[..h].to_vec(), tlvs[h + 1..].to_vec()),
            None => (tlvs.to_vec(), Vec::new()),
        };
        let had_hmac = tlvs.iter().any(|t| t.typ == tlv_type::HMAC);
        let mut ext = encode_tlvs(&before);
        if had_hmac {
            let hmac_flags = tlvs.iter().find(|t| t.typ == tlv_type::HMAC).map_or(0, |t| t.flags);
            let tag = match key {
                Some(k) => k.tag(&[&self.seq.to_be_bytes(), &ext]),
                None => [0; HMAC_LEN],
            };
            Tlv { flags: hmac_flags, typ: tlv_type::HMAC, value: tag.to_vec() }.write(&mut ext);
        }
        ext.extend_from_slice(&encode_tlvs(&after));
        if let Some(m) = malformed {
            let start = ext.len();
            ext.extend_from_slice(m);
            ext[start] |= flag::M;
        }
        out.extend_from_slice(&ext);
        if out.len() < len {
            let room = len - out.len();
            if room < TLV_HEADER {
                out.resize(len, 0);
            } else {
                let mut pad = vec![0_u8; room - TLV_HEADER];
                fill_pseudorandom(&mut pad, u64::from(self.seq) ^ self.timestamp);
                Tlv { flags: 0, typ: tlv_type::EXTRA_PADDING, value: pad }.write(&mut out);
            }
        }
        if mode == Mode::Authenticated {
            let tag = key.expect("checked above").tag(&[&out[..AUTH_HMAC_AT]]);
            out[AUTH_HMAC_AT..AUTH_BASE_LEN].copy_from_slice(&tag);
        }
        Ok(out)
    }

    /// Parses a reflected packet. In authenticated mode the base HMAC is
    /// verified first; a packet that fails is rejected (it is not ours, or it
    /// was altered on the way).
    pub fn parse(buf: &[u8], mode: Mode, key: Option<&Key>) -> Result<(Self, Extensions), ParseError> {
        let p = Self::read_base(mode, buf).ok_or(ParseError::Short)?;
        if mode == Mode::Authenticated {
            let k = key.ok_or(ParseError::UnknownSsid(p.ssid))?;
            if !k.verify(&[&buf[..AUTH_HMAC_AT]], &buf[AUTH_HMAC_AT..AUTH_BASE_LEN]) {
                return Err(ParseError::BadHmac);
            }
        }
        Ok((p, parse_tlvs(&buf[mode.base_len()..])))
    }

    /// Unauthenticated base fields only.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        Self::read_base(Mode::Unauthenticated, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap()
    }

    fn sp() -> SenderPacket {
        SenderPacket { seq: 0xDEAD_BEEF, timestamp: 0x0123_4567_89AB_CDEF, error_estimate: 0x8001, ssid: 0x1234 }
    }

    fn rp() -> ReflectorPacket {
        ReflectorPacket {
            seq: 7,
            timestamp: 0x1111_2222_3333_4444,
            error_estimate: 2,
            ssid: 0x1234,
            receive_timestamp: 0x5555_6666_7777_8888,
            sender_seq: 4,
            sender_timestamp: 5,
            sender_error_estimate: 6,
            sender_ttl: 61,
        }
    }

    #[test]
    fn unauthenticated_layouts_match_rfc_8762_and_8972() {
        let b = sp().build(Mode::Unauthenticated, None, &[], BASE_LEN).unwrap();
        assert_eq!(b.len(), 44);
        assert_eq!(&b[0..4], &0xDEAD_BEEF_u32.to_be_bytes());
        assert_eq!(&b[4..12], &0x0123_4567_89AB_CDEF_u64.to_be_bytes());
        assert_eq!(&b[12..14], &[0x80, 0x01]);
        assert_eq!(&b[14..16], &[0x12, 0x34], "SSID at 14 (RFC 8972 Figure 1)");
        assert!(b[16..44].iter().all(|x| *x == 0));
        let r = rp().build(Mode::Unauthenticated, None, &[], None, BASE_LEN).unwrap();
        assert_eq!(&r[14..16], &[0x12, 0x34]);
        assert_eq!(&r[16..24], &0x5555_6666_7777_8888_u64.to_be_bytes());
        assert_eq!((&r[24..28], r[40]), (&4_u32.to_be_bytes()[..], 61));
        assert_eq!(ReflectorPacket::decode(&r), Some(rp()));
    }

    #[test]
    fn authenticated_layouts_match_rfc_8762_figures_4_and_6() {
        let k = key();
        let b = sp().build(Mode::Authenticated, Some(&k), &[], AUTH_BASE_LEN).unwrap();
        assert_eq!(b.len(), 112);
        assert!(b[4..16].iter().all(|x| *x == 0), "MBZ 4..16");
        assert_eq!(&b[16..24], &0x0123_4567_89AB_CDEF_u64.to_be_bytes());
        assert_eq!(&b[24..26], &[0x80, 0x01]);
        assert_eq!(&b[26..28], &[0x12, 0x34], "SSID at 26 (RFC 8972 Figure 3)");
        assert!(b[28..96].iter().all(|x| *x == 0));
        assert_eq!(&b[96..112], &k.tag(&[&b[..96]]), "HMAC over the first 96 octets");

        let r = rp().build(Mode::Authenticated, Some(&k), &[], None, AUTH_BASE_LEN).unwrap();
        assert_eq!(&r[32..40], &0x5555_6666_7777_8888_u64.to_be_bytes());
        assert_eq!(&r[48..52], &4_u32.to_be_bytes());
        assert_eq!(&r[64..72], &5_u64.to_be_bytes());
        assert_eq!((r[80], &r[96..112]), (61, &k.tag(&[&r[..96]])[..]));
        for (lo, hi) in [(4, 16), (28, 32), (40, 48), (52, 64), (74, 80), (81, 96)] {
            assert!(r[lo..hi].iter().all(|x| *x == 0), "MBZ {lo}..{hi}");
        }
        assert_eq!(ReflectorPacket::parse(&r, Mode::Authenticated, Some(&k)).unwrap().0, rp());
    }

    #[test]
    fn hmac_is_hmac_sha256_truncated_to_128_bits() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        let k = Key(b"Jefe".to_vec());
        let tag = k.tag(&[b"what do ya want for nothing?"]);
        assert_eq!(Key(tag.to_vec()).to_hex(), "5bdcc146bf60754e6a042426089575c7");
    }

    #[test]
    fn a_tampered_or_wrongly_keyed_packet_is_rejected() {
        let k = key();
        let mut b = sp().build(Mode::Authenticated, Some(&k), &[], 200).unwrap();
        let ok = SenderPacket::parse(&b, Mode::Authenticated, |s| (s == 0x1234).then_some(&k)).unwrap();
        assert_eq!(ok.0, sp());
        assert_eq!(
            SenderPacket::parse(&b, Mode::Authenticated, |_| None).unwrap_err(),
            ParseError::UnknownSsid(0x1234)
        );
        let other = Key::new(vec![9; 32]).unwrap();
        assert_eq!(SenderPacket::parse(&b, Mode::Authenticated, |_| Some(&other)).unwrap_err(), ParseError::BadHmac);
        b[17] ^= 1; // the timestamp
        assert_eq!(SenderPacket::parse(&b, Mode::Authenticated, |_| Some(&k)).unwrap_err(), ParseError::BadHmac);
    }

    #[test]
    fn larger_packets_carry_pseudorandom_extra_padding() {
        let b = sp().build(Mode::Unauthenticated, None, &[], 1200).unwrap();
        assert_eq!(b.len(), 1200);
        let ext = parse_tlvs(&b[BASE_LEN..]);
        assert_eq!(ext.tlvs.len(), 1);
        let t = &ext.tlvs[0];
        assert_eq!((t.flags, t.typ, t.value.len()), (flag::U, tlv_type::EXTRA_PADDING, 1200 - 44 - 4));
        let zeros = t.value.iter().filter(|x| **x == 0).count();
        assert!(zeros < 20, "padding is not compressible zeros ({zeros})");
        assert!(sp().build(Mode::Unauthenticated, None, &[], 46).is_err(), "no room for a padding TLV");
        assert!(len_ok(44, 44) && !len_ok(44, 46) && len_ok(44, 48));
    }

    #[test]
    fn hmac_tlv_covers_sequence_and_preceding_tlvs_and_must_be_last() {
        let k = key();
        let ctl = Tlv::new(tlv_type::REFLECTED_CONTROL, vec![0, 200, 0, 10, 0, 0, 0, 0]);
        let b = sp().build(Mode::Authenticated, Some(&k), std::slice::from_ref(&ctl), 400).unwrap();
        let (p, ext, kk) = SenderPacket::parse(&b, Mode::Authenticated, |_| Some(&k)).unwrap();
        assert_eq!([ext.tlvs[0].typ, ext.tlvs[1].typ, ext.tlvs[2].typ], [12, 8, 1]);
        assert!(ext.tlvs.iter().all(|t| t.flags == flag::U), "a sender sets U on every TLV");
        let seq = p.seq.to_be_bytes();
        assert_eq!(check_ext_hmac(&ext, &seq, kk, true), ExtIntegrity::Valid);
        // Altered TLV value -> failure.
        let mut bad = ext.clone();
        bad.tlvs[0].value[1] = 201;
        assert_eq!(check_ext_hmac(&bad, &seq, Some(&k), true), ExtIntegrity::Failed);
        // HMAC TLV not last (another TLV after it) -> failure.
        let mut moved = ext.clone();
        moved.tlvs.insert(2, Tlv::new(42, vec![1, 2, 3, 4]));
        assert_eq!(check_ext_hmac(&moved, &seq, Some(&k), true), ExtIntegrity::Failed);
        // Missing where required -> failure; a lone Extra Padding needs none.
        let mut missing = ext.clone();
        missing.tlvs.remove(1);
        assert_eq!(check_ext_hmac(&missing, &seq, Some(&k), true), ExtIntegrity::Failed);
        let pad_only = parse_tlvs(&sp().build(Mode::Authenticated, Some(&k), &[], 300).unwrap()[AUTH_BASE_LEN..]);
        assert_eq!(check_ext_hmac(&pad_only, &seq, Some(&k), true), ExtIntegrity::NotNeeded);
    }

    #[test]
    fn reflected_packets_keep_the_size_and_carry_tlvs_back() {
        let k = key();
        let ctl = Tlv::new(tlv_type::REFLECTED_CONTROL, vec![0, 200, 0, 10, 0, 0, 0, 0]);
        let b = sp().build(Mode::Authenticated, Some(&k), &[ctl], 400).unwrap();
        let (_, ext, _) = SenderPacket::parse(&b, Mode::Authenticated, |_| Some(&k)).unwrap();
        // The reflector clears U on what it processed.
        let back: Vec<Tlv> = ext.tlvs.iter().map(|t| Tlv { flags: 0, ..t.clone() }).collect();
        let r = rp().build(Mode::Authenticated, Some(&k), &back, None, b.len()).unwrap();
        assert_eq!(r.len(), b.len());
        let (rr, rext) = ReflectorPacket::parse(&r, Mode::Authenticated, Some(&k)).unwrap();
        assert_eq!(rr, rp());
        assert_eq!(check_ext_hmac(&rext, &rr.seq.to_be_bytes(), Some(&k), true), ExtIntegrity::Valid);
        assert_eq!(rext.tlvs[0].value, back[0].value);
    }

    #[test]
    fn malformed_tlvs_are_kept_as_a_tail_and_returned_with_m() {
        let mut tail = vec![0x80, 1, 0, 50, 1, 2, 3]; // claims 50 octets, has 3
        let ext = parse_tlvs(&tail);
        assert!(ext.tlvs.is_empty() && ext.malformed.as_deref() == Some(&tail[..]));
        let r = rp().build(Mode::Unauthenticated, None, &[], ext.malformed.as_deref(), BASE_LEN + tail.len()).unwrap();
        tail[0] |= flag::M;
        assert_eq!(&r[BASE_LEN..], &tail[..]);
        // Zero-filled padding from older probes parses as empty type-0 TLVs and round-trips in length.
        let old = vec![0_u8; 16];
        let e = parse_tlvs(&old);
        assert_eq!((e.tlvs.len(), e.malformed.is_none()), (4, true));
    }

    #[test]
    fn reflected_control_tlv_round_trips_and_sizes_replies() {
        let c = ReflectedControl { len: 1201, count: 64, interval_ns: 0 };
        let t = c.tlv();
        assert_eq!((t.typ, t.value.len()), (12, 8));
        assert_eq!(&t.value, &[0x04, 0xB1, 0, 64, 0, 0, 0, 0]);
        assert_eq!(ReflectedControl::parse(&t), Some(c));
        let mut longer = t.clone();
        longer.value.extend_from_slice(&[0, 0, 0, 0]); // a 12-octet Length is accepted too
        assert_eq!(ReflectedControl::parse(&longer), Some(c));
        assert_eq!(ReflectedControl::parse(&Tlv::new(12, vec![0; 7])), None);
        let hmac = Tlv::new(tlv_type::HMAC, vec![0; 16]);
        let tlvs = [t, hmac];
        // 1201 rounds up to 1204; the base + TLVs (112 + 12 + 20) is smaller.
        assert_eq!(c.reflected_len(Mode::Authenticated, &tlvs), 1204);
        // A request below the minimum gets the minimum.
        let small = ReflectedControl { len: 10, ..c };
        assert_eq!(small.reflected_len(Mode::Authenticated, &tlvs), 144);
    }

    #[test]
    fn keys_reject_short_or_bad_hex_and_never_print() {
        assert!(Key::from_hex("abcd").is_err());
        assert!(Key::from_hex("zz".repeat(16).as_str()).is_err());
        assert_eq!(format!("{:?}", key()), "Key(<32 octets>)");
    }
}
