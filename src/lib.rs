//! # 5grok-parser
//!
//! Standalone, self-contained DIAG frame parser for Qualcomm, MediaTek, and
//! Samsung Shannon cellular modems. Decodes NR/LTE/WCDMA/GSM signaling
//! (RRC, NAS, ML1, MAC/PDCP/RLC, PHY) into structured JSON.
//!
//! This crate is the parser core of the [5grok](https://github.com/yallasec/5grok)
//! project, extracted so it can be reused as a library without pulling in the
//! REST/WebSocket server, agent client, database, or export stack.
//!
//! ## Quick start
//!
//! ```no_run
//! use fivegrok_parser::{DiagFrame, decode_agent_frame};
//!
//! let frame = DiagFrame {
//!     sequence: 0,
//!     timestamp_wall: 0,
//!     timestamp_mono: 0,
//!     log_code: 0x1D0B, // NR_RRC_OTA legacy
//!     payload: vec![],  // [log_code_le(2) || raw_diag_packet]
//!     vendor: 0,        // 0=Qualcomm, 1=MediaTek, 2=Samsung
//! };
//! let decoded = decode_agent_frame(&frame);
//! println!("{}: {}", decoded.log_name, decoded.summary);
//! ```
//!
//! ## Features
//!
//! - `asn1-rrc` (off by default) — enable full ASN.1 UPER decode of BCCH
//!   messages (MIB/SIB1) via the `grok5-asn1` crate.

pub mod decoder;

use serde::{Deserialize, Serialize};

/// A DIAG frame as handed to the parser.
///
/// The `payload` MUST be prefixed with a little-endian `u16` log code,
/// followed by the raw DIAG packet (cmd/more/outer_len/entry_len/log_code/
/// timestamp + protocol bytes), matching the wire format produced by
/// [agent-5grok](https://github.com/yallasec/5grok).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagFrame {
    pub sequence: u64,
    pub timestamp_wall: i64,
    pub timestamp_mono: u64,
    pub log_code: u16,
    pub payload: Vec<u8>,
    /// Chipset vendor: 0 = Qualcomm, 1 = MediaTek, 2 = Samsung Shannon.
    #[serde(default)]
    pub vendor: u8,
}

pub use decoder::{decode_agent_frame, DecodedPacket};
