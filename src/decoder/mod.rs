//! Frame Decoder (self-contained)
//!
//! Decodes incoming DiagFrames from the agent into structured JSON.
//! Split into submodules by protocol layer.

pub mod dispatch;
pub mod legacy;
pub mod macpdcp;
pub mod mediatek;
pub mod metadata;
pub mod ml1;
pub mod nas_5g;
pub mod nas_common;
pub mod nas_lte;
pub mod phy;
pub mod rrc;
pub mod samsung;

use crate::DiagFrame as AgentDiagFrame;
use dispatch::decode_protocol;
use metadata::{categorize_protocol, get_log_code_metadata, hex_preview};
use serde::Serialize;

/// DIAG log command byte
const DIAG_LOG_F: u8 = 0x10;

/// Size of prepended log_code in DiagFrame payload
const LOG_CODE_PREFIX: usize = 2;

/// Size of DIAG log header: cmd(1) + more(1) + outer_len(2) + entry_len(2) + log_code(2) + timestamp(8) = 16
const DIAG_LOG_HEADER_SIZE: usize = 16;

/// A decoded packet ready for WebSocket broadcast
#[derive(Debug, Clone, Serialize)]
pub struct DecodedPacket {
    /// Which agent this frame came from (empty for legacy single-agent mode)
    #[serde(skip_serializing_if = "String::is_empty")]
    pub agent_id: String,
    /// Monotonic sequence number from agent
    pub sequence: u64,
    /// Wall-clock timestamp (unix ms)
    pub timestamp: i64,
    /// Raw DIAG log code
    pub log_code: u16,
    /// Human-readable log code name
    pub log_name: String,
    /// Protocol category (NR-RRC, LTE-NAS, ML1, etc.)
    pub protocol: String,
    /// RAT (NR, LTE, WCDMA, GSM)
    pub rat: String,
    /// Protocol layer (RRC, NAS, ML1, MAC, PDCP, RLC, PHY)
    pub layer: String,
    /// Decoded message (full parse result as JSON)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<serde_json::Value>,
    /// One-line summary of the decoded message
    pub summary: String,
    /// Whether the message was fully decoded
    pub fully_decoded: bool,
    /// Raw payload size in bytes
    pub raw_size: usize,
    /// Hex preview of raw data (first 64 bytes)
    pub hex_preview: String,
    /// Chipset vendor ("Qualcomm", "MediaTek", "Samsung", "")
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vendor: String,
    /// Raw payload bytes for PCAP export (not serialized to WebSocket clients)
    #[serde(skip)]
    pub raw_payload: Vec<u8>,
}

/// Decode an agent DiagFrame into a DecodedPacket
pub fn decode_agent_frame(frame: &AgentDiagFrame) -> DecodedPacket {
    let log_code = frame.log_code;
    let vendor_id = frame.vendor;
    let (log_name, rat, layer) = get_log_code_metadata(log_code);

    // Extract protocol data from the DiagFrame payload
    let protocol_data = extract_protocol_data(&frame.payload, vendor_id);

    // Try self-contained protocol header parsing
    let (decoded, summary, fully_decoded) = match protocol_data {
        Some(data) if !data.is_empty() => decode_protocol(log_code, data, vendor_id),
        _ => {
            let summary = format!("0x{:04X} ({})", log_code, log_name);
            (None, summary, false)
        }
    };

    let protocol = categorize_protocol(log_code);
    let raw_size = frame.payload.len();
    let hex_prev = hex_preview(&frame.payload, 64);

    let vendor_name = match vendor_id {
        1 => "MediaTek",
        2 => "Samsung",
        _ => "",
    };

    DecodedPacket {
        agent_id: String::new(),
        sequence: frame.sequence,
        timestamp: frame.timestamp_wall,
        log_code,
        log_name,
        protocol,
        rat,
        layer,
        decoded,
        summary,
        fully_decoded,
        raw_size,
        hex_preview: hex_prev,
        vendor: vendor_name.to_string(),
        raw_payload: frame.payload.clone(),
    }
}

/// Extract protocol payload from DiagFrame
///
/// For Qualcomm (vendor=0):
///   DiagFrame.payload = [log_code_le(2)] + [diag_packet]
///   For log packets (cmd 0x10): diag_packet = [cmd, more, len(2), len(2), code(2), ts(8), protocol_data...]
///
/// For MediaTek/Samsung (vendor=1,2):
///   Payload is passed through directly (vendor-specific headers handled by their decoders)
fn extract_protocol_data(payload: &[u8], vendor: u8) -> Option<&[u8]> {
    // Non-Qualcomm vendors: pass payload directly to vendor decoder
    // (after stripping the 2-byte log_code prefix that the agent always adds)
    if vendor != 0 {
        if payload.len() > LOG_CODE_PREFIX {
            return Some(&payload[LOG_CODE_PREFIX..]);
        }
        return if payload.is_empty() { None } else { Some(payload) };
    }

    // Qualcomm DIAG format
    if payload.len() < LOG_CODE_PREFIX + 1 {
        return None;
    }

    let diag_packet = &payload[LOG_CODE_PREFIX..];

    if diag_packet[0] == DIAG_LOG_F && diag_packet.len() > DIAG_LOG_HEADER_SIZE {
        // Log packet: skip the 16-byte DIAG log header
        Some(&diag_packet[DIAG_LOG_HEADER_SIZE..])
    } else {
        // Non-log response: pass the whole thing (skip cmd byte)
        if diag_packet.len() > 1 {
            Some(&diag_packet[1..])
        } else {
            None
        }
    }
}
