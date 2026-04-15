//! Samsung Shannon (Exynos modem) IPC protocol decoders
//!
//! Samsung Exynos-based modems use the Shannon baseband processor
//! with a proprietary IPC (Inter-Processor Communication) protocol
//! via /dev/umts_dm0.
//!
//! Log code ranges (synthetic, assigned by 5grok):
//! - 0x2001..=0x20FF: NAS (EMM/5GMM/ESM/5GSM)
//! - 0x2100..=0x21FF: RRC (LTE/NR)
//! - 0x2200..=0x22FF: ML1/PHY measurements
//! - 0x2300..=0x23FF: MAC/PDCP/RLC

use serde_json::{json, Value};

// ============================================================================
// Samsung IPC Log Header
// ============================================================================

/// Samsung IPC header size
const SAMSUNG_IPC_HEADER_SIZE: usize = 16;

/// Samsung IPC log header magic
const SAMSUNG_IPC_MAGIC: u32 = 0x4D495043; // "MIPC" in ASCII

/// Parse Samsung IPC log header
/// Returns (cmd, payload_length, timestamp)
fn parse_samsung_header(data: &[u8]) -> Option<(u16, u16, u64)> {
    if data.len() < SAMSUNG_IPC_HEADER_SIZE {
        return None;
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != SAMSUNG_IPC_MAGIC {
        // Try without magic check — some Samsung log records skip magic
        // and start directly with cmd
    }

    let cmd = u16::from_le_bytes([data[4], data[5]]);
    let length = u16::from_le_bytes([data[6], data[7]]);
    let timestamp = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    Some((cmd, length, timestamp))
}

/// Extract PDU from Samsung envelope
fn strip_samsung_envelope(data: &[u8]) -> Option<(&[u8], &'static str)> {
    // Try structured header first
    if data.len() >= SAMSUNG_IPC_HEADER_SIZE {
        if let Some((_cmd, length, _ts)) = parse_samsung_header(data) {
            let payload_start = SAMSUNG_IPC_HEADER_SIZE;
            let payload_end = payload_start + length as usize;
            let pdu = if data.len() >= payload_end {
                &data[payload_start..payload_end]
            } else {
                &data[payload_start..]
            };
            // Samsung doesn't always include direction in the header;
            // we infer from log code
            return Some((pdu, "??"));
        }
    }

    // Fallback: try to parse as raw PDU (no header)
    if !data.is_empty() {
        Some((data, "??"))
    } else {
        None
    }
}

// ============================================================================
// Samsung NAS Message Name Lookup
// ============================================================================

fn samsung_nas_message_name(log_code: u16) -> (&'static str, &'static str) {
    // Returns (protocol, message_name)
    match log_code {
        // LTE EMM
        0x2001 => ("LTE-EMM", "Attach Request"),
        0x2002 => ("LTE-EMM", "Attach Accept"),
        0x2003 => ("LTE-EMM", "Attach Complete"),
        0x2004 => ("LTE-EMM", "Attach Reject"),
        0x2005 => ("LTE-EMM", "Detach Request"),
        0x2006 => ("LTE-EMM", "Detach Accept"),
        0x2007 => ("LTE-EMM", "TAU Request"),
        0x2008 => ("LTE-EMM", "TAU Accept"),
        0x2009 => ("LTE-EMM", "TAU Reject"),
        0x2010 => ("LTE-EMM", "Auth Request"),
        0x2011 => ("LTE-EMM", "Auth Response"),
        0x2012 => ("LTE-EMM", "Auth Reject"),
        0x2020 => ("LTE-EMM", "Security Mode Command"),
        0x2021 => ("LTE-EMM", "Security Mode Complete"),
        0x2022 => ("LTE-EMM", "Security Mode Reject"),
        0x2030 => ("LTE-EMM", "Identity Request"),
        0x2031 => ("LTE-EMM", "Identity Response"),
        0x2040 => ("LTE-EMM", "Service Request"),
        0x2041 => ("LTE-EMM", "Service Accept"),
        0x2042 => ("LTE-EMM", "Service Reject"),
        // LTE ESM
        0x2050 => ("LTE-ESM", "PDN Connect Request"),
        0x2051 => ("LTE-ESM", "PDN Connect Reject"),
        0x2052 => ("LTE-ESM", "Act Default Bearer Request"),
        0x2053 => ("LTE-ESM", "Act Default Bearer Accept"),
        0x2054 => ("LTE-ESM", "Act Dedicated Bearer Request"),
        0x2055 => ("LTE-ESM", "Act Dedicated Bearer Accept"),
        0x2056 => ("LTE-ESM", "Deact Bearer Request"),
        0x2057 => ("LTE-ESM", "Deact Bearer Accept"),
        // 5GMM
        0x2060 => ("5GMM", "Registration Request"),
        0x2061 => ("5GMM", "Registration Accept"),
        0x2062 => ("5GMM", "Registration Complete"),
        0x2063 => ("5GMM", "Registration Reject"),
        0x2064 => ("5GMM", "Deregistration Request UE"),
        0x2065 => ("5GMM", "Deregistration Accept UE"),
        0x2070 => ("5GMM", "Auth Request"),
        0x2071 => ("5GMM", "Auth Response"),
        0x2072 => ("5GMM", "Auth Reject"),
        0x2080 => ("5GMM", "Security Mode Command"),
        0x2081 => ("5GMM", "Security Mode Complete"),
        0x2082 => ("5GMM", "Security Mode Reject"),
        0x2090 => ("5GMM", "Identity Request"),
        0x2091 => ("5GMM", "Identity Response"),
        0x20A0 => ("5GMM", "Service Request"),
        0x20A1 => ("5GMM", "Service Accept"),
        // 5GSM
        0x20B0 => ("5GSM", "PDU Session Est Request"),
        0x20B1 => ("5GSM", "PDU Session Est Accept"),
        0x20B2 => ("5GSM", "PDU Session Est Reject"),
        0x20C0 => ("5GSM", "PDU Session Release Cmd"),
        0x20C1 => ("5GSM", "PDU Session Release Complete"),
        _ => ("NAS", "Unknown"),
    }
}

fn samsung_rrc_message_name(log_code: u16) -> (&'static str, &'static str) {
    match log_code {
        // LTE RRC
        0x2101 => ("LTE-RRC", "Connection Request"),
        0x2102 => ("LTE-RRC", "Connection Setup"),
        0x2103 => ("LTE-RRC", "Connection Setup Complete"),
        0x2104 => ("LTE-RRC", "Connection Reject"),
        0x2105 => ("LTE-RRC", "Connection Release"),
        0x2110 => ("LTE-RRC", "Connection Reconfig"),
        0x2111 => ("LTE-RRC", "Connection Reconfig Complete"),
        0x2120 => ("LTE-RRC", "Security Mode Command"),
        0x2121 => ("LTE-RRC", "Security Mode Complete"),
        0x2122 => ("LTE-RRC", "Security Mode Failure"),
        0x2130 => ("LTE-RRC", "MIB"),
        0x2131 => ("LTE-RRC", "SIB1"),
        0x2132 => ("LTE-RRC", "SIB2"),
        0x2140 => ("LTE-RRC", "Measurement Report"),
        0x2141 => ("LTE-RRC", "Measurement Config"),
        // NR RRC
        0x2150 => ("NR-RRC", "RRC Setup Request"),
        0x2151 => ("NR-RRC", "RRC Setup"),
        0x2152 => ("NR-RRC", "RRC Setup Complete"),
        0x2153 => ("NR-RRC", "RRC Reject"),
        0x2154 => ("NR-RRC", "RRC Release"),
        0x2160 => ("NR-RRC", "RRC Reconfiguration"),
        0x2161 => ("NR-RRC", "RRC Reconfig Complete"),
        0x2170 => ("NR-RRC", "NR Security Mode Command"),
        0x2171 => ("NR-RRC", "NR Security Mode Complete"),
        0x2172 => ("NR-RRC", "NR Security Mode Failure"),
        0x2180 => ("NR-RRC", "NR MIB"),
        0x2181 => ("NR-RRC", "NR SIB1"),
        0x2190 => ("NR-RRC", "NR Measurement Report"),
        _ => ("RRC", "Unknown"),
    }
}

fn samsung_ml1_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x2201 => "LTE Serving Cell Meas",
        0x2202 => "LTE Neighbor Cell Meas",
        0x2203 => "LTE Connected Meas",
        0x2210 => "NR Serving Cell Meas",
        0x2211 => "NR Neighbor Cell Meas",
        0x2212 => "NR Beam Meas",
        0x2220 => "Cell Selection Info",
        0x2221 => "Handover Info",
        _ => "ML1 Unknown",
    }
}

// ============================================================================
// Public Decoders
// ============================================================================

/// Decode a Samsung Shannon log packet (top-level dispatcher)
pub fn decode_samsung(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    match log_code {
        0x2001..=0x20FF => decode_samsung_nas(log_code, data),
        0x2100..=0x21FF => decode_samsung_rrc(log_code, data),
        0x2200..=0x22FF => decode_samsung_ml1(log_code, data),
        _ => {
            let preview = if data.len() <= 16 {
                hex::encode(data)
            } else {
                format!("{}...", hex::encode(&data[..16]))
            };
            let summary = format!(
                "Samsung 0x{:04X} {} bytes [{}]",
                log_code,
                data.len(),
                preview
            );
            (None, summary, false)
        }
    }
}

/// Decode Samsung NAS message
fn decode_samsung_nas(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let (protocol, msg_name) = samsung_nas_message_name(log_code);

    let pdu = match strip_samsung_envelope(data) {
        Some((pdu, _)) => Some(pdu),
        None => None,
    };

    let summary = format!("Samsung {} {}", protocol, msg_name);

    let mut result = json!({
        "vendor": "Samsung",
        "protocol": protocol,
        "message_name": msg_name,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));

        // Try inner NAS decode
        if !pdu.is_empty() {
            let epd = pdu[0];
            let inner_decoded = match epd {
                0x7E | 0x2E => {
                    let (d, _, _) = super::nas_5g::decode_5g_nas_plain(pdu);
                    d
                }
                0x07 | 0x02 => {
                    let (d, _, _) = super::nas_lte::decode_lte_nas_ota(0xB0EA, pdu);
                    d
                }
                _ => None,
            };

            if let Some(nas) = inner_decoded {
                if let Some(obj) = nas.as_object() {
                    for (k, v) in obj {
                        result[k] = v.clone();
                    }
                }
            }
        }

        // Security-relevant flags
        match log_code {
            0x2020 | 0x2021 | 0x2022 | 0x2080 | 0x2081 | 0x2082 => {
                result["security_relevant"] = json!(true);
            }
            0x2030 | 0x2031 | 0x2090 | 0x2091 => {
                result["identity_relevant"] = json!(true);
            }
            _ => {}
        }
    }

    (Some(result), summary, true)
}

/// Decode Samsung RRC message
fn decode_samsung_rrc(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let (protocol, msg_name) = samsung_rrc_message_name(log_code);

    let pdu = match strip_samsung_envelope(data) {
        Some((pdu, _)) => Some(pdu),
        None => None,
    };

    let summary = format!("Samsung {} {}", protocol, msg_name);

    let mut result = json!({
        "vendor": "Samsung",
        "protocol": protocol,
        "message_name": msg_name,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));

        // Security-relevant messages
        match log_code {
            0x2120 | 0x2121 | 0x2122 | 0x2170 | 0x2171 | 0x2172 => {
                result["security_relevant"] = json!(true);
            }
            _ => {}
        }
    }

    (Some(result), summary, true)
}

/// Decode Samsung ML1/PHY measurement
fn decode_samsung_ml1(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = samsung_ml1_message_name(log_code);

    let pdu = match strip_samsung_envelope(data) {
        Some((pdu, _)) => Some(pdu),
        None => None,
    };

    let summary = format!("Samsung ML1 {}", msg_name);

    let mut result = json!({
        "vendor": "Samsung",
        "protocol": "ML1",
        "message_name": msg_name,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));

        // Try to extract PCI/RSRP from Samsung ML1 serving cell
        if (log_code == 0x2201 || log_code == 0x2210) && pdu.len() >= 6 {
            let pci = u16::from_le_bytes([pdu[0], pdu[1]]);
            let rsrp_raw = i16::from_le_bytes([pdu[2], pdu[3]]);
            result["pci"] = json!(pci);
            result["rsrp"] = json!(rsrp_raw);
        }
    }

    (Some(result), summary, true)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_samsung_frame(pdu: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Magic
        data.extend_from_slice(&SAMSUNG_IPC_MAGIC.to_le_bytes());
        // cmd (unused in our dispatch)
        data.extend_from_slice(&0u16.to_le_bytes());
        // length
        data.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        // timestamp
        data.extend_from_slice(&0u64.to_le_bytes());
        // PDU
        data.extend_from_slice(pdu);
        data
    }

    #[test]
    fn test_samsung_header_parse() {
        let frame = make_samsung_frame(&[0x07, 0x41]);
        let (cmd, length, _ts) = parse_samsung_header(&frame).unwrap();
        assert_eq!(cmd, 0);
        assert_eq!(length, 2);
    }

    #[test]
    fn test_samsung_nas_emm() {
        let frame = make_samsung_frame(&[0x07, 0x41]);
        let (decoded, summary, fully) = decode_samsung_nas(0x2001, &frame);
        assert!(decoded.is_some());
        assert!(summary.contains("Attach Request"));
        assert!(fully);
        assert_eq!(decoded.unwrap()["vendor"], "Samsung");
    }

    #[test]
    fn test_samsung_nas_5gmm() {
        let frame = make_samsung_frame(&[0x7E, 0x00, 0x41]);
        let (decoded, summary, _) = decode_samsung_nas(0x2060, &frame);
        assert!(decoded.is_some());
        assert!(summary.contains("Registration Request"));
    }

    #[test]
    fn test_samsung_rrc() {
        let frame = make_samsung_frame(&[0x10, 0x20, 0x30]);
        let (decoded, summary, fully) = decode_samsung_rrc(0x2101, &frame);
        assert!(decoded.is_some());
        assert!(summary.contains("Connection Request"));
        assert!(fully);
    }

    #[test]
    fn test_samsung_security_relevant() {
        let frame = make_samsung_frame(&[0x07, 0x5D]);
        let (decoded, _, _) = decode_samsung_nas(0x2020, &frame);
        let d = decoded.unwrap();
        assert!(d["security_relevant"].as_bool().unwrap());
    }

    #[test]
    fn test_samsung_ml1_serving() {
        // PCI=123 (0x007B), RSRP=-85 (0xFFAB)
        let mut pdu = vec![0x7B, 0x00]; // PCI
        pdu.extend_from_slice(&(-85i16).to_le_bytes()); // RSRP
        pdu.extend_from_slice(&[0x00, 0x00]); // padding
        let frame = make_samsung_frame(&pdu);
        let (decoded, _, _) = decode_samsung_ml1(0x2201, &frame);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 123);
        assert_eq!(d["rsrp"], -85);
    }

    #[test]
    fn test_samsung_dispatch() {
        let frame = make_samsung_frame(&[0x07, 0x41]);
        let (decoded, _, _) = decode_samsung(0x2001, &frame);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap()["vendor"], "Samsung");
    }

    #[test]
    fn test_samsung_dispatch_rrc() {
        let frame = make_samsung_frame(&[0x10, 0x20]);
        let (decoded, _, _) = decode_samsung(0x2150, &frame);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap()["protocol"], "NR-RRC");
    }

    #[test]
    fn test_samsung_dispatch_unknown() {
        let (decoded, summary, fully) = decode_samsung(0x2FFF, &[0x01, 0x02]);
        assert!(decoded.is_none());
        assert!(summary.contains("Samsung 0x2FFF"));
        assert!(!fully);
    }
}
