//! MediaTek (Dimensity/Helio) CCCI protocol decoders
//!
//! MediaTek modems wrap standard 3GPP NAS/RRC PDUs with a vendor-specific
//! CCCI (Cross Core Communication Interface) header. After stripping the
//! MTK envelope, the inner bytes are standard 3GPP format that can be fed
//! to our existing NAS/RRC decoders.
//!
//! Log code ranges:
//! - 0x0C01..=0x0C90: LTE RRC
//! - 0x0D00..=0x0D5F: LTE EMM (NAS)
//! - 0x0E01..=0x0E61: LTE ESM (NAS)
//! - 0x1C01..=0x1C80: NR RRC
//! - 0x1D01..=0x1D81: 5GMM NAS
//! - 0x1E01..=0x1E40: 5GSM NAS

use serde_json::{json, Value};

// ============================================================================
// MTK Log Record Header
// ============================================================================

/// MediaTek log record header size (9 bytes)
const MTK_LOG_HEADER_SIZE: usize = 9;

/// Parse MTK log record header
/// Returns (log_code, timestamp_ticks, payload_length, direction)
fn parse_mtk_header(data: &[u8]) -> Option<(u16, u32, u16, u8)> {
    if data.len() < MTK_LOG_HEADER_SIZE {
        return None;
    }
    let log_code = u16::from_le_bytes([data[0], data[1]]);
    let timestamp = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let length = u16::from_le_bytes([data[6], data[7]]);
    let direction = data[8];
    Some((log_code, timestamp, length, direction))
}

/// Extract NAS/RRC PDU from MTK envelope
/// Returns the inner 3GPP PDU bytes and direction string
fn strip_mtk_envelope(data: &[u8]) -> Option<(&[u8], &'static str)> {
    let (_code, _ts, length, direction) = parse_mtk_header(data)?;
    let dir = if direction == 0 { "DL" } else { "UL" };
    let payload_start = MTK_LOG_HEADER_SIZE;
    let payload_end = payload_start + length as usize;

    let pdu = if data.len() >= payload_end {
        &data[payload_start..payload_end]
    } else if data.len() > payload_start {
        &data[payload_start..]
    } else {
        return None;
    };

    Some((pdu, dir))
}

// ============================================================================
// MTK NAS Message Name Lookup
// ============================================================================

fn mtk_emm_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x0D01 => "Attach Request",
        0x0D02 => "Attach Accept",
        0x0D03 => "Attach Complete",
        0x0D04 => "Attach Reject",
        0x0D05 => "Detach Request",
        0x0D06 => "Detach Accept",
        0x0D07 => "TAU Request",
        0x0D08 => "TAU Accept",
        0x0D09 => "TAU Complete",
        0x0D0A => "TAU Reject",
        0x0D10 => "Auth Request",
        0x0D11 => "Auth Response",
        0x0D12 => "Auth Reject",
        0x0D13 => "Auth Failure",
        0x0D20 => "Security Mode Command",
        0x0D21 => "Security Mode Complete",
        0x0D22 => "Security Mode Reject",
        0x0D30 => "Identity Request",
        0x0D31 => "Identity Response",
        0x0D40 => "Service Request",
        0x0D41 => "Service Accept",
        0x0D42 => "Service Reject",
        0x0D50 => "EMM State Change",
        0x0D51 => "EMM Substate Change",
        _ => "EMM Unknown",
    }
}

fn mtk_esm_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x0E01 => "PDN Connect Request",
        0x0E02 => "PDN Connect Reject",
        0x0E03 => "PDN Disconnect Request",
        0x0E04 => "PDN Disconnect Reject",
        0x0E10 => "Bearer Resource Alloc Req",
        0x0E11 => "Bearer Resource Alloc Rej",
        0x0E20 => "Act Default Bearer Req",
        0x0E21 => "Act Default Bearer Accept",
        0x0E22 => "Act Default Bearer Reject",
        0x0E30 => "Act Dedicated Bearer Req",
        0x0E31 => "Act Dedicated Bearer Accept",
        0x0E32 => "Act Dedicated Bearer Reject",
        0x0E40 => "Modify Bearer Request",
        0x0E41 => "Modify Bearer Accept",
        0x0E42 => "Modify Bearer Reject",
        0x0E50 => "Deact Bearer Request",
        0x0E51 => "Deact Bearer Accept",
        0x0E60 => "Bearer State Change",
        _ => "ESM Unknown",
    }
}

fn mtk_5gmm_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x1D01 => "Registration Request",
        0x1D02 => "Registration Accept",
        0x1D03 => "Registration Complete",
        0x1D04 => "Registration Reject",
        0x1D10 => "Deregistration Request UE",
        0x1D11 => "Deregistration Accept UE",
        0x1D12 => "Deregistration Request NW",
        0x1D13 => "Deregistration Accept NW",
        0x1D20 => "Auth Request",
        0x1D21 => "Auth Response",
        0x1D22 => "Auth Reject",
        0x1D23 => "Auth Failure",
        0x1D24 => "Auth Result",
        0x1D30 => "Security Mode Command",
        0x1D31 => "Security Mode Complete",
        0x1D32 => "Security Mode Reject",
        0x1D40 => "Identity Request",
        0x1D41 => "Identity Response",
        0x1D50 => "Service Request",
        0x1D51 => "Service Accept",
        0x1D52 => "Service Reject",
        0x1D60 => "Config Update Command",
        0x1D61 => "Config Update Complete",
        0x1D70 => "Notification",
        0x1D71 => "Notification Response",
        0x1D72 => "DL NAS Transport",
        0x1D73 => "UL NAS Transport",
        0x1D80 => "5GMM State Change",
        0x1D81 => "5GMM Substate Change",
        _ => "5GMM Unknown",
    }
}

fn mtk_5gsm_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x1E01 => "PDU Session Est Request",
        0x1E02 => "PDU Session Est Accept",
        0x1E03 => "PDU Session Est Reject",
        0x1E10 => "PDU Session Mod Request",
        0x1E11 => "PDU Session Mod Accept",
        0x1E12 => "PDU Session Mod Reject",
        0x1E13 => "PDU Session Mod Command",
        0x1E14 => "PDU Session Mod Complete",
        0x1E20 => "PDU Session Release Req",
        0x1E21 => "PDU Session Release Rej",
        0x1E22 => "PDU Session Release Cmd",
        0x1E23 => "PDU Session Release Complete",
        0x1E30 => "5GSM Status",
        0x1E40 => "5GSM State Change",
        _ => "5GSM Unknown",
    }
}

fn mtk_lte_rrc_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x0C01 => "Connection Request",
        0x0C02 => "Connection Setup",
        0x0C03 => "Connection Setup Complete",
        0x0C04 => "Connection Reject",
        0x0C05 => "Connection Release",
        0x0C10 => "Connection Reconfig",
        0x0C11 => "Connection Reconfig Complete",
        0x0C20 => "Connection Reest Request",
        0x0C21 => "Connection Reest",
        0x0C22 => "Connection Reest Complete",
        0x0C23 => "Connection Reest Reject",
        0x0C30 => "MIB",
        0x0C31 => "SIB1",
        0x0C32 => "SIB2",
        0x0C33 => "SIB3",
        0x0C34 => "SIB4",
        0x0C35 => "SIB5",
        0x0C40 => "Measurement Report",
        0x0C41 => "Measurement Config",
        0x0C50 => "Security Mode Command",
        0x0C51 => "Security Mode Complete",
        0x0C52 => "Security Mode Failure",
        0x0C60 => "UL Info Transfer",
        0x0C61 => "DL Info Transfer",
        0x0C70 => "Mobility From EUTRA Cmd",
        0x0C80 => "Paging",
        0x0C90 => "RRC State Change",
        _ => "LTE RRC Unknown",
    }
}

fn mtk_nr_rrc_message_name(log_code: u16) -> &'static str {
    match log_code {
        0x1C01 => "RRC Setup Request",
        0x1C02 => "RRC Setup",
        0x1C03 => "RRC Setup Complete",
        0x1C04 => "RRC Reject",
        0x1C05 => "RRC Release",
        0x1C10 => "RRC Reconfiguration",
        0x1C11 => "RRC Reconfig Complete",
        0x1C20 => "RRC Reest Request",
        0x1C21 => "RRC Reest",
        0x1C22 => "RRC Reest Complete",
        0x1C30 => "NR MIB",
        0x1C31 => "NR SIB1",
        0x1C32 => "NR SIB2",
        0x1C33 => "NR SIB3",
        0x1C40 => "NR Measurement Report",
        0x1C50 => "NR Security Mode Command",
        0x1C51 => "NR Security Mode Complete",
        0x1C52 => "NR Security Mode Failure",
        0x1C60 => "NR UL Info Transfer",
        0x1C61 => "NR DL Info Transfer",
        0x1C70 => "NR Paging",
        0x1C80 => "NR RRC State Change",
        _ => "NR RRC Unknown",
    }
}

// ============================================================================
// Public Decoders
// ============================================================================

/// Decode a MediaTek log packet (top-level dispatcher)
pub fn decode_mediatek(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    match log_code {
        // LTE EMM NAS
        0x0D00..=0x0D5F => decode_mtk_emm(log_code, data),
        // LTE ESM NAS
        0x0E01..=0x0E61 => decode_mtk_esm(log_code, data),
        // 5GMM NAS
        0x1D01..=0x1D81 => decode_mtk_5gmm(log_code, data),
        // 5GSM NAS
        0x1E01..=0x1E40 => decode_mtk_5gsm(log_code, data),
        // LTE RRC
        0x0C01..=0x0C90 => decode_mtk_lte_rrc(log_code, data),
        // NR RRC
        0x1C01..=0x1C80 => decode_mtk_nr_rrc(log_code, data),
        // Fallback
        _ => {
            let preview = if data.len() <= 16 {
                hex::encode(data)
            } else {
                format!("{}...", hex::encode(&data[..16]))
            };
            let summary = format!("MTK 0x{:04X} {} bytes [{}]", log_code, data.len(), preview);
            (None, summary, false)
        }
    }
}

/// Decode MTK EMM NAS message
fn decode_mtk_emm(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_emm_message_name(log_code);

    let (pdu, direction, decoded) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => {
            // Try to feed the inner PDU to existing LTE NAS decoders
            let nas_decoded = try_decode_lte_nas_pdu(pdu);
            (Some(pdu), dir, nas_decoded)
        }
        None => (None, "??", None),
    };

    let summary = format!("MTK EMM {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "LTE-EMM",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));
    }

    // Merge inner NAS decode if available
    let fully_decoded = decoded.is_some();
    if let Some(nas) = decoded {
        if let Some(obj) = nas.as_object() {
            for (k, v) in obj {
                result[k] = v.clone();
            }
        }
    }

    (Some(result), summary, fully_decoded)
}

/// Decode MTK ESM NAS message
fn decode_mtk_esm(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_esm_message_name(log_code);

    let (pdu, direction, decoded) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => {
            let nas_decoded = try_decode_lte_nas_pdu(pdu);
            (Some(pdu), dir, nas_decoded)
        }
        None => (None, "??", None),
    };

    let summary = format!("MTK ESM {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "LTE-ESM",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));
    }

    let fully_decoded = decoded.is_some();
    if let Some(nas) = decoded {
        if let Some(obj) = nas.as_object() {
            for (k, v) in obj {
                result[k] = v.clone();
            }
        }
    }

    (Some(result), summary, fully_decoded)
}

/// Decode MTK 5GMM NAS message
fn decode_mtk_5gmm(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_5gmm_message_name(log_code);

    let (pdu, direction, decoded) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => {
            let nas_decoded = try_decode_5g_nas_pdu(pdu);
            (Some(pdu), dir, nas_decoded)
        }
        None => (None, "??", None),
    };

    let summary = format!("MTK 5GMM {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "5GMM",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));
    }

    let fully_decoded = decoded.is_some();
    if let Some(nas) = decoded {
        if let Some(obj) = nas.as_object() {
            for (k, v) in obj {
                result[k] = v.clone();
            }
        }
    }

    (Some(result), summary, fully_decoded)
}

/// Decode MTK 5GSM NAS message
fn decode_mtk_5gsm(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_5gsm_message_name(log_code);

    let (pdu, direction, decoded) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => {
            let nas_decoded = try_decode_5g_nas_pdu(pdu);
            (Some(pdu), dir, nas_decoded)
        }
        None => (None, "??", None),
    };

    let summary = format!("MTK 5GSM {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "5GSM",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));
    }

    let fully_decoded = decoded.is_some();
    if let Some(nas) = decoded {
        if let Some(obj) = nas.as_object() {
            for (k, v) in obj {
                result[k] = v.clone();
            }
        }
    }

    (Some(result), summary, fully_decoded)
}

/// Decode MTK LTE RRC message
fn decode_mtk_lte_rrc(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_lte_rrc_message_name(log_code);

    let (pdu, direction) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => (Some(pdu), dir),
        None => (None, "??"),
    };

    let summary = format!("MTK LTE RRC {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "LTE-RRC",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));

        // For security-relevant messages, extract key fields
        if log_code == 0x0C50 || log_code == 0x0C51 || log_code == 0x0C52 {
            result["security_relevant"] = json!(true);
        }
    }

    (Some(result), summary, true)
}

/// Decode MTK NR RRC message
fn decode_mtk_nr_rrc(log_code: u16, data: &[u8]) -> (Option<Value>, String, bool) {
    let msg_name = mtk_nr_rrc_message_name(log_code);

    let (pdu, direction) = match strip_mtk_envelope(data) {
        Some((pdu, dir)) => (Some(pdu), dir),
        None => (None, "??"),
    };

    let summary = format!("MTK NR RRC {} [{}]", msg_name, direction);

    let mut result = json!({
        "vendor": "MediaTek",
        "protocol": "NR-RRC",
        "message_name": msg_name,
        "direction": direction,
        "log_code": format!("0x{:04X}", log_code),
    });

    if let Some(pdu) = pdu {
        result["pdu_length"] = json!(pdu.len());
        result["pdu_hex"] = json!(hex::encode(&pdu[..pdu.len().min(64)]));

        if log_code == 0x1C50 || log_code == 0x1C51 || log_code == 0x1C52 {
            result["security_relevant"] = json!(true);
        }
    }

    (Some(result), summary, true)
}

// ============================================================================
// NAS PDU Reuse Helpers
// ============================================================================

/// Try to decode a raw LTE NAS PDU using the existing decoders
fn try_decode_lte_nas_pdu(pdu: &[u8]) -> Option<Value> {
    if pdu.is_empty() {
        return None;
    }

    // LTE NAS: first byte is security header type / protocol discriminator
    let epd = pdu[0] & 0x0F;
    match epd {
        // EPS Mobility Management (EMM)
        0x07 => {
            let (decoded, _, _) = super::nas_lte::decode_lte_nas_ota(0xB0EA, pdu);
            decoded
        }
        // EPS Session Management (ESM)
        0x02 => {
            let (decoded, _, _) = super::nas_lte::decode_lte_nas_ota(0xB0EB, pdu);
            decoded
        }
        _ => None,
    }
}

/// Try to decode a raw 5G NAS PDU using the existing decoders
fn try_decode_5g_nas_pdu(pdu: &[u8]) -> Option<Value> {
    if pdu.is_empty() {
        return None;
    }

    let epd = pdu[0];
    match epd {
        // 5GS Mobility Management (5GMM)
        0x7E => {
            let (decoded, _, _) = super::nas_5g::decode_5g_nas_plain(pdu);
            decoded
        }
        // 5GS Session Management (5GSM)
        0x2E => {
            let (decoded, _, _) = super::nas_5g::decode_5g_nas_plain(pdu);
            decoded
        }
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mtk_frame(log_code: u16, direction: u8, pdu: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&log_code.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        data.extend_from_slice(&(pdu.len() as u16).to_le_bytes());
        data.push(direction);
        data.extend_from_slice(pdu);
        data
    }

    #[test]
    fn test_mtk_header_parse() {
        let data = make_mtk_frame(0x0D01, 1, &[0x07, 0x41]);
        let (code, _ts, length, dir) = parse_mtk_header(&data).unwrap();
        assert_eq!(code, 0x0D01);
        assert_eq!(length, 2);
        assert_eq!(dir, 1); // UL
    }

    #[test]
    fn test_mtk_emm_attach() {
        let pdu = vec![0x07, 0x41, 0x01, 0x02, 0x03]; // EPD=EMM, msg_type=Attach Request
        let data = make_mtk_frame(0x0D01, 1, &pdu);
        let (decoded, summary, fully) = decode_mtk_emm(0x0D01, &data);
        assert!(decoded.is_some());
        assert!(summary.contains("Attach Request"));
        assert!(summary.contains("UL"));
        let d = decoded.unwrap();
        assert_eq!(d["vendor"], "MediaTek");
        assert_eq!(d["protocol"], "LTE-EMM");
        // fully_decoded depends on whether inner NAS parser succeeded
        let _ = fully;
    }

    #[test]
    fn test_mtk_5gmm_registration() {
        let pdu = vec![0x7E, 0x00, 0x41, 0x01]; // EPD=5GMM, security=plain, type=Registration
        let data = make_mtk_frame(0x1D01, 0, &pdu);
        let (decoded, summary, _) = decode_mtk_5gmm(0x1D01, &data);
        assert!(decoded.is_some());
        assert!(summary.contains("Registration Request"));
        assert!(summary.contains("DL"));
        let d = decoded.unwrap();
        assert_eq!(d["vendor"], "MediaTek");
        assert_eq!(d["protocol"], "5GMM");
    }

    #[test]
    fn test_mtk_5gsm_pdu_session() {
        let pdu = vec![0x2E, 0x01, 0xC1, 0x00]; // EPD=5GSM
        let data = make_mtk_frame(0x1E01, 1, &pdu);
        let (decoded, summary, _) = decode_mtk_5gsm(0x1E01, &data);
        assert!(decoded.is_some());
        assert!(summary.contains("PDU Session Est Request"));
        assert_eq!(decoded.unwrap()["vendor"], "MediaTek");
    }

    #[test]
    fn test_mtk_lte_rrc() {
        let pdu = vec![0x10, 0x20, 0x30]; // RRC PDU
        let data = make_mtk_frame(0x0C01, 1, &pdu);
        let (decoded, summary, fully) = decode_mtk_lte_rrc(0x0C01, &data);
        assert!(decoded.is_some());
        assert!(summary.contains("Connection Request"));
        assert!(fully);
        assert_eq!(decoded.unwrap()["vendor"], "MediaTek");
    }

    #[test]
    fn test_mtk_nr_rrc() {
        let pdu = vec![0x10, 0x20, 0x30];
        let data = make_mtk_frame(0x1C10, 0, &pdu);
        let (decoded, summary, fully) = decode_mtk_nr_rrc(0x1C10, &data);
        assert!(decoded.is_some());
        assert!(summary.contains("RRC Reconfiguration"));
        assert!(fully);
    }

    #[test]
    fn test_mtk_security_mode() {
        let pdu = vec![0x10, 0x20];
        let data = make_mtk_frame(0x0C50, 0, &pdu);
        let (decoded, _, _) = decode_mtk_lte_rrc(0x0C50, &data);
        assert!(decoded.as_ref().unwrap()["security_relevant"].as_bool().unwrap());
    }

    #[test]
    fn test_mtk_nr_security_mode() {
        let pdu = vec![0x10, 0x20];
        let data = make_mtk_frame(0x1C50, 0, &pdu);
        let (decoded, _, _) = decode_mtk_nr_rrc(0x1C50, &data);
        assert!(decoded.as_ref().unwrap()["security_relevant"].as_bool().unwrap());
    }

    #[test]
    fn test_mtk_truncated_header() {
        let data = vec![0x01, 0x0D]; // Too short for MTK header
        let (decoded, summary, fully) = decode_mtk_emm(0x0D01, &data);
        assert!(decoded.is_some()); // Still produces metadata
        assert!(!fully || summary.contains("??"));
    }

    #[test]
    fn test_mtk_dispatch() {
        let pdu = vec![0x07, 0x41];
        let data = make_mtk_frame(0x0D01, 1, &pdu);
        let (decoded, _, _) = decode_mediatek(0x0D01, &data);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap()["protocol"], "LTE-EMM");
    }

    #[test]
    fn test_mtk_dispatch_nr_rrc() {
        let pdu = vec![0x10, 0x20];
        let data = make_mtk_frame(0x1C01, 1, &pdu);
        let (decoded, _, _) = decode_mediatek(0x1C01, &data);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap()["protocol"], "NR-RRC");
    }
}
