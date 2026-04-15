//! LTE NAS decoder: EMM (EPS Mobility Management) and ESM (EPS Session Management)

use serde_json;

// ---------------------------------------------------------------------------
// OTA entry points
// ---------------------------------------------------------------------------

/// Decode LTE NAS OTA log (log codes 0xB0EA, 0xB0EB, 0xB0EC).
///
/// Parses the OTA header to extract version, direction, and PDU offset, then
/// delegates to [`decode_lte_nas_inner`].
pub fn decode_lte_nas_ota(
    log_code: u16,
    data: &[u8],
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (
            None,
            format!("LTE NAS OTA: too short ({} bytes)", data.len()),
            false,
        );
    }

    let version = data[0];
    let direction = if data[3] & 0x10 != 0 { "UL" } else { "DL" };

    let pdu_offset: usize = match version {
        0..=3 => 6,
        _ => 4,
    };

    if data.len() <= pdu_offset {
        let code_name = match log_code {
            0xB0EA => "LTE_NAS_Plain",
            0xB0EB => "LTE_NAS_ESM",
            0xB0EC => "LTE_NAS_Security",
            _ => "LTE_NAS",
        };
        return (
            None,
            format!("{} {} (header only)", code_name, direction),
            false,
        );
    }

    let pdu = &data[pdu_offset..];
    decode_lte_nas_inner(pdu, direction)
}

/// Dispatch on Protocol Discriminator: 0x07 = EMM, 0x02 = ESM.
pub fn decode_lte_nas_inner(
    pdu: &[u8],
    direction: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if pdu.is_empty() {
        return (None, "Empty LTE NAS PDU".into(), false);
    }

    let pd = pdu[0] & 0x0F;

    match pd {
        0x07 => decode_emm(pdu, direction),
        0x02 => decode_esm(pdu, direction),
        _ => {
            let summary =
                format!("LTE NAS {} PD=0x{:02X} ({} bytes)", direction, pd, pdu.len());
            (None, summary, false)
        }
    }
}

// ---------------------------------------------------------------------------
// EMM
// ---------------------------------------------------------------------------

fn decode_emm(
    pdu: &[u8],
    direction: &str,
) -> (Option<serde_json::Value>, String, bool) {
    let pd = pdu[0] & 0x0F;
    let security_header = (pdu[0] >> 4) & 0x0F;

    let (msg_type_byte, is_protected) = if security_header == 0 && pdu.len() >= 2 {
        (pdu[1], false)
    } else {
        (0u8, true)
    };

    let msg_name = if is_protected {
        format!("Security-protected (SHT={})", security_header)
    } else {
        super::metadata::nas_emm_message_name(msg_type_byte)
    };

    let mut decoded = serde_json::json!({
        "protocol": "EMM",
        "direction": direction,
        "pd": format!("0x{:02X}", pd),
        "security_header": security_header,
        "message_type": format!("0x{:02X}", msg_type_byte),
        "message_name": msg_name,
        "is_protected": is_protected,
        "pdu_length": pdu.len(),
    });

    // Deep-parse specific unprotected message types
    if !is_protected {
        let deep: Option<(&str, serde_json::Value)> = match msg_type_byte {
            0x5D => Some(("security_mode", deep_parse_emm_security_mode_cmd(pdu))),
            0x44 => Some(("reject", deep_parse_emm_reject(pdu, "emm"))),
            0x4B => Some(("reject", deep_parse_emm_reject(pdu, "emm"))),
            0x4E => Some(("reject", deep_parse_emm_reject(pdu, "emm"))),
            0x55 => Some(("identity_request", deep_parse_emm_identity_request(pdu))),
            0x42 => Some(("attach_accept", deep_parse_emm_attach_accept(pdu))),
            0x52 => Some(("auth_request", deep_parse_emm_auth_request(pdu))),
            0x62 => Some(("emm_information", deep_parse_emm_information(pdu))),
            0x43 => Some(("attach_complete", deep_parse_emm_simple(pdu, "Attach Complete"))),
            0x45 => Some(("detach_request", deep_parse_emm_detach_request(pdu))),
            0x46 => Some(("detach_accept", deep_parse_emm_simple(pdu, "Detach Accept"))),
            0x48 => Some(("tau_request", deep_parse_emm_tau_request(pdu))),
            0x49 => Some(("tau_accept", deep_parse_emm_tau_accept(pdu))),
            0x4A => Some(("tau_complete", deep_parse_emm_simple(pdu, "TAU Complete"))),
            0x53 => Some(("auth_response", deep_parse_emm_simple(pdu, "Authentication Response"))),
            0x54 => Some(("auth_reject", deep_parse_emm_simple(pdu, "Authentication Reject"))),
            0x5E => Some(("sec_mode_complete", deep_parse_emm_simple(pdu, "Security Mode Complete"))),
            0x5F => Some(("sec_mode_reject", deep_parse_emm_sec_mode_reject(pdu))),
            _ => None,
        };
        if let Some((key, val)) = deep {
            decoded.as_object_mut().unwrap().insert(key.to_string(), val);
        }
    }

    let summary = format!("EMM {} {}", direction, msg_name);
    (Some(decoded), summary, true)
}

// ---------------------------------------------------------------------------
// ESM
// ---------------------------------------------------------------------------

fn decode_esm(
    pdu: &[u8],
    direction: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if pdu.len() < 3 {
        return (None, format!("ESM {} (truncated)", direction), false);
    }

    let pd = pdu[0] & 0x0F;
    let bearer_id = (pdu[0] >> 4) & 0x0F;
    let _pti = pdu[1];
    let msg_type_byte = pdu[2];
    let msg_name = super::metadata::nas_esm_message_name(msg_type_byte);

    let mut decoded = serde_json::json!({
        "protocol": "ESM",
        "direction": direction,
        "pd": format!("0x{:02X}", pd),
        "bearer_id": bearer_id,
        "message_type": format!("0x{:02X}", msg_type_byte),
        "message_name": msg_name,
        "pdu_length": pdu.len(),
    });

    let deep: Option<(&str, serde_json::Value)> = match msg_type_byte {
        0xC1 => Some(("activate_default", deep_parse_esm_activate_default(pdu))),
        0xC3 => Some(("reject", deep_parse_esm_reject(pdu))),
        0xE8 => Some(("status", deep_parse_esm_reject(pdu))),
        0xCD => Some(("deactivate_bearer", deep_parse_esm_deactivate_bearer(pdu))),
        0xD0 => Some(("pdn_connectivity", deep_parse_esm_pdn_connectivity(pdu))),
        _ => None,
    };
    if let Some((key, val)) = deep {
        decoded.as_object_mut().unwrap().insert(key.to_string(), val);
    }

    let summary = format!("ESM {} {} (bearer {})", direction, msg_name, bearer_id);
    (Some(decoded), summary, true)
}

// ---------------------------------------------------------------------------
// Deep-parse helpers — EMM
// ---------------------------------------------------------------------------

/// Parse Security Mode Command (message type 0x5E / 0x5D).
///
/// Layout: PD_SHT(1) + MT(1) + NAS_SEC(1) + NAS_KSI(1/2) +
///         UE_SEC_CAP_LEN(1) + caps...
fn deep_parse_emm_security_mode_cmd(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 5 {
        return serde_json::json!({"error": "truncated"});
    }

    let sec_algo = pdu[2];
    let cipher_algo = (sec_algo >> 4) & 0x07;
    let integrity_algo = sec_algo & 0x07;

    let cipher_name = super::nas_common::security_algo_lte_cipher(cipher_algo);
    let integrity_name = super::nas_common::security_algo_lte_integrity(integrity_algo);

    let nas_ksi = (pdu[3] >> 4) & 0x07;

    // Scan past replayed UE security capabilities (mandatory TLV)
    let mut imeisv_requested = false;
    let mut i = 4usize;
    if i < pdu.len() {
        let cap_len = pdu[i] as usize;
        i += 1 + cap_len;
    }
    // Look for IMEISV request IE (IEI upper nibble 0xC)
    while i < pdu.len() {
        match pdu[i] >> 4 {
            0xC => {
                imeisv_requested = (pdu[i] & 0x01) != 0;
                i += 1;
            }
            _ => break,
        }
    }

    serde_json::json!({
        "cipher_algo": cipher_algo,
        "cipher_name": cipher_name,
        "integrity_algo": integrity_algo,
        "integrity_name": integrity_name,
        "nas_ksi": nas_ksi,
        "imeisv_requested": imeisv_requested,
        "null_cipher_warning": cipher_algo == 0,
        "null_integrity_warning": integrity_algo == 0,
    })
}

/// Parse EMM Reject messages: Attach Reject (0x44), TAU Reject (0x4B),
/// Service Reject (0x4E).
///
/// TS 24.301: PD_SHT(1) + MT(1) + EMM_Cause(1)
fn deep_parse_emm_reject(pdu: &[u8], _cause_type: &str) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[2];
    let name = super::nas_common::emm_cause_name(cause);
    serde_json::json!({
        "emm_cause": cause,
        "cause_name": name,
    })
}

/// Parse Identity Request (message type 0x55).
///
/// TS 24.301 section 8.2.18: PD_SHT(1) + MT(1) + Identity_type(half-octet) + spare
fn deep_parse_emm_identity_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let identity_type = pdu[2] & 0x07;
    let name = super::nas_common::identity_type_lte_name(identity_type);
    serde_json::json!({
        "identity_type": identity_type,
        "identity_type_name": name,
    })
}

/// Parse Attach Accept (message type 0x42).
///
/// TS 24.301 section 8.2.1:
///   PD_SHT(1) + MT(1) + EPS_attach_result(half) + spare(half) +
///   T3412_value(1) + TAI_list(LV) + ESM_message_container(LV-E) + ...
fn deep_parse_emm_attach_accept(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }

    let eps_attach_result = pdu[2] & 0x07;

    let t3412_value: Option<u8> = if pdu.len() >= 4 { Some(pdu[3]) } else { None };

    // TAI list: starts at pdu[4], first byte is length
    let mut tai_count: u8 = 0;
    let mut pos = 4usize;
    if pdu.len() > pos {
        let tai_list_len = pdu[pos] as usize;
        // Number of TAIs can be derived from the first byte of the TAI list body
        if tai_list_len > 0 && pdu.len() > pos + 1 {
            // The first byte of TAI list data contains partial-list type (bits 6-5)
            // and number of elements (bits 4-0)
            tai_count = (pdu[pos + 1] & 0x1F) + 1;
        }
        pos += 1 + tai_list_len;
    }

    // ESM message container: LV-E (2-byte length) at current pos
    // Skip over it
    if pdu.len() > pos + 1 {
        let esm_len = u16::from_le_bytes([
            pdu[pos],
            if pdu.len() > pos + 1 { pdu[pos + 1] } else { 0 },
        ]) as usize;
        pos += 2 + esm_len;
    }

    // Scan for GUTI (IEI 0x50, TLV)
    let mut guti: Option<String> = None;
    while pos + 1 < pdu.len() {
        let iei = pdu[pos];
        if iei == 0x50 {
            // GUTI TLV: tag(1) + len(1) + value
            if pos + 2 < pdu.len() {
                let guti_len = pdu[pos + 1] as usize;
                if pos + 2 + guti_len <= pdu.len() {
                    guti = Some(hex::encode(&pdu[pos + 2..pos + 2 + guti_len]));
                }
            }
            break;
        }
        // Skip unknown TLV IEs
        if pos + 1 < pdu.len() {
            let ie_len = pdu[pos + 1] as usize;
            pos += 2 + ie_len;
        } else {
            break;
        }
    }

    serde_json::json!({
        "eps_attach_result": eps_attach_result,
        "t3412_value": t3412_value,
        "tai_count": tai_count,
        "guti": guti,
    })
}

/// Parse Authentication Request (message type 0x52).
///
/// TS 24.301 section 8.2.7:
///   PD_SHT(1) + MT(1) + NAS_KSI(half) + spare(half) + RAND(16) +
///   AUTN(TLV: tag + len + 16)
fn deep_parse_emm_auth_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }

    let nas_ksi = (pdu[2] >> 4) & 0x07;

    // RAND: 16 bytes starting at pdu[3]
    let rand_hex = if pdu.len() >= 19 {
        Some(hex::encode(&pdu[3..19]))
    } else {
        None
    };

    // AUTN: tag at pdu[19], length at pdu[20], value at pdu[21..37]
    let autn_hex = if pdu.len() >= 37 {
        let _tag = pdu[19];
        let _len = pdu[20];
        Some(hex::encode(&pdu[21..37]))
    } else {
        None
    };

    serde_json::json!({
        "nas_ksi": nas_ksi,
        "rand_hex": rand_hex,
        "autn_hex": autn_hex,
    })
}

/// Parse EMM Information (message type 0x62).
///
/// TS 24.301 section 8.2.13:
///   PD_SHT(1) + MT(1) + optional IEs:
///   - 0x43: Full network name (TLV)
///   - 0x45: Short network name (TLV)
///   - 0x46: Local time zone (TV, 1 byte)
///   - 0x47: Universal time and local time zone (TV, 7 bytes)
fn deep_parse_emm_information(pdu: &[u8]) -> serde_json::Value {
    let mut network_name: Option<String> = None;
    let mut short_name: Option<String> = None;
    let mut timezone: Option<u8> = None;

    let mut i = 2usize; // skip PD_SHT + MT
    while i < pdu.len() {
        let iei = pdu[i];
        match iei {
            0x43 => {
                // Full network name (TLV)
                if i + 1 >= pdu.len() {
                    break;
                }
                let len = pdu[i + 1] as usize;
                if i + 2 + len > pdu.len() || len == 0 {
                    i += 2;
                    continue;
                }
                // First byte of value: encoding info (bit 7: 0=GSM7, 1=UCS2),
                // we do simple ASCII extraction from the remaining bytes
                let name_bytes = &pdu[i + 3..i + 2 + len];
                network_name = Some(extract_ascii(name_bytes));
                i += 2 + len;
            }
            0x45 => {
                // Short network name (TLV)
                if i + 1 >= pdu.len() {
                    break;
                }
                let len = pdu[i + 1] as usize;
                if i + 2 + len > pdu.len() || len == 0 {
                    i += 2;
                    continue;
                }
                let name_bytes = &pdu[i + 3..i + 2 + len];
                short_name = Some(extract_ascii(name_bytes));
                i += 2 + len;
            }
            0x46 => {
                // Local time zone (TV, 1 data byte after IEI)
                if i + 1 < pdu.len() {
                    timezone = Some(pdu[i + 1]);
                }
                i += 2;
            }
            0x47 => {
                // Universal time and local time zone (TV, 7 data bytes)
                i += 1 + 7;
            }
            _ => {
                // Unknown IE — try to skip as TLV
                if i + 1 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    i += 2 + len;
                } else {
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "network_name": network_name,
        "short_name": short_name,
        "timezone": timezone,
    })
}

// ---------------------------------------------------------------------------
// Deep-parse helpers — ESM
// ---------------------------------------------------------------------------

/// Parse Activate Default EPS Bearer Context Request (message type 0xC1).
///
/// TS 24.301 section 8.3.6:
///   PD/Bearer(1) + PTI(1) + MT(1) + EPS_QoS(LV) + APN(LV) + PDN_address(LV)
fn deep_parse_esm_activate_default(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let mut pos = 3usize;

    // EPS QoS (LV): length byte then QCI
    let qci: Option<u8> = if pos < pdu.len() {
        let qos_len = pdu[pos] as usize;
        let val = if qos_len >= 1 && pos + 1 < pdu.len() {
            Some(pdu[pos + 1])
        } else {
            None
        };
        pos += 1 + qos_len;
        val
    } else {
        None
    };

    // APN (LV): length byte then APN octets
    let apn: Option<String> = if pos < pdu.len() {
        let apn_len = pdu[pos] as usize;
        let val = if apn_len > 0 && pos + 1 + apn_len <= pdu.len() {
            Some(decode_apn(&pdu[pos + 1..pos + 1 + apn_len]))
        } else {
            None
        };
        pos += 1 + apn_len;
        val
    } else {
        None
    };

    // PDN address (LV): length byte + type byte + address bytes
    let (pdn_type, pdn_address): (Option<String>, Option<String>) = if pos < pdu.len() {
        let pdn_len = pdu[pos] as usize;
        if pdn_len >= 1 && pos + 1 + pdn_len <= pdu.len() {
            let pdn_type_byte = pdu[pos + 1];
            let pdn_type_str = match pdn_type_byte & 0x07 {
                1 => "IPv4",
                2 => "IPv6",
                3 => "IPv4v6",
                _ => "Unknown",
            };
            let addr = if pdn_len > 1 {
                Some(format_pdn_address(pdn_type_byte & 0x07, &pdu[pos + 2..pos + 1 + pdn_len]))
            } else {
                None
            };
            (Some(pdn_type_str.to_string()), addr)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    serde_json::json!({
        "qci": qci,
        "apn": apn,
        "pdn_type": pdn_type,
        "pdn_address": pdn_address,
    })
}

/// Parse ESM Reject / ESM Status (message types 0xC3, 0xE8).
///
/// PD/Bearer(1) + PTI(1) + MT(1) + ESM_Cause(1) at pdu[3]
fn deep_parse_esm_reject(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[3];
    let name = super::nas_common::esm_cause_name(cause);
    serde_json::json!({
        "esm_cause": cause,
        "cause_name": name,
    })
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Decode APN label-encoded bytes into a dot-separated string.
///
/// Each label is preceded by its length byte; labels are concatenated with `.`.
fn decode_apn(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let label_len = data[i] as usize;
        i += 1;
        if label_len == 0 || i + label_len > data.len() {
            break;
        }
        if !result.is_empty() {
            result.push('.');
        }
        for &b in &data[i..i + label_len] {
            if b >= 0x20 && b <= 0x7E {
                result.push(b as char);
            }
        }
        i += label_len;
    }
    result
}

/// Format a PDN address from its type and raw bytes.
fn format_pdn_address(pdn_type: u8, data: &[u8]) -> String {
    match pdn_type {
        1 if data.len() >= 4 => {
            // IPv4
            format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3])
        }
        2 if data.len() >= 8 => {
            // IPv6 interface identifier (8 bytes)
            format!("::{}",
                hex::encode(data)
            )
        }
        3 if data.len() >= 12 => {
            // IPv4v6: first 8 bytes = IPv6 iid, next 4 = IPv4
            let ipv6_part = hex::encode(&data[..8]);
            let ipv4_part = format!("{}.{}.{}.{}", data[8], data[9], data[10], data[11]);
            format!("{}  /  ::{}", ipv4_part, ipv6_part)
        }
        _ => hex::encode(data),
    }
}

/// Extract printable ASCII characters from a byte slice.
fn extract_ascii(data: &[u8]) -> String {
    let mut s = String::new();
    for &b in data {
        if b >= 0x20 && b <= 0x7E {
            s.push(b as char);
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Deep-parse helpers — EMM (simple / remaining messages)
// ---------------------------------------------------------------------------

/// Shared parser for simple EMM messages with no mandatory IEs beyond the
/// header (e.g. Attach Complete, Detach Accept, TAU Complete, Auth Response/Reject,
/// Security Mode Complete).
fn deep_parse_emm_simple(pdu: &[u8], name: &str) -> serde_json::Value {
    serde_json::json!({"parsed": true, "message": name, "pdu_length": pdu.len()})
}

/// Parse Detach Request (message type 0x45).
///
/// TS 24.301 section 8.2.11:
///   PD_SHT(1) + MT(1) + detach_type(half-octet, bits 4-1) + switch_off(bit 3 of byte)
fn deep_parse_emm_detach_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let detach_type = (pdu[2] >> 4) & 0x0F;
    let switch_off = (pdu[2] >> 3) & 0x01;
    let type_name = match detach_type & 0x07 {
        1 => "EPS detach",
        2 => "IMSI detach",
        3 => "Combined EPS/IMSI detach",
        _ => "reserved",
    };
    serde_json::json!({"detach_type": detach_type, "type_name": type_name, "switch_off": switch_off != 0})
}

/// Parse TAU Request (message type 0x48).
///
/// TS 24.301 section 8.2.29:
///   PD_SHT(1) + MT(1) + EPS_update_type(lower nibble of byte 2)
fn deep_parse_emm_tau_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let eps_update_type = pdu[2] & 0x07;
    let type_name = match eps_update_type {
        0 => "TA updating",
        1 => "Combined TA/LA updating",
        2 => "Combined TA/LA with IMSI attach",
        3 => "Periodic updating",
        _ => "reserved",
    };
    serde_json::json!({"eps_update_type": eps_update_type, "type_name": type_name})
}

/// Parse TAU Accept (message type 0x49).
///
/// TS 24.301 section 8.2.26:
///   PD_SHT(1) + MT(1) + EPS_update_result(lower nibble of byte 2)
fn deep_parse_emm_tau_accept(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let eps_update_result = pdu[2] & 0x07;
    let result_name = match eps_update_result {
        0 => "TA updated",
        1 => "Combined TA/LA updated",
        _ => "reserved",
    };
    serde_json::json!({"eps_update_result": eps_update_result, "result_name": result_name})
}

/// Parse Security Mode Reject (message type 0x5F).
///
/// TS 24.301 section 8.2.22:
///   PD_SHT(1) + MT(1) + EMM_Cause(1)
fn deep_parse_emm_sec_mode_reject(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 3 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[2];
    let cause_name = super::nas_common::emm_cause_name(cause);
    serde_json::json!({"emm_cause": cause, "cause_name": cause_name})
}

// ---------------------------------------------------------------------------
// Deep-parse helpers — ESM (additional messages)
// ---------------------------------------------------------------------------

/// Parse Deactivate EPS Bearer Context Request (message type 0xCD).
///
/// TS 24.301 section 8.3.12:
///   PD/Bearer(1) + PTI(1) + MT(1) + ESM_Cause(1)
fn deep_parse_esm_deactivate_bearer(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[3];
    let cause_name = super::nas_common::esm_cause_name(cause);
    serde_json::json!({"esm_cause": cause, "cause_name": cause_name})
}

/// Parse PDN Connectivity Request (message type 0xD0).
///
/// TS 24.301 section 8.3.20:
///   PD/Bearer(1) + PTI(1) + MT(1) + request_type(lower nibble) + PDN_type(upper nibble)
fn deep_parse_esm_pdn_connectivity(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }
    let request_type = pdu[3] & 0x07;
    let pdn_type = (pdu[3] >> 4) & 0x07;
    let req_name = match request_type {
        1 => "initial",
        2 => "handover",
        3 => "emergency",
        _ => "unknown",
    };
    let pdn_name = match pdn_type {
        1 => "IPv4",
        2 => "IPv6",
        3 => "IPv4v6",
        _ => "unknown",
    };
    serde_json::json!({"request_type": request_type, "request_name": req_name, "pdn_type": pdn_type, "pdn_type_name": pdn_name})
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emm_identity_request() {
        // PD=0x07 (EMM, SHT=0), MT=0x55 (Identity Request), identity_type=1 (IMSI)
        let pdu = [0x07, 0x55, 0x01];
        let result = deep_parse_emm_identity_request(&pdu);
        assert_eq!(result["identity_type"], 1);
        assert_eq!(result["identity_type_name"], "IMSI");
    }

    #[test]
    fn test_emm_reject() {
        // PD=0x07, MT=0x44 (Attach Reject), cause=7 (EPS services not allowed)
        let pdu = [0x07, 0x44, 0x07];
        let result = deep_parse_emm_reject(&pdu, "emm");
        assert_eq!(result["emm_cause"], 7);
        assert_eq!(result["cause_name"], "EPS services not allowed");
    }

    #[test]
    fn test_emm_security_mode_cmd() {
        // PD=0x07 (SHT=0), MT=0x5D, sec_algo=0x22 (cipher=2/AES, integrity=2/AES),
        // NAS_KSI=0x20 (ksi=2), UE_SEC_CAP_LEN=0x02, caps=0x80 0xE0
        let pdu = [0x07, 0x5D, 0x22, 0x20, 0x02, 0x80, 0xE0];
        let result = deep_parse_emm_security_mode_cmd(&pdu);
        assert_eq!(result["cipher_algo"], 2);
        assert_eq!(result["integrity_algo"], 2);
        assert_eq!(result["cipher_name"], "128-EEA2 (AES)");
        assert_eq!(result["integrity_name"], "128-EIA2 (AES)");
        assert_eq!(result["nas_ksi"], 2);
        assert_eq!(result["null_cipher_warning"], false);
        assert_eq!(result["null_integrity_warning"], false);
    }

    #[test]
    fn test_esm_reject() {
        // PD=0x02 (ESM), bearer_id=5, PTI=0x00, MT=0xE8 (ESM Status),
        // cause=111 (Protocol error unspecified)
        let pdu = [0x52, 0x00, 0xE8, 0x6F];
        let result = deep_parse_esm_reject(&pdu);
        assert_eq!(result["esm_cause"], 111);
        assert_eq!(result["cause_name"], "Protocol error unspecified");
    }

    #[test]
    fn test_decode_apn() {
        // APN: "\x04test\x03com" -> "test.com"
        let apn_data = [0x04, b't', b'e', b's', b't', 0x03, b'c', b'o', b'm'];
        assert_eq!(decode_apn(&apn_data), "test.com");
    }

    #[test]
    fn test_emm_dispatch_via_inner() {
        // Ensure decode_lte_nas_inner dispatches EMM correctly
        let pdu = [0x07, 0x55, 0x01]; // Identity Request
        let (decoded, summary, fully_decoded) = decode_lte_nas_inner(&pdu, "DL");
        assert!(fully_decoded);
        assert!(summary.contains("EMM"));
        let obj = decoded.unwrap();
        assert_eq!(obj["protocol"], "EMM");
        assert_eq!(obj["identity_request"]["identity_type"], 1);
    }

    #[test]
    fn test_esm_dispatch_via_inner() {
        // Ensure decode_lte_nas_inner dispatches ESM correctly
        let pdu = [0x52, 0x00, 0xE8, 0x6F]; // ESM Status
        let (decoded, summary, fully_decoded) = decode_lte_nas_inner(&pdu, "DL");
        assert!(fully_decoded);
        assert!(summary.contains("ESM"));
        let obj = decoded.unwrap();
        assert_eq!(obj["protocol"], "ESM");
        assert_eq!(obj["status"]["esm_cause"], 111);
    }

    #[test]
    fn test_emm_detach_request() {
        // PD=0x07 (EMM, SHT=0), MT=0x45 (Detach Request),
        // byte 2: detach_type=1 (EPS detach) in upper nibble, switch_off=1 (bit 3)
        // Upper nibble = 0001, switch_off bit = 1 -> byte = 0x18
        let pdu = [0x07, 0x45, 0x18];
        let result = deep_parse_emm_detach_request(&pdu);
        assert_eq!(result["detach_type"], 1);
        assert_eq!(result["type_name"], "EPS detach");
        assert_eq!(result["switch_off"], true);
    }

    #[test]
    fn test_emm_sec_mode_reject() {
        // PD=0x07 (EMM, SHT=0), MT=0x5F (Security Mode Reject),
        // cause=23 (#23 = UE security capabilities mismatch)
        let pdu = [0x07, 0x5F, 0x17];
        let result = deep_parse_emm_sec_mode_reject(&pdu);
        assert_eq!(result["emm_cause"], 23);
        assert_eq!(result["cause_name"], "UE security capabilities mismatch");
    }

    #[test]
    fn test_emm_tau_request() {
        // PD=0x07 (EMM, SHT=0), MT=0x48 (TAU Request),
        // EPS update type = 1 (Combined TA/LA updating) in lower nibble
        let pdu = [0x07, 0x48, 0x01];
        let result = deep_parse_emm_tau_request(&pdu);
        assert_eq!(result["eps_update_type"], 1);
        assert_eq!(result["type_name"], "Combined TA/LA updating");
    }
}
