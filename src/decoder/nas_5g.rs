//! 5G NAS decoder functions
//!
//! Decodes 5G NAS (Non-Access Stratum) messages for both 5GMM (Mobility Management)
//! and 5GSM (Session Management) protocols per 3GPP TS 24.501.

// ============================================================================
// OTA / PDU ENTRY POINTS
// ============================================================================

/// Decode 5G NAS OTA message (log codes 0xB0C2, 0xB0C3)
/// OTA header: version(1) + rrc_rel(1) + rrc_ver(1) + bearer_id(1) + len(2) + NAS PDU...
pub fn decode_5g_nas_ota(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 6 {
        return (
            None,
            format!("5G NAS OTA: too short ({} bytes)", data.len()),
            false,
        );
    }

    let version = data[0];
    let _rrc_rel = data[1];
    let _rrc_ver = data[2];
    let bearer_id = data[3];
    let nas_len = u16::from_le_bytes([data[4], data[5]]) as usize;

    let direction = if bearer_id & 0x10 != 0 { "UL" } else { "DL" };

    if data.len() < 6 + nas_len || nas_len == 0 {
        return (
            None,
            format!("5G NAS {} (truncated, hdr_ver={})", direction, version),
            false,
        );
    }

    let nas_pdu = &data[6..6 + nas_len];
    decode_5g_nas_pdu(nas_pdu, direction)
}

/// Decode 5G NAS plain OTA (log code 0xB0C6)
pub fn decode_5g_nas_plain(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 2 {
        return (None, "5G NAS plain: too short".into(), false);
    }
    decode_5g_nas_pdu(data, "UL/DL")
}

/// Parse a 5G NAS PDU and identify message type.
/// Dispatches on EPD: 0x7E = 5GMM, 0x2E = 5GSM, 0x07/0x02 = LTE NAS.
fn decode_5g_nas_pdu(pdu: &[u8], direction: &str) -> (Option<serde_json::Value>, String, bool) {
    if pdu.is_empty() {
        return (None, "Empty NAS PDU".into(), false);
    }

    let epd = pdu[0];
    match epd {
        // 5GS Mobility Management (5GMM)
        0x7E => decode_5gmm(pdu, direction),

        // 5GS Session Management (5GSM)
        0x2E => decode_5gsm(pdu, direction),

        // LTE NAS (in 5G context -- EN-DC)
        0x07 | 0x02 => super::nas_lte::decode_lte_nas_inner(pdu, direction),

        _ => {
            let summary = format!(
                "NAS {} EPD=0x{:02X} ({} bytes)",
                direction,
                epd,
                pdu.len()
            );
            (None, summary, false)
        }
    }
}

// ============================================================================
// 5GMM PARSING (EPD 0x7E)
// ============================================================================

fn decode_5gmm(pdu: &[u8], direction: &str) -> (Option<serde_json::Value>, String, bool) {
    let epd = pdu[0];

    if pdu.len() < 3 {
        return (None, format!("5GMM {} (truncated)", direction), false);
    }

    let security_header = pdu[1] & 0x0F;
    let (msg_type_byte, is_protected) = if security_header == 0 {
        // Plain NAS
        (pdu[2], false)
    } else if pdu.len() >= 7 {
        // Security-protected: skip 4 bytes (MAC) + 1 byte (seq)
        // Then we'd need to decrypt... just note it's protected
        (0u8, true)
    } else {
        (0u8, true)
    };

    let msg_name = if is_protected {
        format!("Security-protected (SHT={})", security_header)
    } else {
        super::metadata::nas_5gmm_message_name(msg_type_byte)
    };

    let mut decoded = serde_json::json!({
        "protocol": "5GMM",
        "direction": direction,
        "epd": format!("0x{:02X}", epd),
        "security_header": security_header,
        "message_type": format!("0x{:02X}", msg_type_byte),
        "message_name": msg_name,
        "is_protected": is_protected,
        "pdu_length": pdu.len(),
    });

    // Deep parse specific message types
    if !is_protected {
        let deep = match msg_type_byte {
            0x5E => Some(("security_mode", deep_parse_5gmm_security_mode_cmd(pdu))),
            0x42 => Some((
                "registration_accept",
                deep_parse_5gmm_registration_accept(pdu),
            )),
            0x44 => Some(("reject", deep_parse_5gmm_reject(pdu))),
            0x4D => Some(("reject", deep_parse_5gmm_reject(pdu))),
            0x47 => Some((
                "deregistration",
                deep_parse_5gmm_deregistration_nw(pdu),
            )),
            0x5C => Some((
                "identity_request",
                deep_parse_5gmm_identity_request(pdu),
            )),
            0x56 => Some(("auth_request", deep_parse_5gmm_auth_request(pdu))),
            0x41 => Some((
                "registration_request",
                deep_parse_5gmm_registration_request(pdu),
            )),
            0x54 => Some(("config_update", deep_parse_5gmm_config_update(pdu))),
            0x67 | 0x68 => Some(("nas_transport", deep_parse_5gmm_nas_transport(pdu))),
            0x43 => Some(("registration_complete", deep_parse_5gmm_simple(pdu, "Registration Complete"))),
            0x46 => Some(("deregistration_accept_ue", deep_parse_5gmm_simple(pdu, "Deregistration Accept (UE)"))),
            0x48 => Some(("deregistration_accept_nw", deep_parse_5gmm_simple(pdu, "Deregistration Accept (NW)"))),
            0x4E => Some(("service_accept", deep_parse_5gmm_simple(pdu, "Service Accept"))),
            0x55 => Some(("config_update_complete", deep_parse_5gmm_simple(pdu, "Configuration Update Complete"))),
            0x57 => Some(("auth_response", deep_parse_5gmm_auth_response(pdu))),
            0x58 => Some(("auth_reject", deep_parse_5gmm_simple(pdu, "Authentication Reject"))),
            0x59 => Some(("auth_failure", deep_parse_5gmm_auth_failure(pdu))),
            0x5F => Some(("security_mode_complete", deep_parse_5gmm_simple(pdu, "Security Mode Complete"))),
            0x60 => Some(("security_mode_reject", deep_parse_5gmm_sec_mode_reject(pdu))),
            _ => None,
        };
        if let Some((key, val)) = deep {
            decoded
                .as_object_mut()
                .unwrap()
                .insert(key.to_string(), val);
        }
    }

    let summary = format!("5GMM {} {}", direction, msg_name);
    (Some(decoded), summary, true)
}

// ============================================================================
// 5GSM PARSING (EPD 0x2E)
// ============================================================================

fn decode_5gsm(pdu: &[u8], direction: &str) -> (Option<serde_json::Value>, String, bool) {
    let epd = pdu[0];

    if pdu.len() < 4 {
        return (None, format!("5GSM {} (truncated)", direction), false);
    }

    let pdu_session_id = pdu[1];
    let _pti = pdu[2];
    let msg_type_byte = pdu[3];
    let msg_name = super::metadata::nas_5gsm_message_name(msg_type_byte);

    let mut decoded = serde_json::json!({
        "protocol": "5GSM",
        "direction": direction,
        "epd": format!("0x{:02X}", epd),
        "pdu_session_id": pdu_session_id,
        "message_type": format!("0x{:02X}", msg_type_byte),
        "message_name": msg_name,
        "pdu_length": pdu.len(),
    });

    // Deep parse specific message types
    let deep = match msg_type_byte {
        0xC1 => Some(deep_parse_5gsm_pdu_session_est_request(pdu)),
        0xC2 => Some(deep_parse_5gsm_pdu_session_accept(pdu)),
        0xC3 => Some(deep_parse_5gsm_pdu_session_reject(pdu)),
        0xD3 => Some(deep_parse_5gsm_release_command(pdu)),
        _ => None,
    };
    if let Some(val) = deep {
        if let Some(obj) = val.as_object() {
            for (k, v) in obj {
                decoded
                    .as_object_mut()
                    .unwrap()
                    .insert(k.clone(), v.clone());
            }
        }
    }

    let summary = format!(
        "5GSM {} {} (session {})",
        direction, msg_name, pdu_session_id
    );
    (Some(decoded), summary, true)
}

// ============================================================================
// DEEP PARSE FUNCTIONS -- 5GMM
// ============================================================================

/// Deep-parse 5G NAS Security Mode Command (msg_type 0x5E)
/// TS 24.501 section 8.2.25: EPD(1) + SHT(1) + MT(1) + NAS_SEC_Algo(1) + ngKSI(1) + optional IEs
fn deep_parse_5gmm_security_mode_cmd(pdu: &[u8]) -> serde_json::Value {
    // Minimum: EPD(1) + SHT(1) + MT(1) + NAS_SEC_Algo(1) + ngKSI(1) = 5
    if pdu.len() < 5 {
        return serde_json::json!({"error": "truncated"});
    }

    // Byte 3: NAS security algorithms (TS 24.501 section 9.11.3.34)
    // Bits 4-7: type of ciphering algorithm, bits 0-3: type of integrity protection
    let sec_algo = pdu[3];
    let cipher_algo = (sec_algo >> 4) & 0x07;
    let integrity_algo = sec_algo & 0x07;

    let cipher_name = super::nas_common::security_algo_5g_cipher(cipher_algo);
    let integrity_name = super::nas_common::security_algo_5g_integrity(integrity_algo);

    // Byte 4: ngKSI (half-octet + spare)
    let ng_ksi = pdu[4] & 0x07;

    // Check for IMEISV request (optional IE, tag 0xE-)
    let mut imeisv_requested = false;
    let mut additional_sec_info = false;
    let mut i = 5usize;
    while i < pdu.len() {
        let iei = pdu[i];
        match iei >> 4 {
            0xE => {
                imeisv_requested = (pdu[i] & 0x01) != 0;
                i += 1;
            }
            0xD => {
                if i + 1 < pdu.len() {
                    additional_sec_info = (pdu[i + 1] & 0x01) != 0;
                }
                i += 2;
            }
            _ => break, // Stop at unknown IE
        }
    }

    serde_json::json!({
        "cipher_algo": cipher_algo,
        "cipher_name": cipher_name,
        "integrity_algo": integrity_algo,
        "integrity_name": integrity_name,
        "ng_ksi": ng_ksi,
        "imeisv_requested": imeisv_requested,
        "horizontal_derivation": additional_sec_info,
        "null_cipher_warning": cipher_algo == 0,
        "null_integrity_warning": integrity_algo == 0,
    })
}

/// Deep-parse 5G NAS Registration Accept (msg_type 0x42)
/// TS 24.501 section 8.2.7: EPD(1) + SHT(1) + MT(1) + 5GS_reg_result(1) + optional IEs
fn deep_parse_5gmm_registration_accept(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let reg_result = pdu[3];
    let sms_allowed = (reg_result >> 3) & 0x01;
    let reg_type = match reg_result & 0x07 {
        1 => "3GPP access",
        2 => "non-3GPP access",
        3 => "3GPP and non-3GPP access",
        _ => "reserved",
    };

    // Scan optional IEs for 5G-GUTI (0x77) and TAI list (0x54)
    let mut guti_str = String::new();
    let mut tai_count = 0u8;
    let mut nssai_slices = Vec::new();

    let mut i = 4usize;
    while i < pdu.len() {
        if i >= pdu.len() {
            break;
        }
        let iei = pdu[i];

        match iei {
            // 5G-GUTI (IEI 0x77, TLV-E)
            0x77 => {
                if i + 3 < pdu.len() {
                    let len = u16::from_be_bytes([pdu[i + 1], pdu[i + 2]]) as usize;
                    if i + 3 + len <= pdu.len() && len >= 11 {
                        let guti_data = &pdu[i + 3..i + 3 + len];
                        // GUTI: spare(1/2) + type(1/2) + MCC/MNC(3) + AMF(3) + 5G-TMSI(4)
                        if guti_data.len() >= 11 {
                            let mcc = format!(
                                "{}{}{}",
                                guti_data[1] & 0x0F,
                                (guti_data[1] >> 4) & 0x0F,
                                guti_data[2] & 0x0F
                            );
                            let mnc_d3 = (guti_data[2] >> 4) & 0x0F;
                            let mnc = if mnc_d3 == 0x0F {
                                format!(
                                    "{}{}",
                                    guti_data[3] & 0x0F,
                                    (guti_data[3] >> 4) & 0x0F
                                )
                            } else {
                                format!(
                                    "{}{}{}",
                                    guti_data[3] & 0x0F,
                                    (guti_data[3] >> 4) & 0x0F,
                                    mnc_d3
                                )
                            };
                            let amf_region = guti_data[4];
                            let amf_set = ((guti_data[5] as u16) << 2)
                                | ((guti_data[6] as u16) >> 6);
                            let amf_pointer = guti_data[6] & 0x3F;
                            let tmsi = u32::from_be_bytes([
                                guti_data[7],
                                guti_data[8],
                                guti_data[9],
                                guti_data[10],
                            ]);
                            guti_str = format!(
                                "{}-{}-{:02X}-{:03X}-{:02X}-{:08X}",
                                mcc, mnc, amf_region, amf_set, amf_pointer, tmsi
                            );
                        }
                    }
                    i += 3 + len;
                } else {
                    break;
                }
            }
            // TAI list (IEI 0x54, TLV)
            0x54 => {
                if i + 2 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    if len > 0 {
                        tai_count = (len / 5).min(255) as u8; // approx
                    }
                    i += 2 + len;
                } else {
                    break;
                }
            }
            // Allowed NSSAI (IEI 0x15, TLV)
            0x15 => {
                if i + 2 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    if i + 2 + len <= pdu.len() {
                        let mut j = 0;
                        while j < len {
                            if i + 2 + j >= pdu.len() {
                                break;
                            }
                            let s_nssai_len = pdu[i + 2 + j] as usize;
                            if s_nssai_len >= 1 && j + 1 + s_nssai_len <= len {
                                let sst = pdu[i + 2 + j + 1];
                                let sd = if s_nssai_len >= 4 {
                                    Some(format!(
                                        "{:02X}{:02X}{:02X}",
                                        pdu[i + 2 + j + 2],
                                        pdu[i + 2 + j + 3],
                                        pdu[i + 2 + j + 4]
                                    ))
                                } else {
                                    None
                                };
                                nssai_slices.push(serde_json::json!({"sst": sst, "sd": sd}));
                            }
                            j += 1 + s_nssai_len;
                        }
                    }
                    i += 2 + len;
                } else {
                    break;
                }
            }
            // Skip other IEs
            _ => {
                // TLV format: check if it's a half-octet IE (high nibble match)
                if iei & 0xF0 == 0x90 || iei & 0xF0 == 0xA0 || iei & 0xF0 == 0xB0 {
                    i += 1; // Half-octet IE
                } else if i + 1 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    i += 2 + len;
                } else {
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "registration_type": reg_type,
        "sms_over_nas_allowed": sms_allowed != 0,
        "5g_guti": if guti_str.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(guti_str) },
        "tai_count": tai_count,
        "allowed_nssai": nssai_slices,
    })
}

/// Deep-parse 5GMM Registration Reject (0x44) and Service Reject (0x4D)
/// TS 24.501: EPD(1) + SHT(1) + MT(1) + 5GMM_Cause(1)
fn deep_parse_5gmm_reject(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let cause = pdu[3];
    let cause_name = super::nas_common::fgmm_cause_name(cause);

    serde_json::json!({
        "fgmm_cause": cause,
        "cause_name": cause_name,
    })
}

/// Deep-parse 5GMM Deregistration Request from network (0x47)
/// TS 24.501 section 8.2.12: EPD(1) + SHT(1) + MT(1) + de-reg_type(1) + [5GMM_Cause]
fn deep_parse_5gmm_deregistration_nw(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let de_reg_type = pdu[3];
    let switch_off = ((de_reg_type >> 3) & 0x01) != 0;
    let re_registration = (de_reg_type & 0x01) != 0;

    // Optional 5GMM cause at byte 4
    let (cause, cause_name) = if pdu.len() >= 5 {
        let c = pdu[4];
        (
            Some(c),
            Some(super::nas_common::fgmm_cause_name(c).to_string()),
        )
    } else {
        (None, None)
    };

    serde_json::json!({
        "switch_off": switch_off,
        "re_registration_required": re_registration,
        "fgmm_cause": cause,
        "cause_name": cause_name,
    })
}

/// Deep-parse 5GMM Identity Request (0x5C)
/// TS 24.501 section 8.2.22: EPD(1) + SHT(1) + MT(1) + spare(4bits) + identity_type(4bits)
fn deep_parse_5gmm_identity_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let identity_type = pdu[3] & 0x07;
    let name = super::nas_common::identity_type_5g_name(identity_type);

    serde_json::json!({
        "identity_type": identity_type,
        "identity_type_name": name,
    })
}

/// Deep-parse 5GMM Authentication Request (0x56)
/// TS 24.501 section 8.2.1: EPD(1) + SHT(1) + MT(1) + ngKSI(1) + ABBA(LV) + [RAND(TV,16)] + [AUTN(TLV,16)]
fn deep_parse_5gmm_auth_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    // Byte 3: ngKSI (lower 3 bits)
    let ng_ksi = pdu[3] & 0x07;

    // ABBA starts at byte 4: length at pdu[4], value at pdu[5..5+len]
    let mut abba_hex = String::new();
    let mut offset = 4usize;
    if offset < pdu.len() {
        let abba_len = pdu[offset] as usize;
        offset += 1;
        if offset + abba_len <= pdu.len() {
            abba_hex = hex::encode(&pdu[offset..offset + abba_len]);
            offset += abba_len;
        }
    }

    // Scan for optional IEs: RAND (IEI 0x21) and AUTN (IEI 0x20)
    let mut rand_hex = String::new();
    let mut autn_hex = String::new();

    while offset < pdu.len() {
        let iei = pdu[offset];
        match iei {
            // RAND (IEI 0x21, TV fixed 16 bytes)
            0x21 => {
                offset += 1;
                if offset + 16 <= pdu.len() {
                    rand_hex = hex::encode(&pdu[offset..offset + 16]);
                    offset += 16;
                } else {
                    break;
                }
            }
            // AUTN (IEI 0x20, TLV)
            0x20 => {
                offset += 1;
                if offset < pdu.len() {
                    let autn_len = pdu[offset] as usize;
                    offset += 1;
                    if offset + autn_len <= pdu.len() {
                        autn_hex = hex::encode(&pdu[offset..offset + autn_len]);
                        offset += autn_len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            _ => {
                // Unknown IE -- skip
                break;
            }
        }
    }

    serde_json::json!({
        "ng_ksi": ng_ksi,
        "abba_hex": abba_hex,
        "rand_hex": rand_hex,
        "autn_hex": autn_hex,
    })
}

/// Deep-parse 5GMM Registration Request (0x41)
/// TS 24.501 section 8.2.6: EPD(1) + SHT(1) + MT(1) + 5GS_reg_type_ngKSI(1) + 5GS_mobile_identity(LV-E)
fn deep_parse_5gmm_registration_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let reg_type_ksi = pdu[3];
    let reg_type = reg_type_ksi & 0x07;
    let ng_ksi = (reg_type_ksi >> 4) & 0x07;

    let reg_type_name = match reg_type {
        1 => "initial registration",
        2 => "mobility registration updating",
        3 => "periodic registration updating",
        4 => "emergency registration",
        _ => "unknown",
    };

    // Mobile identity is LV-E at offset 4: length = u16 big-endian at pdu[4..6]
    let (mobile_identity_type, mobile_identity_type_name) = if pdu.len() >= 7 {
        let mi_len = u16::from_be_bytes([pdu[4], pdu[5]]) as usize;
        if mi_len > 0 && pdu.len() >= 7 {
            let id_type = pdu[6] & 0x07;
            let id_name = super::nas_common::identity_type_5g_name(id_type);
            (Some(id_type), Some(id_name.to_string()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    serde_json::json!({
        "reg_type": reg_type,
        "reg_type_name": reg_type_name,
        "ng_ksi": ng_ksi,
        "mobile_identity_type": mobile_identity_type,
        "mobile_identity_type_name": mobile_identity_type_name,
    })
}

/// Deep-parse 5GMM Configuration Update Command (0x54)
/// TS 24.501 section 8.2.18: EPD(1) + SHT(1) + MT(1) + optional IEs (TLV)
fn deep_parse_5gmm_config_update(pdu: &[u8]) -> serde_json::Value {
    let mut guti: Option<String> = None;
    let mut tai_count: Option<u8> = None;
    let mut network_name: Option<String> = None;

    // Parse optional IEs after byte 3
    let mut i = 3usize;
    while i < pdu.len() {
        let iei = pdu[i];

        match iei {
            // 5G-GUTI (IEI 0x77, TLV-E)
            0x77 => {
                if i + 3 < pdu.len() {
                    let len = u16::from_be_bytes([pdu[i + 1], pdu[i + 2]]) as usize;
                    if i + 3 + len <= pdu.len() && len >= 11 {
                        let guti_data = &pdu[i + 3..i + 3 + len];
                        if guti_data.len() >= 11 {
                            let mcc = format!(
                                "{}{}{}",
                                guti_data[1] & 0x0F,
                                (guti_data[1] >> 4) & 0x0F,
                                guti_data[2] & 0x0F
                            );
                            let mnc_d3 = (guti_data[2] >> 4) & 0x0F;
                            let mnc = if mnc_d3 == 0x0F {
                                format!(
                                    "{}{}",
                                    guti_data[3] & 0x0F,
                                    (guti_data[3] >> 4) & 0x0F
                                )
                            } else {
                                format!(
                                    "{}{}{}",
                                    guti_data[3] & 0x0F,
                                    (guti_data[3] >> 4) & 0x0F,
                                    mnc_d3
                                )
                            };
                            let amf_region = guti_data[4];
                            let amf_set = ((guti_data[5] as u16) << 2)
                                | ((guti_data[6] as u16) >> 6);
                            let amf_pointer = guti_data[6] & 0x3F;
                            let tmsi = u32::from_be_bytes([
                                guti_data[7],
                                guti_data[8],
                                guti_data[9],
                                guti_data[10],
                            ]);
                            guti = Some(format!(
                                "{}-{}-{:02X}-{:03X}-{:02X}-{:08X}",
                                mcc, mnc, amf_region, amf_set, amf_pointer, tmsi
                            ));
                        }
                    }
                    i += 3 + len;
                } else {
                    break;
                }
            }
            // TAI list (IEI 0x54, TLV)
            0x54 => {
                if i + 2 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    if len > 0 {
                        tai_count = Some((len / 5).min(255) as u8);
                    }
                    i += 2 + len;
                } else {
                    break;
                }
            }
            // Full network name (IEI 0x43, TLV)
            0x43 => {
                if i + 2 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    if i + 2 + len <= pdu.len() && len > 0 {
                        // Try to extract ASCII from network name data
                        // First byte contains coding scheme info, rest is the name
                        let name_data = &pdu[i + 2..i + 2 + len];
                        let ascii: String = name_data
                            .iter()
                            .skip(1) // skip coding scheme byte
                            .filter(|&&b| b >= 0x20 && b <= 0x7E)
                            .map(|&b| b as char)
                            .collect();
                        if !ascii.is_empty() {
                            network_name = Some(ascii);
                        }
                    }
                    i += 2 + len;
                } else {
                    break;
                }
            }
            // Skip other IEs
            _ => {
                // Half-octet IEs
                if iei & 0xF0 == 0x90
                    || iei & 0xF0 == 0xA0
                    || iei & 0xF0 == 0xB0
                    || iei & 0xF0 == 0xD0
                {
                    i += 1;
                } else if i + 1 < pdu.len() {
                    // Check for TLV-E IEs (certain IEIs use 2-byte length)
                    if iei == 0x77 || iei == 0x78 || iei == 0x79 || iei == 0x7A || iei == 0x7B {
                        if i + 3 <= pdu.len() {
                            let len =
                                u16::from_be_bytes([pdu[i + 1], pdu[i + 2]]) as usize;
                            i += 3 + len;
                        } else {
                            break;
                        }
                    } else {
                        let len = pdu[i + 1] as usize;
                        i += 2 + len;
                    }
                } else {
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "guti": guti,
        "tai_count": tai_count,
        "network_name": network_name,
    })
}

/// Deep-parse 5GMM UL/DL NAS Transport (0x67, 0x68)
/// TS 24.501 section 8.2.11: EPD(1) + SHT(1) + MT(1) + payload_container_type(half-octet) + spare(half-octet) + payload_container(LV-E)
fn deep_parse_5gmm_nas_transport(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }

    let payload_container_type = pdu[3] & 0x0F;

    let container_type_name = match payload_container_type {
        1 => "N1 SM information",
        2 => "SMS",
        3 => "LPP",
        4 => "SOR transparent container",
        5 => "UE policy container",
        15 => "Multiple payloads",
        _ => "Unknown",
    };

    serde_json::json!({
        "payload_container_type": payload_container_type,
        "container_type_name": container_type_name,
    })
}

// ============================================================================
// DEEP PARSE FUNCTIONS -- 5GSM
// ============================================================================

/// Deep-parse 5GSM PDU Session Establishment Accept (0xC2)
/// TS 24.501 section 8.3.2: EPD(1) + PDU_Session_ID(1) + PTI(1) + MT(1) + SSC_mode(1)
///   + authorized_QoS_rules(LV-E) + session-AMBR(LV) + optional IEs
fn deep_parse_5gsm_pdu_session_accept(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 5 {
        return serde_json::json!({"error": "truncated"});
    }

    let ssc_mode = pdu[4] & 0x07;

    // After SSC mode byte, parse QoS rules (LV-E: 2-byte length), then session-AMBR (LV: 1-byte length)
    let mut offset = 5usize;
    let mut session_ambr_dl: Option<u16> = None;
    let mut session_ambr_ul: Option<u16> = None;
    let mut pdu_address: Option<String> = None;

    // Skip authorized QoS rules (LV-E)
    if offset + 2 <= pdu.len() {
        let qos_len = u16::from_be_bytes([pdu[offset], pdu[offset + 1]]) as usize;
        offset += 2 + qos_len;
    }

    // Session-AMBR (LV: 1-byte length)
    if offset < pdu.len() {
        let ambr_len = pdu[offset] as usize;
        offset += 1;
        if ambr_len >= 4 && offset + ambr_len <= pdu.len() {
            // DL AMBR (2 bytes) + UL AMBR (2 bytes)
            session_ambr_dl = Some(u16::from_be_bytes([pdu[offset], pdu[offset + 1]]));
            session_ambr_ul =
                Some(u16::from_be_bytes([pdu[offset + 2], pdu[offset + 3]]));
        }
        offset += ambr_len;
    }

    // Scan optional IEs for PDU address (IEI 0x29, TLV)
    while offset < pdu.len() {
        let iei = pdu[offset];
        match iei {
            // PDU address (IEI 0x29, TLV)
            0x29 => {
                if offset + 2 < pdu.len() {
                    let len = pdu[offset + 1] as usize;
                    if offset + 2 + len <= pdu.len() && len >= 5 {
                        let addr_type = pdu[offset + 2] & 0x07;
                        match addr_type {
                            // IPv4
                            1 => {
                                if len >= 5 {
                                    pdu_address = Some(format!(
                                        "{}.{}.{}.{}",
                                        pdu[offset + 3],
                                        pdu[offset + 4],
                                        pdu[offset + 5],
                                        pdu[offset + 6]
                                    ));
                                }
                            }
                            // IPv6 (interface ID, 8 bytes)
                            2 => {
                                if len >= 9 {
                                    pdu_address = Some(format!(
                                        "IPv6 IF-ID: {}",
                                        hex::encode(&pdu[offset + 3..offset + 3 + 8])
                                    ));
                                }
                            }
                            // IPv4v6
                            3 => {
                                if len >= 13 {
                                    pdu_address = Some(format!(
                                        "{}.{}.{}.{} + IPv6",
                                        pdu[offset + 11],
                                        pdu[offset + 12],
                                        pdu[offset + 13],
                                        pdu[offset + 14]
                                    ));
                                } else if len >= 5 {
                                    pdu_address = Some("IPv4v6 (truncated)".into());
                                }
                            }
                            _ => {}
                        }
                    }
                    offset += 2 + len;
                } else {
                    break;
                }
            }
            _ => {
                // Skip unknown IEs
                if iei & 0xF0 == 0x90
                    || iei & 0xF0 == 0xA0
                    || iei & 0xF0 == 0xB0
                    || iei & 0xF0 == 0xD0
                {
                    offset += 1;
                } else if offset + 1 < pdu.len() {
                    let len = pdu[offset + 1] as usize;
                    offset += 2 + len;
                } else {
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "ssc_mode": ssc_mode,
        "session_ambr_dl": session_ambr_dl,
        "session_ambr_ul": session_ambr_ul,
        "pdu_address": pdu_address,
    })
}

/// Deep-parse 5GSM PDU Session Establishment Reject (0xC3)
/// TS 24.501 section 8.3.3: EPD(1) + PDU_Session_ID(1) + PTI(1) + MT(1) + 5GSM_Cause(1)
fn deep_parse_5gsm_pdu_session_reject(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 5 {
        return serde_json::json!({"error": "truncated"});
    }

    let cause = pdu[4];
    // 5GSM cause codes largely overlap with ESM cause codes
    let cause_name = super::nas_common::esm_cause_name(cause);

    serde_json::json!({
        "cause": cause,
        "cause_name": cause_name,
    })
}

// ============================================================================
// DEEP PARSE FUNCTIONS -- 5GMM (simple messages)
// ============================================================================

/// Deep-parse simple 5GMM messages with no mandatory IEs beyond the header.
/// Used for: Registration Complete (0x43), Deregistration Accept UE (0x46),
/// Deregistration Accept NW (0x48), Service Accept (0x4E),
/// Config Update Complete (0x55), Security Mode Complete (0x5F).
fn deep_parse_5gmm_simple(pdu: &[u8], name: &str) -> serde_json::Value {
    serde_json::json!({"parsed": true, "message": name, "pdu_length": pdu.len()})
}

/// Deep-parse 5GMM Authentication Response (0x57)
/// TS 24.501 section 8.2.2: EPD(1) + SHT(1) + MT(1) + optional IEs
/// Optional: Authentication response parameter (IEI 0x2D, TLV)
fn deep_parse_5gmm_auth_response(pdu: &[u8]) -> serde_json::Value {
    let mut auth_response_param: Option<String> = None;

    // Scan optional IEs after byte 3
    let mut i = 3usize;
    while i < pdu.len() {
        let iei = pdu[i];
        match iei {
            // Authentication response parameter (IEI 0x2D, TLV)
            0x2D => {
                if i + 2 < pdu.len() {
                    let len = pdu[i + 1] as usize;
                    if i + 2 + len <= pdu.len() {
                        auth_response_param = Some(hex::encode(&pdu[i + 2..i + 2 + len]));
                    }
                    i += 2 + len;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    serde_json::json!({
        "auth_response_parameter": auth_response_param,
    })
}

/// Deep-parse 5GMM Authentication Failure (0x59)
/// TS 24.501 section 8.2.4: EPD(1) + SHT(1) + MT(1) + 5GMM_Cause(1) + [AUTS(IEI 0x30, TLV)]
fn deep_parse_5gmm_auth_failure(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[3];
    let cause_name = super::nas_common::fgmm_cause_name(cause);
    // Optional: AUTS parameter at IEI 0x30
    serde_json::json!({"fgmm_cause": cause, "cause_name": cause_name})
}

/// Deep-parse 5GMM Security Mode Reject (0x60)
/// TS 24.501 section 8.2.27: EPD(1) + SHT(1) + MT(1) + 5GMM_Cause(1)
fn deep_parse_5gmm_sec_mode_reject(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 4 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[3];
    let cause_name = super::nas_common::fgmm_cause_name(cause);
    serde_json::json!({"fgmm_cause": cause, "cause_name": cause_name})
}

// ============================================================================
// DEEP PARSE FUNCTIONS -- 5GSM (additional)
// ============================================================================

/// Deep-parse 5GSM PDU Session Establishment Request (0xC1)
/// TS 24.501 section 8.3.1: EPD(1) + PDU_Session_ID(1) + PTI(1) + MT(1) + integrity_prot_max_data_rate(2)
///   + optional IEs including PDU session type (IEI 0x9-, half-octet)
fn deep_parse_5gsm_pdu_session_est_request(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 6 {
        return serde_json::json!({"error": "truncated"});
    }

    // Bytes 4-5: integrity protection maximum data rate (mandatory, 2 bytes)
    let _integrity_max_dr_ul = pdu[4];
    let _integrity_max_dr_dl = pdu[5];

    // Scan optional IEs after byte 5 for PDU session type (IEI 0x9-, half-octet)
    let mut pdu_session_type: Option<u8> = None;
    let mut pdu_session_type_name: Option<&str> = None;

    let mut i = 6usize;
    while i < pdu.len() {
        let iei = pdu[i];
        match iei >> 4 {
            // PDU session type (IEI 0x9-, half-octet)
            0x9 => {
                let pst = iei & 0x07;
                pdu_session_type = Some(pst);
                pdu_session_type_name = Some(match pst {
                    1 => "IPv4",
                    2 => "IPv6",
                    3 => "IPv4v6",
                    4 => "Unstructured",
                    5 => "Ethernet",
                    _ => "Unknown",
                });
                i += 1;
            }
            // Other half-octet IEs
            0xA | 0xB | 0xD => {
                i += 1;
            }
            _ => {
                // TLV IE -- skip
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
        "pdu_session_type": pdu_session_type,
        "pdu_session_type_name": pdu_session_type_name,
    })
}

/// Deep-parse 5GSM PDU Session Release Command (0xD3)
/// TS 24.501 section 8.3.12: EPD(1) + PDU_Session_ID(1) + PTI(1) + MT(1) + 5GSM_Cause(1)
fn deep_parse_5gsm_release_command(pdu: &[u8]) -> serde_json::Value {
    if pdu.len() < 5 {
        return serde_json::json!({"error": "truncated"});
    }
    let cause = pdu[4];
    let cause_name = super::nas_common::esm_cause_name(cause);
    serde_json::json!({"sm_cause": cause, "cause_name": cause_name})
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_5gmm_identity_request() {
        // EPD=0x7E, SHT=0x00, MT=0x5C, identity_type=0x01 (SUCI)
        let pdu = [0x7E, 0x00, 0x5C, 0x01];
        let result = deep_parse_5gmm_identity_request(&pdu);

        assert_eq!(result["identity_type"], 1);
        assert_eq!(result["identity_type_name"], "SUCI");
    }

    #[test]
    fn test_5gmm_reject() {
        // EPD=0x7E, SHT=0x00, MT=0x44 (Registration Reject), cause=7 (5GS services not allowed)
        let pdu = [0x7E, 0x00, 0x44, 0x07];
        let result = deep_parse_5gmm_reject(&pdu);

        assert_eq!(result["fgmm_cause"], 7);
        let cause_name = result["cause_name"].as_str().unwrap();
        assert!(
            cause_name.contains("5GS services"),
            "cause_name '{}' should contain '5GS services'",
            cause_name
        );
    }

    #[test]
    fn test_5gmm_security_mode_cmd() {
        // EPD=0x7E, SHT=0x00, MT=0x5E, NAS_SEC_Algo=0x22 (cipher=2, integrity=2), ngKSI=0x03
        let pdu = [0x7E, 0x00, 0x5E, 0x22, 0x03];
        let result = deep_parse_5gmm_security_mode_cmd(&pdu);

        assert_eq!(result["cipher_algo"], 2);
        assert_eq!(result["integrity_algo"], 2);
        assert_eq!(result["ng_ksi"], 3);
        assert_eq!(result["null_cipher_warning"], false);
        assert_eq!(result["null_integrity_warning"], false);
    }

    #[test]
    fn test_5gmm_auth_request() {
        // EPD=0x7E, SHT=0x00, MT=0x56, ngKSI=0x03, ABBA len=2, ABBA=0x0000
        let pdu = [0x7E, 0x00, 0x56, 0x03, 0x02, 0x00, 0x00];
        let result = deep_parse_5gmm_auth_request(&pdu);

        assert_eq!(result["ng_ksi"], 3);
        assert_eq!(result["abba_hex"], "0000");
    }

    #[test]
    fn test_5gsm_reject() {
        // EPD=0x2E, PDU_Session_ID=0x01, PTI=0x00, MT=0xC3, cause=26 (Insufficient resources)
        let pdu = [0x2E, 0x01, 0x00, 0xC3, 0x1A];
        let result = deep_parse_5gsm_pdu_session_reject(&pdu);

        assert_eq!(result["cause"], 26);
        let cause_name = result["cause_name"].as_str().unwrap();
        assert_eq!(cause_name, "Insufficient resources");
    }

    #[test]
    fn test_5gmm_simple_registration_complete() {
        // EPD=0x7E, SHT=0x00, MT=0x43 (Registration Complete)
        let pdu = [0x7E, 0x00, 0x43];
        let result = deep_parse_5gmm_simple(&pdu, "Registration Complete");

        assert_eq!(result["parsed"], true);
        assert_eq!(result["message"], "Registration Complete");
        assert_eq!(result["pdu_length"], 3);
    }

    #[test]
    fn test_5gmm_auth_failure() {
        // EPD=0x7E, SHT=0x00, MT=0x59, cause=21 (Synch failure)
        let pdu = [0x7E, 0x00, 0x59, 0x15];
        let result = deep_parse_5gmm_auth_failure(&pdu);

        assert_eq!(result["fgmm_cause"], 21);
        assert_eq!(result["cause_name"], "Synch failure");
    }

    #[test]
    fn test_5gmm_auth_failure_truncated() {
        let pdu = [0x7E, 0x00, 0x59];
        let result = deep_parse_5gmm_auth_failure(&pdu);

        assert_eq!(result["error"], "truncated");
    }

    #[test]
    fn test_5gmm_sec_mode_reject() {
        // EPD=0x7E, SHT=0x00, MT=0x60, cause=24 (Security mode rejected unspecified)
        let pdu = [0x7E, 0x00, 0x60, 0x18];
        let result = deep_parse_5gmm_sec_mode_reject(&pdu);

        assert_eq!(result["fgmm_cause"], 24);
        assert_eq!(result["cause_name"], "Security mode rejected unspecified");
    }

    #[test]
    fn test_5gsm_release_command() {
        // EPD=0x2E, PDU_Session_ID=0x05, PTI=0x01, MT=0xD3, cause=36 (Regular deactivation)
        let pdu = [0x2E, 0x05, 0x01, 0xD3, 0x24];
        let result = deep_parse_5gsm_release_command(&pdu);

        assert_eq!(result["sm_cause"], 36);
        assert_eq!(result["cause_name"], "Regular deactivation");
    }

    #[test]
    fn test_5gsm_pdu_session_est_request() {
        // EPD=0x2E, PDU_Session_ID=0x01, PTI=0x00, MT=0xC1,
        // integrity_max_dr_ul=0xFF, integrity_max_dr_dl=0xFF,
        // PDU session type half-octet IE: 0x91 = IEI 0x9 + type 1 (IPv4)
        let pdu = [0x2E, 0x01, 0x00, 0xC1, 0xFF, 0xFF, 0x91];
        let result = deep_parse_5gsm_pdu_session_est_request(&pdu);

        assert_eq!(result["pdu_session_type"], 1);
        assert_eq!(result["pdu_session_type_name"], "IPv4");
    }
}
