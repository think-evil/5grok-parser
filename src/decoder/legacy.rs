//! Legacy log code decoders (0x1xxx range — Qualcomm older/variant formats)

use super::metadata::{
    earfcn_to_band, emm_state_name, emm_substate_name, extract_ascii_string, lte_rrc_channel_name,
    nr_arfcn_to_band,
};

/// Decode NR RRC OTA v1 (log code 0x1D0B)
/// Version 6 layout (from empirical analysis of 55 captured frames, 388 bytes each):
///   [version:u32][nr_arfcn:u32][time_ref:u32][channel_type:u32]
///   [rsrp_raw:u16][pad:u16][secondary:u32][rsrq_raw:u16][pad:u16]
///   [rrc_pdu...]
///
/// RSRP formula: raw_u16 / 64.0 - 140.0 → dBm (validated: 3112→-91.4, 5701→-50.9)
/// Channel type: 0=BCCH-BCH, 1=BCCH-DL-SCH, 2=DCCH, 3=DCCH-UL, 4=PCCH
pub fn decode_nr_rrc_ota_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 16 {
        return (None, format!("NR RRC OTA v1: too short ({} bytes)", data.len()), false);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let nr_arfcn = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let time_ref = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let channel_type = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    let channel = match channel_type {
        0 => "BCCH-BCH",
        1 => "BCCH-DL-SCH",
        2 => "DCCH",
        3 => "DCCH-UL",
        4 => "PCCH",
        _ => "Unknown",
    };
    let direction = if channel_type == 3 { "UL" } else { "DL" };

    let band = nr_arfcn_to_band(nr_arfcn);

    // Extract RSRP from u16 at offset [16-17], formula: val / 64.0 - 140.0 dBm
    let mut rsrp_dbm: Option<f64> = None;
    let mut rsrp_raw: Option<u16> = None;
    if data.len() >= 18 {
        let raw = u16::from_le_bytes([data[16], data[17]]);
        if raw > 0 {
            rsrp_raw = Some(raw);
            rsrp_dbm = Some(raw as f64 / 64.0 - 140.0);
        }
    }

    // Extract secondary RSRP/RSRQ from u16 at offset [24-25]
    let mut rsrq_dbm: Option<f64> = None;
    let mut rsrq_raw: Option<u16> = None;
    if data.len() >= 26 {
        let raw = u16::from_le_bytes([data[24], data[25]]);
        if raw > 0 {
            rsrq_raw = Some(raw);
            rsrq_dbm = Some(raw as f64 / 64.0 - 140.0);
        }
    }

    // RRC PDU starts after the measurement fields (offset ~28+)
    let pdu_offset = 28usize;
    let has_pdu = data.len() > pdu_offset && data[pdu_offset..].iter().any(|&b| b != 0);

    let decoded = serde_json::json!({
        "protocol": "NR-RRC",
        "version": version,
        "nr_arfcn": nr_arfcn,
        "band": band,
        "direction": direction,
        "channel": channel,
        "time_ref": time_ref,
        "rsrp_raw": rsrp_raw,
        "rsrp_dbm": rsrp_dbm,
        "rsrq_raw": rsrq_raw,
        "rsrq_dbm": rsrq_dbm,
        "has_rrc_pdu": has_pdu,
        "raw_length": data.len(),
    });

    let rsrp_str = rsrp_dbm.map_or(String::new(), |v| format!(" RSRP={:.1}dBm", v));
    let summary = format!(
        "NR RRC {} {} ARFCN={} {}{}",
        direction, channel, nr_arfcn, band, rsrp_str
    );
    (Some(decoded), summary, true)
}

/// Decode LTE RRC OTA v1 (log code 0x11EB)
pub fn decode_lte_rrc_ota_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 12 {
        return (None, format!("LTE RRC OTA v1: too short ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let bearer_id = data[3];
    let pci = u16::from_le_bytes([data[4], data[5]]);
    let earfcn = u16::from_le_bytes([data[6], data[7]]);
    let sfn = u16::from_le_bytes([data[8], data[9]]);

    let channel = lte_rrc_channel_name(bearer_id);
    let direction = if bearer_id & 0x10 != 0 { "UL" } else { "DL" };
    let band = earfcn_to_band(earfcn as u32);

    let decoded = serde_json::json!({
        "protocol": "LTE-RRC",
        "version": version,
        "direction": direction,
        "channel": channel,
        "pci": pci,
        "earfcn": earfcn,
        "band": band,
        "sfn": sfn,
        "raw_length": data.len(),
    });

    let summary = format!(
        "LTE RRC {} {} PCI={} EARFCN={} {} SFN={}",
        direction, channel, pci, earfcn, band, sfn
    );
    (Some(decoded), summary, true)
}

/// Decode LTE RRC Reconfiguration v1 (log code 0x184C)
pub fn decode_lte_rrc_reconf_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 16 {
        return (None, format!("LTE RRC Reconfig v1: too short ({} bytes)", data.len()), false);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let sfn = u16::from_le_bytes([data[8], data[9]]);
    let sfn_valid = sfn <= 1023;
    let sub_id = data[10];
    let num_bearers = data[14];
    let bearer_type = data[15];

    let mut security_info = None;
    if data.len() > 20 {
        for i in 16..data.len().saturating_sub(2) {
            if data[i] == 0xFF && data[i + 1] <= 3 && data[i + 2] <= 3 {
                let cipher = data[i + 1];
                let integrity = data[i + 2];
                security_info = Some(serde_json::json!({
                    "offset": i,
                    "cipher_algo_id": cipher,
                    "cipher_algo": format!("EEA{}", cipher),
                    "integrity_algo_id": integrity,
                    "integrity_algo": format!("EIA{}", integrity),
                    "null_cipher": cipher == 0,
                    "null_integrity": integrity == 0,
                }));
                break;
            }
        }
    }

    let is_endc_candidate = num_bearers >= 3 && data.len() > 200;

    let decoded = serde_json::json!({
        "protocol": "LTE-RRC",
        "message": "RRC Reconfiguration",
        "version": version,
        "sfn": sfn,
        "sfn_valid": sfn_valid,
        "sub_id": sub_id,
        "num_bearers": num_bearers,
        "bearer_type": bearer_type,
        "security": security_info,
        "endc_candidate": is_endc_candidate,
        "raw_length": data.len(),
    });

    let sec_str = security_info
        .as_ref()
        .and_then(|s| s.get("cipher_algo"))
        .and_then(|v| v.as_str())
        .map(|a| format!(" sec={}", a))
        .unwrap_or_default();
    let endc_str = if is_endc_candidate { " [EN-DC?]" } else { "" };
    let summary = format!(
        "LTE RRC Reconfig v{} SFN={} bearers={}{}{}",
        version, sfn, num_bearers, sec_str, endc_str
    );
    (Some(decoded), summary, true)
}

/// Decode LTE RRC Serving Cell v1 (log code 0x1849)
pub fn decode_lte_rrc_srv_cell_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 18 {
        return (None, format!("LTE RRC Srv Cell v1: too short ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let sub_version = data[1];
    let dl_earfcn = u16::from_le_bytes([data[4], data[5]]);
    let band = earfcn_to_band(dl_earfcn as u32);

    let ul_earfcn = if data.len() >= 8 {
        Some(u16::from_le_bytes([data[6], data[7]]))
    } else {
        None
    };

    let dl_bw = if data.len() > 8 { Some(data[8]) } else { None };
    let _ul_bw = if data.len() > 9 { Some(data[9]) } else { None };

    let cell_id = if data.len() >= 14 {
        Some(u32::from_le_bytes([data[10], data[11], data[12], data[13]]))
    } else {
        None
    };

    let tac = if data.len() >= 16 {
        Some(u16::from_le_bytes([data[14], data[15]]))
    } else {
        None
    };

    let pci = if data.len() >= 18 {
        let v = u16::from_le_bytes([data[16], data[17]]);
        if v <= 503 { Some(v) } else { None }
    } else {
        None
    };

    let reported_band = if data.len() >= 22 {
        let b = u32::from_le_bytes([data[18], data[19], data[20], data[21]]);
        if b > 0 && b <= 256 { Some(b) } else { None }
    } else {
        None
    };

    let mcc = if data.len() >= 24 {
        let v = u16::from_le_bytes([data[22], data[23]]);
        if v >= 100 && v <= 999 { Some(v) } else { None }
    } else {
        None
    };

    let mnc = if data.len() >= 27 {
        let mnc_digits = data[24];
        let mnc_val = u16::from_le_bytes([data[25], data[26]]);
        if mnc_digits == 2 || mnc_digits == 3 {
            Some((mnc_digits, mnc_val))
        } else {
            None
        }
    } else {
        None
    };

    let bandwidth_mhz = match dl_bw {
        Some(bw) if matches!(bw, 1 | 3 | 5 | 10 | 15 | 20) => Some(bw),
        _ => tac.and_then(|t| if matches!(t, 1 | 3 | 5 | 10 | 15 | 20) { Some(t as u8) } else { None }),
    };

    let decoded = serde_json::json!({
        "protocol": "LTE-RRC",
        "message": "Serving Cell Info",
        "version": version,
        "sub_version": sub_version,
        "dl_earfcn": dl_earfcn,
        "ul_earfcn": ul_earfcn,
        "band": band,
        "reported_band": reported_band,
        "pci": pci,
        "cell_id": cell_id,
        "tac": tac,
        "dl_bandwidth_mhz": bandwidth_mhz,
        "mcc": mcc,
        "mnc": mnc.map(|(d, v)| serde_json::json!({"digits": d, "value": v})),
        "raw_length": data.len(),
    });

    let pci_str = pci.map_or("?".to_string(), |p| p.to_string());
    let bw_str = bandwidth_mhz.map_or(String::new(), |b| format!(" {}MHz", b));
    let tac_str = tac.map_or(String::new(), |t| format!(" TAC={}", t));
    let summary = format!(
        "LTE Srv Cell PCI={} EARFCN={} {}{}{}",
        pci_str, dl_earfcn, band, bw_str, tac_str
    );
    (Some(decoded), summary, true)
}

/// Decode LTE NAS EMM State v1 (log code 0x1951)
pub fn decode_lte_nas_emm_state_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 3 {
        return (None, "LTE NAS EMM State v1: too short".into(), false);
    }

    let version = data[0];

    // Version 0x22 (34): extended format with APN and network name
    if version == 0x22 && data.len() >= 10 {
        let emm_state = data[1];
        let emm_substate = data[2];

        let state_name = emm_state_name(emm_state);
        let substate_name = emm_substate_name(emm_substate);

        let apn = extract_ascii_string(&data[3..], 64);

        let network_name = if data.len() > 35 {
            extract_ascii_string(&data[35..], 32)
        } else {
            String::new()
        };

        let decoded = serde_json::json!({
            "protocol": "EMM",
            "message": "EMM State",
            "version": version,
            "emm_state": emm_state,
            "emm_state_name": state_name,
            "emm_substate": emm_substate,
            "emm_substate_name": substate_name,
            "apn": apn.trim(),
            "network_name": network_name.trim(),
            "raw_length": data.len(),
        });

        let summary = format!(
            "EMM {} ({}) APN=\"{}\" net=\"{}\"",
            state_name, substate_name, apn.trim(), network_name.trim()
        );
        return (Some(decoded), summary, true);
    }

    // Version 3: compact EMM state
    if version == 3 && data.len() >= 5 {
        let emm_state = data[1];
        let emm_substate = data[2];
        let emm_cause = data[3];
        let _flag = data[4];

        let state_name = emm_state_name(emm_state);
        let substate_name = emm_substate_name(emm_substate);

        let cipher_algo = if data.len() >= 12 { Some(data[11]) } else { None };

        let decoded = serde_json::json!({
            "protocol": "EMM",
            "message": "EMM State",
            "version": version,
            "emm_state": emm_state,
            "emm_state_name": state_name,
            "emm_substate": emm_substate,
            "emm_substate_name": substate_name,
            "emm_cause": emm_cause,
            "cipher_algo": cipher_algo,
            "raw_length": data.len(),
        });

        let summary = format!("EMM {} ({}) cause=0x{:02X}", state_name, substate_name, emm_cause);
        return (Some(decoded), summary, true);
    }

    // Generic version
    let decoded = serde_json::json!({
        "protocol": "EMM",
        "message": "EMM State",
        "version": version,
        "raw_length": data.len(),
    });
    let summary = format!("EMM State v{} ({} bytes)", version, data.len());
    (Some(decoded), summary, false)
}

/// Decode NR ML1 measurement logs v1 (log codes 0x1C6E-0x1C72)
pub fn decode_nr_ml1_v1(
    log_code: u16,
    log_name: &str,
    data: &[u8],
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];

    // NR-ARFCN as u24 LE at bytes [1-3]
    let nr_arfcn = if data.len() >= 4 {
        data[1] as u32 | ((data[2] as u32) << 8) | ((data[3] as u32) << 16)
    } else {
        0
    };

    let band = if nr_arfcn > 0 && nr_arfcn < 4000000 {
        nr_arfcn_to_band(nr_arfcn)
    } else {
        "N/A".into()
    };

    let mut meas_fields = serde_json::Map::new();

    // For 0x1C6E (Serving Meas), extract detailed fields
    if log_code == 0x1C6E && data.len() >= 24 {
        if data.len() > 8 {
            meas_fields.insert("num_carriers".into(), (data[8] as u64).into());
        }
        if data.len() > 13 {
            meas_fields.insert("ssb_index".into(), (data[13] as u64).into());
        }
        if data.len() >= 16 {
            let pci = u16::from_le_bytes([data[14], data[15]]);
            if pci <= 1007 {
                meas_fields.insert("pci".into(), (pci as u64).into());
            }
        }
        if data.len() >= 20 {
            let arfcn2 = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
            if arfcn2 > 0 && arfcn2 < 4000000 {
                meas_fields.insert("secondary_arfcn".into(), arfcn2.into());
                meas_fields.insert(
                    "secondary_band".into(),
                    serde_json::Value::String(nr_arfcn_to_band(arfcn2)),
                );
            }
        }
        if data.len() >= 24 {
            let arfcn3 = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
            if arfcn3 > 0 && arfcn3 < 4000000 {
                meas_fields.insert("tertiary_arfcn".into(), arfcn3.into());
                meas_fields.insert(
                    "tertiary_band".into(),
                    serde_json::Value::String(nr_arfcn_to_band(arfcn3)),
                );
            }
        }
        if data.len() >= 31 {
            let meas1 = u16::from_le_bytes([data[29], data[30]]);
            if meas1 > 0 {
                meas_fields.insert("meas_raw_1".into(), (meas1 as u64).into());
            }
        }
        if data.len() >= 39 {
            let meas2 = u16::from_le_bytes([data[37], data[38]]);
            if meas2 > 0 {
                meas_fields.insert("meas_raw_2".into(), (meas2 as u64).into());
            }
        }
        if data.len() >= 43 {
            let meas3 = u16::from_le_bytes([data[41], data[42]]);
            if meas3 > 0 {
                meas_fields.insert("meas_raw_3".into(), (meas3 as u64).into());
            }
        }
    }

    // For 0x1C70 (Searcher), extract PCI candidates
    if log_code == 0x1C70 && data.len() >= 16 {
        let pci = u16::from_le_bytes([data[14], data[15]]);
        if pci > 0 && pci <= 1007 {
            meas_fields.insert("pci".into(), (pci as u64).into());
        }
    }

    // For 0x1C71 (RRC Meas), extract measurement report fields
    if log_code == 0x1C71 && data.len() >= 16 {
        let pci = u16::from_le_bytes([data[14], data[15]]);
        if pci > 0 && pci <= 1007 {
            meas_fields.insert("pci".into(), (pci as u64).into());
        }
    }

    // For 0x1C72 (Beam Mgmt), extract beam/SSB info
    if log_code == 0x1C72 && data.len() >= 16 {
        if data.len() > 8 {
            meas_fields.insert("num_beams".into(), (data[8] as u64).into());
        }
        let pci = u16::from_le_bytes([data[14], data[15]]);
        if pci > 0 && pci <= 1007 {
            meas_fields.insert("pci".into(), (pci as u64).into());
        }
    }

    // For 0x1C6F (Neighbor Meas), extract neighbor info
    if log_code == 0x1C6F && data.len() >= 16 {
        if data.len() > 8 {
            meas_fields.insert("num_neighbors".into(), (data[8] as u64).into());
        }
        let pci = u16::from_le_bytes([data[14], data[15]]);
        if pci > 0 && pci <= 1007 {
            meas_fields.insert("pci".into(), (pci as u64).into());
        }
    }

    let pci_str = meas_fields
        .get("pci")
        .and_then(|v| v.as_u64())
        .map(|p| format!(" PCI={}", p))
        .unwrap_or_default();

    let decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "nr_arfcn": nr_arfcn,
        "band": band,
        "measurements": meas_fields,
        "raw_length": data.len(),
    });

    let summary = format!(
        "{} v{} ARFCN={} {}{}",
        log_name, version, nr_arfcn, band, pci_str
    );
    (Some(decoded), summary, true)
}

/// Decode LTE PDCCH Decode log (log code 0x1874)
pub fn decode_lte_pdcch(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 5 {
        return (None, format!("LTE PDCCH ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let num_cc = data[3];
    let num_records = data[4];

    let sfn = if data.len() >= 8 {
        let raw = u16::from_le_bytes([data[5], data[6]]);
        let sfn_val = raw >> 4;
        if sfn_val <= 1023 { Some(sfn_val) } else { None }
    } else {
        None
    };

    let timing = if data.len() >= 24 {
        Some(u16::from_le_bytes([data[22], data[23]]))
    } else {
        None
    };

    let earfcn = if data.len() >= 28 {
        let raw = data[25] as u32 | ((data[26] as u32) << 8) | ((data[27] as u32) << 16);
        if raw > 0 && raw < 70000 { Some(raw) } else { None }
    } else {
        None
    };

    let band = earfcn.map_or("N/A".into(), earfcn_to_band);

    let decoded = serde_json::json!({
        "protocol": "LTE-PHY",
        "log_name": "LTE_PDCCH_Decode",
        "version": version,
        "num_cc": num_cc,
        "num_records": num_records,
        "sfn": sfn,
        "timing": timing,
        "earfcn": earfcn,
        "band": band,
        "raw_length": data.len(),
    });

    let earfcn_str = earfcn.map_or(String::new(), |e| format!(" EARFCN={}", e));
    let sfn_str = sfn.map_or(String::new(), |s| format!(" SFN={}", s));
    let summary = format!(
        "LTE PDCCH v{} {}CC recs={}{}{}",
        version, num_cc, num_records, sfn_str, earfcn_str
    );
    (Some(decoded), summary, true)
}

/// Decode LTE MAC UL TB v1 (log code 0x18F7)
pub fn decode_lte_mac_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("LTE MAC v1 ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let num_samples = if data.len() >= 4 {
        u16::from_le_bytes([data[2], data[3]])
    } else {
        0
    };

    let decoded = serde_json::json!({
        "protocol": "LTE-MAC",
        "log_name": "LTE_MAC_UL_TB_v1",
        "version": version,
        "num_samples": num_samples,
        "raw_length": data.len(),
    });

    let summary = format!("LTE MAC UL TB v{} samples={} ({} bytes)", version, num_samples, data.len());
    (Some(decoded), summary, true)
}

/// Decode LTE PDCP DL Config v1 (log code 0x14D8)
pub fn decode_lte_pdcp_v1(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("LTE PDCP v1 ({} bytes)", data.len()), false);
    }

    let version = data[0];

    let mut cipher_algo = None;
    let mut integrity_algo = None;
    if data.len() >= 8 {
        for i in 2..data.len().saturating_sub(1) {
            if data[i] <= 3 && data[i + 1] <= 3 && i > 2 {
                cipher_algo = Some(data[i]);
                integrity_algo = Some(data[i + 1]);
                break;
            }
        }
    }

    let decoded = serde_json::json!({
        "protocol": "LTE-PDCP",
        "log_name": "LTE_PDCP_DL_Config_v1",
        "version": version,
        "cipher_algo": cipher_algo,
        "integrity_algo": integrity_algo,
        "raw_length": data.len(),
    });

    let algo_str = cipher_algo.map_or("?".into(), |a| format!("EEA{}", a));
    let summary = format!("LTE PDCP DL Config v{} cipher={} ({} bytes)", version, algo_str, data.len());
    (Some(decoded), summary, true)
}

/// Decode NR misc log v1 (log code 0x1850 = NR Serving Cell / Band Combo)
pub fn decode_nr_misc_v1(
    _log_code: u16,
    log_name: &str,
    data: &[u8],
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let nr_arfcn = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let band = if nr_arfcn > 0 { nr_arfcn_to_band(nr_arfcn) } else { "N/A".into() };

    let num_records = if data.len() >= 16 {
        u32::from_le_bytes([data[12], data[13], data[14], data[15]])
    } else {
        0
    };

    let decoded = serde_json::json!({
        "protocol": "NR-RRC",
        "log_name": log_name,
        "version": version,
        "nr_arfcn": nr_arfcn,
        "band": band,
        "num_records": num_records,
        "raw_length": data.len(),
    });

    let summary = format!("{} v{} ARFCN={} {} recs={}", log_name, version, nr_arfcn, band, num_records);
    (Some(decoded), summary, true)
}

/// Decode common timer/utility log (log code 0x0098)
pub fn decode_common_timer(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("Common 0x0098 ({} bytes)", data.len()), false);
    }

    let decoded = serde_json::json!({
        "protocol": "System",
        "log_name": "System_Timer",
        "raw_length": data.len(),
    });

    let summary = format!("System Timer ({} bytes)", data.len());
    (Some(decoded), summary, true)
}
