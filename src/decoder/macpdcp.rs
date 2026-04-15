//! MAC, PDCP, and RLC basic structure decoders for NR and LTE
//!
//! Replaces placeholder ranges with basic structure parsing.
//! Extended with MCS/modulation extraction and scheduling log codes.

use super::phy;

/// Decode NR MAC log (0xB890-0xB8AF range)
pub fn decode_nr_mac(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    let log_name = match log_code {
        0xB890 => "NR_MAC_UL_TB",
        0xB891 => "NR_MAC_DL_TB",
        0xB893 => "NR_MAC_RACH",
        0xB894 => "NR_MAC_DL_Sched",
        0xB895 => "NR_MAC_UL_Sched",
        _ => return decode_nr_mac_generic(log_code, data),
    };

    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];

    match log_code {
        0xB890 | 0xB891 => decode_nr_mac_tb(log_code, data, version, log_name),
        0xB893 => decode_nr_mac_rach(data, version, log_name),
        0xB894 | 0xB895 => decode_nr_mac_sched(log_code, data, version, log_name),
        _ => {
            let decoded = serde_json::json!({
                "protocol": "NR-MAC",
                "log_name": log_name,
                "version": version,
                "raw_length": data.len(),
            });
            let summary = format!("{} v{} ({} bytes)", log_name, version, data.len());
            (Some(decoded), summary, true)
        }
    }
}

/// NR MAC UL/DL Transport Block (0xB890/0xB891)
///
/// Extended to extract MCS index, modulation, number of layers, NDI, and RV.
fn decode_nr_mac_tb(
    log_code: u16,
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-MAC",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let direction = if log_code == 0xB890 { "UL" } else { "DL" };
    let num_tbs = u16::from_le_bytes([data[2], data[3]]) as usize;
    let rnti = if data.len() >= 6 { Some(u16::from_le_bytes([data[4], data[5]])) } else { None };
    let harq_id = if data.len() >= 7 { Some(data[6]) } else { None };

    // MCS index at byte 7 (after harq_id)
    let mcs_index = if data.len() >= 8 { Some(data[7]) } else { None };

    // TB size at bytes 8-11
    let tb_size = if data.len() >= 12 {
        Some(u32::from_le_bytes([data[8], data[9], data[10], data[11]]))
    } else {
        None
    };

    // Number of layers / MIMO rank at byte 12
    let num_layers = if data.len() >= 13 { Some(data[12]) } else { None };

    // NDI (new data indicator) and RV (redundancy version) at byte 13
    let ndi = if data.len() >= 14 { Some(data[13] & 1) } else { None };
    let rv = if data.len() >= 14 { Some((data[13] >> 1) & 3) } else { None };

    // Derive modulation from MCS index
    let modulation = mcs_index.and_then(|mcs| {
        phy::nr_mcs_table1(mcs).map(|(m, _, _)| m)
    });

    let mut decoded = serde_json::json!({
        "protocol": "NR-MAC",
        "log_name": log_name,
        "version": version,
        "direction": direction,
        "num_tbs": num_tbs,
        "raw_length": data.len(),
    });

    if let Some(r) = rnti { decoded["rnti"] = serde_json::json!(r); }
    if let Some(h) = harq_id { decoded["harq_id"] = serde_json::json!(h); }
    if let Some(mcs) = mcs_index { decoded["mcs_index"] = serde_json::json!(mcs); }
    if let Some(m) = modulation { decoded["modulation"] = serde_json::json!(m); }
    if let Some(s) = tb_size { decoded["tb_size"] = serde_json::json!(s); }
    if let Some(nl) = num_layers {
        decoded["num_layers"] = serde_json::json!(nl);
        decoded["mimo_rank"] = serde_json::json!(phy::mimo_rank_name(nl));
    }
    if let Some(n) = ndi { decoded["ndi"] = serde_json::json!(n); }
    if let Some(r) = rv { decoded["rv"] = serde_json::json!(r); }

    let rnti_str = rnti.map_or(String::new(), |r| format!(" RNTI=0x{:04X}", r));
    let size_str = tb_size.map_or(String::new(), |s| format!(" {}B", s));
    let mcs_str = mcs_index.map_or(String::new(), |m| format!(" MCS={}", m));
    let mod_str = modulation.map_or(String::new(), |m| format!(" {}", m));
    let summary = format!(
        "NR MAC {} TBs={}{}{}{}{}",
        direction, num_tbs, rnti_str, size_str, mcs_str, mod_str
    );
    (Some(decoded), summary, true)
}

/// NR MAC DL/UL Scheduling Info (0xB894/0xB895)
///
/// Richer than TB logs — includes full scheduling grant details with MCS, RBs, NDI.
fn decode_nr_mac_sched(
    log_code: u16,
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 6 {
        let decoded = serde_json::json!({
            "protocol": "NR-MAC",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let direction = if log_code == 0xB894 { "DL" } else { "UL" };
    let num_grants = data[2] as usize;
    let carrier_id = data[3];

    let mut grants = Vec::new();
    let mut offset = 4;
    let grant_size = 12; // estimated

    for _ in 0..num_grants.min(8) {
        if offset + grant_size > data.len() {
            break;
        }

        let rnti = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let harq_id = data[offset + 2];
        let mcs = data[offset + 3];
        let num_rbs = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
        let tbs = u32::from_le_bytes([data[offset + 6], data[offset + 7], data[offset + 8], data[offset + 9]]);
        let ndi = data[offset + 10] & 1;
        let rv = (data[offset + 10] >> 1) & 3;

        let modulation = phy::nr_mcs_table1(mcs).map(|(m, _, _)| m).unwrap_or("unknown");

        // UL-specific: BSR/SR trigger flags at byte 11
        let bsr_trigger = if log_code == 0xB895 && offset + 12 <= data.len() {
            Some(data[offset + 11] & 1 != 0)
        } else {
            None
        };
        let sr_trigger = if log_code == 0xB895 && offset + 12 <= data.len() {
            Some(data[offset + 11] & 2 != 0)
        } else {
            None
        };

        let mut grant = serde_json::json!({
            "rnti": rnti,
            "harq_id": harq_id,
            "mcs": mcs,
            "modulation": modulation,
            "num_rbs": num_rbs,
            "tbs": tbs,
            "ndi": ndi,
            "rv": rv,
        });

        if let Some(bsr) = bsr_trigger { grant["bsr_trigger"] = serde_json::json!(bsr); }
        if let Some(sr) = sr_trigger { grant["sr_trigger"] = serde_json::json!(sr); }

        grants.push(grant);
        offset += grant_size;
    }

    let avg_mcs = if !grants.is_empty() {
        let sum: u32 = grants.iter()
            .filter_map(|g| g.get("mcs").and_then(|v| v.as_u64()))
            .map(|v| v as u32)
            .sum();
        sum as f64 / grants.len() as f64
    } else {
        0.0
    };

    let decoded = serde_json::json!({
        "protocol": "NR-MAC",
        "log_name": log_name,
        "version": version,
        "direction": direction,
        "carrier_id": carrier_id,
        "num_grants": num_grants,
        "grants": grants,
        "avg_mcs": (avg_mcs * 10.0).round() / 10.0,
        "raw_length": data.len(),
    });

    let summary = format!(
        "NR MAC {} Sched {} grants MCS_avg={:.1}",
        direction, grants.len(), avg_mcs
    );
    (Some(decoded), summary, !grants.is_empty())
}

/// NR MAC RACH (0xB893)
fn decode_nr_mac_rach(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-MAC",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let preamble_index = data[4];
    let timing_advance = if data.len() >= 8 {
        Some(u16::from_le_bytes([data[6], data[7]]))
    } else {
        None
    };
    let result = if data.len() >= 9 { Some(data[8]) } else { None };
    let result_name = result.map(|r| match r {
        0 => "success",
        1 => "failure",
        _ => "unknown",
    });

    let decoded = serde_json::json!({
        "protocol": "NR-MAC",
        "log_name": log_name,
        "version": version,
        "preamble_index": preamble_index,
        "timing_advance": timing_advance,
        "result": result,
        "result_name": result_name,
        "raw_length": data.len(),
    });

    let result_str = result_name.unwrap_or("?");
    let summary = format!(
        "NR MAC RACH preamble={} TA={} {}",
        preamble_index,
        timing_advance.unwrap_or(0),
        result_str
    );
    (Some(decoded), summary, true)
}

/// Generic NR MAC decoder for unrecognized sub-codes
fn decode_nr_mac_generic(
    log_code: u16,
    data: &[u8],
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 2 {
        return (None, format!("NR MAC 0x{:04X} ({} bytes)", log_code, data.len()), false);
    }

    let version = data[0];
    let decoded = serde_json::json!({
        "protocol": "NR-MAC",
        "log_code": format!("0x{:04X}", log_code),
        "version": version,
        "raw_length": data.len(),
    });
    let summary = format!("NR MAC 0x{:04X} v{} ({} bytes)", log_code, version, data.len());
    (Some(decoded), summary, true)
}

/// Decode NR PDCP log (0xB840-0xB84F range)
pub fn decode_nr_pdcp(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    let log_name = match log_code {
        0xB840 => "NR_PDCP_UL_Stats",
        0xB841 => "NR_PDCP_DL_Stats",
        0xB842 => "NR_PDCP_UL_Config",
        0xB843 => "NR_PDCP_DL_Config",
        _ => "NR_PDCP_Unknown",
    };

    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];
    let direction = if log_code & 1 == 0 { "UL" } else { "DL" };

    // For config logs, try to extract security algorithm info
    let (cipher_algo, integrity_algo) = if (log_code == 0xB842 || log_code == 0xB843) && data.len() >= 6 {
        // PDCP config typically has cipher + integrity algo fields
        let cipher = if data[4] <= 3 { Some(data[4]) } else { None };
        let integrity = if data[5] <= 3 { Some(data[5]) } else { None };
        (cipher, integrity)
    } else {
        (None, None)
    };

    // For stats logs, extract PDU count if available
    let pdu_count = if (log_code == 0xB840 || log_code == 0xB841) && data.len() >= 8 {
        Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
    } else {
        None
    };

    let bearer_id = if data.len() >= 4 { Some(data[2]) } else { None };

    let mut decoded = serde_json::json!({
        "protocol": "NR-PDCP",
        "log_name": log_name,
        "version": version,
        "direction": direction,
        "raw_length": data.len(),
    });

    if let Some(b) = bearer_id { decoded["bearer_id"] = serde_json::json!(b); }
    if let Some(c) = cipher_algo {
        let name = match c {
            0 => "NEA0 (null)", 1 => "128-NEA1", 2 => "128-NEA2", 3 => "128-NEA3", _ => "?",
        };
        decoded["cipher_algo"] = serde_json::json!(c);
        decoded["cipher_name"] = serde_json::json!(name);
    }
    if let Some(i) = integrity_algo {
        let name = match i {
            0 => "NIA0 (null)", 1 => "128-NIA1", 2 => "128-NIA2", 3 => "128-NIA3", _ => "?",
        };
        decoded["integrity_algo"] = serde_json::json!(i);
        decoded["integrity_name"] = serde_json::json!(name);
    }
    if let Some(p) = pdu_count { decoded["pdu_count"] = serde_json::json!(p); }

    let algo_str = cipher_algo.map_or(String::new(), |c| format!(" NEA{}", c));
    let count_str = pdu_count.map_or(String::new(), |c| format!(" pdus={}", c));
    let summary = format!("{} {} v{}{}{}",
        log_name, direction, version, algo_str, count_str);
    (Some(decoded), summary, true)
}

/// Decode NR RLC log (0xB850-0xB85F range)
pub fn decode_nr_rlc(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    let log_name = match log_code {
        0xB850 => "NR_RLC_UL_Stats",
        0xB851 => "NR_RLC_DL_Stats",
        _ => "NR_RLC_Unknown",
    };

    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];
    let direction = if log_code & 1 == 0 { "UL" } else { "DL" };
    let bearer_id = data[2];

    // RLC mode at byte 3 (0=TM, 1=UM, 2=AM)
    let mode = if data.len() >= 4 { Some(data[3]) } else { None };
    let mode_name = mode.map(|m| match m {
        0 => "TM",
        1 => "UM",
        2 => "AM",
        _ => "?",
    });

    // PDU count at bytes 4-7 if available
    let pdu_count = if data.len() >= 8 {
        Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
    } else {
        None
    };

    let mut decoded = serde_json::json!({
        "protocol": "NR-RLC",
        "log_name": log_name,
        "version": version,
        "direction": direction,
        "bearer_id": bearer_id,
        "raw_length": data.len(),
    });

    if let Some(m) = mode_name { decoded["mode"] = serde_json::json!(m); }
    if let Some(p) = pdu_count { decoded["pdu_count"] = serde_json::json!(p); }

    let mode_str = mode_name.unwrap_or("?");
    let count_str = pdu_count.map_or(String::new(), |c| format!(" pdus={}", c));
    let summary = format!(
        "{} {} bearer={} mode={}{}",
        log_name, direction, bearer_id, mode_str, count_str
    );
    (Some(decoded), summary, true)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nr_mac_ul_tb() {
        let mut data = vec![0u8; 14];
        data[0] = 3; // version
        data[2] = 2; data[3] = 0; // num_tbs=2
        data[4] = 0x34; data[5] = 0x12; // RNTI=0x1234
        data[6] = 5; // HARQ=5
        data[7] = 15; // MCS=15
        data[8] = 0x00; data[9] = 0x04; data[10] = 0; data[11] = 0; // TB size=1024
        data[12] = 2; // num_layers=2
        data[13] = 1; // ndi=1, rv=0

        let (decoded, summary, fully) = decode_nr_mac(0xB890, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["direction"], "UL");
        assert_eq!(d["num_tbs"], 2);
        assert_eq!(d["rnti"], 0x1234);
        assert_eq!(d["harq_id"], 5);
        assert_eq!(d["mcs_index"], 15);
        assert_eq!(d["modulation"], "16QAM");
        assert_eq!(d["num_layers"], 2);
        assert_eq!(d["ndi"], 1);
        assert!(summary.contains("UL"));
        assert!(summary.contains("MCS=15"));
    }

    #[test]
    fn test_nr_mac_dl_sched() {
        let mut data = vec![0u8; 16];
        data[0] = 1; // version
        data[2] = 1; // num_grants=1
        data[3] = 0; // carrier_id
        // Grant at offset 4:
        data[4] = 0x34; data[5] = 0x12; // rnti
        data[6] = 3; // harq_id
        data[7] = 20; // mcs=20 (64QAM)
        data[8] = 50; data[9] = 0; // num_rbs=50
        data[10] = 0; data[11] = 0x10; data[12] = 0; data[13] = 0; // tbs=4096
        data[14] = 1; // ndi=1, rv=0
        data[15] = 0;

        let (decoded, summary, fully) = decode_nr_mac(0xB894, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["direction"], "DL");
        assert_eq!(d["num_grants"], 1);
        assert!(summary.contains("Sched"));
    }

    #[test]
    fn test_nr_mac_rach() {
        let mut data = vec![0u8; 9];
        data[0] = 2; // version
        data[4] = 42; // preamble_index=42
        data[6] = 10; data[7] = 0; // timing_advance=10
        data[8] = 0; // result=success

        let (decoded, summary, fully) = decode_nr_mac(0xB893, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["preamble_index"], 42);
        assert_eq!(d["result_name"], "success");
        assert!(summary.contains("preamble=42"));
    }

    #[test]
    fn test_nr_pdcp_stats() {
        let mut data = vec![0u8; 8];
        data[0] = 1; // version
        data[2] = 3; // bearer_id=3
        data[4] = 0xE8; data[5] = 0x03; data[6] = 0; data[7] = 0; // pdu_count=1000

        let (decoded, summary, fully) = decode_nr_pdcp(0xB840, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["direction"], "UL");
        assert_eq!(d["pdu_count"], 1000);
        assert!(summary.contains("pdus=1000"));
    }

    #[test]
    fn test_nr_rlc_stats() {
        let mut data = vec![0u8; 8];
        data[0] = 2; // version
        data[2] = 1; // bearer_id=1
        data[3] = 2; // mode=AM
        data[4] = 0x64; data[5] = 0; data[6] = 0; data[7] = 0; // pdu_count=100

        let (decoded, summary, fully) = decode_nr_rlc(0xB850, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["mode"], "AM");
        assert_eq!(d["pdu_count"], 100);
        assert!(summary.contains("mode=AM"));
    }

    #[test]
    fn test_truncated_mac() {
        let data = [0u8; 2]; // too short
        let (_, _, fully) = decode_nr_mac(0xB890, &data);
        assert!(!fully);
    }
}
