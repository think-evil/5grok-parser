//! PHY layer decoders — NR and LTE physical layer log codes
//!
//! Includes MCS/CQI lookup tables (3GPP TS 38.214, TS 36.213) and
//! decoders for PDSCH, PUSCH, PDCCH, PUCCH statistics.

use serde_json::json;

// ============================================================================
// MCS LOOKUP TABLES (TS 38.214)
// ============================================================================

/// NR MCS Table 1 (64QAM, TS 38.214 Table 5.1.3.1-1)
/// Returns (modulation, target_code_rate_x1024, spectral_efficiency)
pub fn nr_mcs_table1(index: u8) -> Option<(&'static str, u16, f64)> {
    match index {
        0  => Some(("QPSK",   120, 0.2344)),
        1  => Some(("QPSK",   157, 0.3066)),
        2  => Some(("QPSK",   193, 0.3770)),
        3  => Some(("QPSK",   251, 0.4902)),
        4  => Some(("QPSK",   308, 0.6016)),
        5  => Some(("QPSK",   379, 0.7402)),
        6  => Some(("QPSK",   449, 0.8770)),
        7  => Some(("QPSK",   526, 1.0273)),
        8  => Some(("QPSK",   602, 1.1758)),
        9  => Some(("QPSK",   679, 1.3262)),
        10 => Some(("16QAM",  340, 1.3281)),
        11 => Some(("16QAM",  378, 1.4766)),
        12 => Some(("16QAM",  434, 1.6953)),
        13 => Some(("16QAM",  490, 1.9141)),
        14 => Some(("16QAM",  553, 2.1602)),
        15 => Some(("16QAM",  616, 2.4063)),
        16 => Some(("16QAM",  658, 2.5703)),
        17 => Some(("64QAM",  438, 2.5664)),
        18 => Some(("64QAM",  466, 2.7305)),
        19 => Some(("64QAM",  517, 3.0293)),
        20 => Some(("64QAM",  567, 3.3223)),
        21 => Some(("64QAM",  616, 3.6094)),
        22 => Some(("64QAM",  666, 3.9023)),
        23 => Some(("64QAM",  719, 4.2129)),
        24 => Some(("64QAM",  772, 4.5234)),
        25 => Some(("64QAM",  822, 4.8164)),
        26 => Some(("64QAM",  873, 5.1152)),
        27 => Some(("64QAM",  910, 5.3320)),
        28 => Some(("64QAM",  948, 5.5547)),
        _ => None, // 29-31 reserved for retransmission
    }
}

/// NR MCS Table 2 (256QAM, TS 38.214 Table 5.1.3.1-2)
pub fn nr_mcs_table2(index: u8) -> Option<(&'static str, u16, f64)> {
    match index {
        0  => Some(("QPSK",    120, 0.2344)),
        1  => Some(("QPSK",    193, 0.3770)),
        2  => Some(("QPSK",    308, 0.6016)),
        3  => Some(("QPSK",    449, 0.8770)),
        4  => Some(("QPSK",    602, 1.1758)),
        5  => Some(("16QAM",   378, 1.4766)),
        6  => Some(("16QAM",   434, 1.6953)),
        7  => Some(("16QAM",   490, 1.9141)),
        8  => Some(("16QAM",   553, 2.1602)),
        9  => Some(("16QAM",   616, 2.4063)),
        10 => Some(("16QAM",   658, 2.5703)),
        11 => Some(("64QAM",   466, 2.7305)),
        12 => Some(("64QAM",   517, 3.0293)),
        13 => Some(("64QAM",   567, 3.3223)),
        14 => Some(("64QAM",   616, 3.6094)),
        15 => Some(("64QAM",   666, 3.9023)),
        16 => Some(("64QAM",   719, 4.2129)),
        17 => Some(("64QAM",   772, 4.5234)),
        18 => Some(("64QAM",   822, 4.8164)),
        19 => Some(("64QAM",   873, 5.1152)),
        20 => Some(("256QAM",  682, 5.3320)),
        21 => Some(("256QAM",  711, 5.5547)),
        22 => Some(("256QAM",  754, 5.8906)),
        23 => Some(("256QAM",  797, 6.2266)),
        24 => Some(("256QAM",  841, 6.5703)),
        25 => Some(("256QAM",  885, 6.9141)),
        26 => Some(("256QAM",  916, 7.1602)),
        27 => Some(("256QAM",  948, 7.4063)),
        _ => None,
    }
}

/// LTE MCS Table (TS 36.213 Table 7.1.7.1-1)
/// Returns (modulation, tbs_index)
pub fn lte_mcs_table(index: u8) -> Option<(&'static str, u8)> {
    match index {
        0  => Some(("QPSK",   0)),
        1  => Some(("QPSK",   1)),
        2  => Some(("QPSK",   2)),
        3  => Some(("QPSK",   3)),
        4  => Some(("QPSK",   4)),
        5  => Some(("QPSK",   5)),
        6  => Some(("QPSK",   6)),
        7  => Some(("QPSK",   7)),
        8  => Some(("QPSK",   8)),
        9  => Some(("QPSK",   9)),
        10 => Some(("16QAM",  9)),
        11 => Some(("16QAM",  10)),
        12 => Some(("16QAM",  11)),
        13 => Some(("16QAM",  12)),
        14 => Some(("16QAM",  13)),
        15 => Some(("16QAM",  14)),
        16 => Some(("16QAM",  15)),
        17 => Some(("64QAM",  15)),
        18 => Some(("64QAM",  16)),
        19 => Some(("64QAM",  17)),
        20 => Some(("64QAM",  18)),
        21 => Some(("64QAM",  19)),
        22 => Some(("64QAM",  20)),
        23 => Some(("64QAM",  21)),
        24 => Some(("64QAM",  22)),
        25 => Some(("64QAM",  23)),
        26 => Some(("64QAM",  24)),
        27 => Some(("64QAM",  25)),
        28 => Some(("64QAM",  26)),
        _ => None, // 29-31 reserved
    }
}

// ============================================================================
// CQI LOOKUP TABLES (TS 38.214 / TS 36.213)
// ============================================================================

/// NR CQI Table 1 (4-bit, TS 38.214 Table 5.2.2.1-2)
/// Returns (modulation, code_rate_x1024, spectral_efficiency)
pub fn nr_cqi_table1(index: u8) -> Option<(&'static str, u16, f64)> {
    match index {
        0  => None, // out of range
        1  => Some(("QPSK",   78,  0.1523)),
        2  => Some(("QPSK",   120, 0.2344)),
        3  => Some(("QPSK",   193, 0.3770)),
        4  => Some(("QPSK",   308, 0.6016)),
        5  => Some(("QPSK",   449, 0.8770)),
        6  => Some(("QPSK",   602, 1.1758)),
        7  => Some(("16QAM",  378, 1.4766)),
        8  => Some(("16QAM",  490, 1.9141)),
        9  => Some(("16QAM",  616, 2.4063)),
        10 => Some(("64QAM",  466, 2.7305)),
        11 => Some(("64QAM",  567, 3.3223)),
        12 => Some(("64QAM",  666, 3.9023)),
        13 => Some(("64QAM",  772, 4.5234)),
        14 => Some(("64QAM",  873, 5.1152)),
        15 => Some(("64QAM",  948, 5.5547)),
        _ => None,
    }
}

/// NR CQI Table 2 (256QAM, TS 38.214 Table 5.2.2.1-3)
pub fn nr_cqi_table2(index: u8) -> Option<(&'static str, u16, f64)> {
    match index {
        0  => None,
        1  => Some(("QPSK",   78,  0.1523)),
        2  => Some(("QPSK",   193, 0.3770)),
        3  => Some(("QPSK",   449, 0.8770)),
        4  => Some(("16QAM",  378, 1.4766)),
        5  => Some(("16QAM",  490, 1.9141)),
        6  => Some(("16QAM",  616, 2.4063)),
        7  => Some(("64QAM",  466, 2.7305)),
        8  => Some(("64QAM",  567, 3.3223)),
        9  => Some(("64QAM",  666, 3.9023)),
        10 => Some(("64QAM",  772, 4.5234)),
        11 => Some(("64QAM",  873, 5.1152)),
        12 => Some(("256QAM", 711, 5.5547)),
        13 => Some(("256QAM", 797, 6.2266)),
        14 => Some(("256QAM", 885, 6.9141)),
        15 => Some(("256QAM", 948, 7.4063)),
        _ => None,
    }
}

/// LTE CQI Table (TS 36.213 Table 7.2.3-1)
pub fn lte_cqi_table(index: u8) -> Option<(&'static str, u16, f64)> {
    match index {
        0  => None, // out of range
        1  => Some(("QPSK",   78,  0.1523)),
        2  => Some(("QPSK",   120, 0.2344)),
        3  => Some(("QPSK",   193, 0.3770)),
        4  => Some(("QPSK",   308, 0.6016)),
        5  => Some(("QPSK",   449, 0.8770)),
        6  => Some(("QPSK",   602, 1.1758)),
        7  => Some(("16QAM",  378, 1.4766)),
        8  => Some(("16QAM",  490, 1.9141)),
        9  => Some(("16QAM",  616, 2.4063)),
        10 => Some(("64QAM",  466, 2.7305)),
        11 => Some(("64QAM",  567, 3.3223)),
        12 => Some(("64QAM",  666, 3.9023)),
        13 => Some(("64QAM",  772, 4.5234)),
        14 => Some(("64QAM",  873, 5.1152)),
        15 => Some(("64QAM",  948, 5.5547)),
        _ => None,
    }
}

// ============================================================================
// MIMO RANK
// ============================================================================

/// MIMO rank / number of layers description
pub fn mimo_rank_name(rank: u8) -> &'static str {
    match rank {
        0 => "unknown",
        1 => "1 layer (SISO/SIMO)",
        2 => "2 layers (2x2 MIMO)",
        3 => "3 layers",
        4 => "4 layers (4x4 MIMO)",
        5 => "5 layers",
        6 => "6 layers",
        7 => "7 layers",
        8 => "8 layers (8x8 MIMO)",
        _ => "invalid",
    }
}

/// Modulation order to name
pub fn modulation_order_name(order: u8) -> &'static str {
    match order {
        1 => "BPSK",
        2 => "QPSK",
        4 => "16QAM",
        6 => "64QAM",
        8 => "256QAM",
        10 => "1024QAM",
        _ => "unknown",
    }
}

// ============================================================================
// NR PHY PDSCH DECODER (0xB800)
// ============================================================================

/// Decode NR PHY PDSCH statistics (0xB800)
///
/// Heuristic parser — Qualcomm DIAG PHY log structure:
/// ```text
/// [version(1)] [num_records(1)] [carrier_id(1)] [reserved(1)]
/// Per record (variable, ~24-32 bytes):
///   [harq_id(1)] [rnti_type(1)] [rnti(2)] [tb_index(1)] [mcs(1)] [mcs_table(1)]
///   [num_rbs(2)] [num_layers(1)] [crc_result(1)] [tb_size(4)] [reserved...]
/// ```
pub fn decode_nr_phy_pdsch(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("NR_PHY_PDSCH ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let num_records = data[1] as usize;
    let carrier_id = data[2];

    let mut records = Vec::new();
    let mut total_tbs: u32 = 0;
    let mut crc_pass: u32 = 0;
    let mut crc_fail: u32 = 0;
    let mut mcs_sum: u32 = 0;
    let mut total_tb_size: u64 = 0;

    // Record offset starts after header
    let record_size = estimate_pdsch_record_size(data, num_records);
    let mut offset = 4;

    for _ in 0..num_records.min(16) {
        if offset + record_size > data.len() {
            break;
        }

        let harq_id = data[offset];
        let rnti_type = data[offset + 1];
        let rnti = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let tb_index = data[offset + 4];
        let mcs_index = data[offset + 5];
        let mcs_table_id = data[offset + 6];

        let num_rbs = if offset + 9 <= data.len() {
            u16::from_le_bytes([data[offset + 7], data[offset + 8]])
        } else {
            0
        };

        let num_layers = if offset + 10 <= data.len() { data[offset + 9] } else { 1 };
        let crc_result = if offset + 11 <= data.len() { data[offset + 10] } else { 0 };

        let tb_size = if offset + 15 <= data.len() {
            u32::from_le_bytes([data[offset + 11], data[offset + 12], data[offset + 13], data[offset + 14]])
        } else {
            0
        };

        // MCS lookup
        let mcs_info = match mcs_table_id {
            0 | 1 => nr_mcs_table1(mcs_index),
            2 => nr_mcs_table2(mcs_index),
            _ => nr_mcs_table1(mcs_index),
        };

        let (modulation, code_rate) = mcs_info
            .map(|(m, cr, _)| (m, cr as f64 / 1024.0))
            .unwrap_or(("unknown", 0.0));

        let crc_ok = crc_result == 0;

        records.push(json!({
            "harq_id": harq_id,
            "rnti_type": rnti_type_name(rnti_type),
            "rnti": rnti,
            "tb_index": tb_index,
            "mcs_index": mcs_index,
            "mcs_table": mcs_table_id,
            "modulation": modulation,
            "code_rate": code_rate,
            "num_rbs": num_rbs,
            "num_layers": num_layers,
            "mimo_rank": mimo_rank_name(num_layers),
            "tb_size": tb_size,
            "crc_pass": crc_ok,
        }));

        total_tbs += 1;
        if crc_ok { crc_pass += 1; } else { crc_fail += 1; }
        mcs_sum += mcs_index as u32;
        total_tb_size += tb_size as u64;

        offset += record_size;
    }

    let bler = if total_tbs > 0 {
        (crc_fail as f64 / total_tbs as f64) * 100.0
    } else {
        0.0
    };

    let avg_mcs = if total_tbs > 0 {
        mcs_sum as f64 / total_tbs as f64
    } else {
        0.0
    };

    let decoded = json!({
        "protocol": "NR-PHY",
        "log_name": "NR_PHY_PDSCH",
        "version": version,
        "carrier_id": carrier_id,
        "num_records": num_records,
        "records": records,
        "total_tbs": total_tbs,
        "crc_pass": crc_pass,
        "crc_fail": crc_fail,
        "bler_percent": (bler * 100.0).round() / 100.0,
        "avg_mcs": (avg_mcs * 10.0).round() / 10.0,
        "total_tb_bytes": total_tb_size,
        "raw_length": data.len(),
    });

    let mod_str = records.first()
        .and_then(|r| r.get("modulation").and_then(|v| v.as_str()))
        .unwrap_or("?");

    let summary = format!(
        "NR PHY PDSCH {} TBs MCS_avg={:.1} {} BLER={:.1}% {}KB",
        total_tbs, avg_mcs, mod_str, bler, total_tb_size / 1024
    );

    (Some(decoded), summary, total_tbs > 0)
}

// ============================================================================
// NR PHY PUSCH DECODER (0xB801)
// ============================================================================

/// Decode NR PHY PUSCH statistics (0xB801)
pub fn decode_nr_phy_pusch(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("NR_PHY_PUSCH ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let num_records = data[1] as usize;
    let carrier_id = data[2];

    let mut records = Vec::new();
    let mut total_tbs: u32 = 0;
    let mut mcs_sum: u32 = 0;
    let mut total_tb_size: u64 = 0;

    let record_size = estimate_pusch_record_size(data, num_records);
    let mut offset = 4;

    for _ in 0..num_records.min(16) {
        if offset + record_size > data.len() {
            break;
        }

        let harq_id = data[offset];
        let rnti = u16::from_le_bytes([data[offset + 1], data[offset + 2]]);
        let mcs_index = data[offset + 3];
        let mcs_table_id = if offset + 5 <= data.len() { data[offset + 4] } else { 0 };

        let num_rbs = if offset + 7 <= data.len() {
            u16::from_le_bytes([data[offset + 5], data[offset + 6]])
        } else {
            0
        };

        let num_layers = if offset + 8 <= data.len() { data[offset + 7] } else { 1 };

        let tb_size = if offset + 12 <= data.len() {
            u32::from_le_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]])
        } else {
            0
        };

        let mcs_info = match mcs_table_id {
            0 | 1 => nr_mcs_table1(mcs_index),
            2 => nr_mcs_table2(mcs_index),
            _ => nr_mcs_table1(mcs_index),
        };

        let modulation = mcs_info.map(|(m, _, _)| m).unwrap_or("unknown");

        records.push(json!({
            "harq_id": harq_id,
            "rnti": rnti,
            "mcs_index": mcs_index,
            "mcs_table": mcs_table_id,
            "modulation": modulation,
            "num_rbs": num_rbs,
            "num_layers": num_layers,
            "mimo_rank": mimo_rank_name(num_layers),
            "tb_size": tb_size,
        }));

        total_tbs += 1;
        mcs_sum += mcs_index as u32;
        total_tb_size += tb_size as u64;

        offset += record_size;
    }

    let avg_mcs = if total_tbs > 0 { mcs_sum as f64 / total_tbs as f64 } else { 0.0 };

    let decoded = json!({
        "protocol": "NR-PHY",
        "log_name": "NR_PHY_PUSCH",
        "version": version,
        "carrier_id": carrier_id,
        "num_records": num_records,
        "records": records,
        "total_tbs": total_tbs,
        "avg_mcs": (avg_mcs * 10.0).round() / 10.0,
        "total_tb_bytes": total_tb_size,
        "raw_length": data.len(),
    });

    let summary = format!(
        "NR PHY PUSCH {} TBs MCS_avg={:.1} {}KB",
        total_tbs, avg_mcs, total_tb_size / 1024
    );

    (Some(decoded), summary, total_tbs > 0)
}

// ============================================================================
// NR PHY PDCCH DECODER (0xB802)
// ============================================================================

/// Decode NR PHY PDCCH / DCI (0xB802)
pub fn decode_nr_phy_pdcch(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("NR_PHY_PDCCH ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let num_dci = data[1] as usize;

    let mut dcis = Vec::new();
    let mut offset = 4;

    for _ in 0..num_dci.min(8) {
        if offset + 12 > data.len() {
            break;
        }

        let dci_format = data[offset];
        let rnti_type = data[offset + 1];
        let rnti = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let aggregation_level = data[offset + 4];
        let cce_index = data[offset + 5];
        let mcs = data[offset + 6];
        let ndi = data[offset + 7] & 1;
        let rv = (data[offset + 7] >> 1) & 3;
        let harq_process = data[offset + 8];
        let tpc_command = data[offset + 9] as i8;
        let num_rbs = u16::from_le_bytes([data[offset + 10], data[offset + 11]]);

        dcis.push(json!({
            "dci_format": dci_format_name(dci_format),
            "rnti_type": rnti_type_name(rnti_type),
            "rnti": rnti,
            "aggregation_level": 1u32 << (aggregation_level & 3),
            "cce_index": cce_index,
            "mcs": mcs,
            "ndi": ndi,
            "rv": rv,
            "harq_process": harq_process,
            "tpc_command": tpc_command,
            "num_rbs": num_rbs,
        }));

        offset += 12;
    }

    let decoded = json!({
        "protocol": "NR-PHY",
        "log_name": "NR_PHY_PDCCH",
        "version": version,
        "num_dci": num_dci,
        "dcis": dcis,
        "raw_length": data.len(),
    });

    let fmt_str = dcis.first()
        .and_then(|d| d.get("dci_format").and_then(|v| v.as_str()))
        .unwrap_or("?");

    let summary = format!("NR PHY PDCCH {} DCIs format={}", num_dci, fmt_str);

    (Some(decoded), summary, !dcis.is_empty())
}

// ============================================================================
// NR PHY PUCCH DECODER (0xB803)
// ============================================================================

/// Decode NR PHY PUCCH (0xB803) — CSI reporting channel
pub fn decode_nr_phy_pucch(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 4 {
        return (None, format!("NR_PHY_PUCCH ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let pucch_format = data[1];
    let num_reports = data[2] as usize;

    let mut reports = Vec::new();
    let mut offset = 4;

    for _ in 0..num_reports.min(4) {
        if offset + 6 > data.len() {
            break;
        }

        let cqi = data[offset];
        let ri = data[offset + 1];
        let pmi = data[offset + 2];
        let harq_ack = data[offset + 3];
        let sr = data[offset + 4];
        let csi_part2 = data[offset + 5];

        let cqi_info = if cqi > 0 && cqi <= 15 {
            nr_cqi_table1(cqi).map(|(m, _, eff)| json!({
                "modulation": m,
                "spectral_efficiency": eff,
            }))
        } else {
            None
        };

        reports.push(json!({
            "cqi": cqi,
            "cqi_info": cqi_info,
            "ri": ri,
            "ri_name": mimo_rank_name(ri),
            "pmi": pmi,
            "harq_ack": harq_ack_name(harq_ack),
            "sr": sr != 0,
            "csi_part2": csi_part2,
        }));

        offset += 6;
    }

    let first_cqi = reports.first()
        .and_then(|r| r.get("cqi").and_then(|v| v.as_u64()))
        .unwrap_or(0) as u8;
    let first_ri = reports.first()
        .and_then(|r| r.get("ri").and_then(|v| v.as_u64()))
        .unwrap_or(0) as u8;

    let decoded = json!({
        "protocol": "NR-PHY",
        "log_name": "NR_PHY_PUCCH",
        "version": version,
        "pucch_format": pucch_format,
        "num_reports": num_reports,
        "reports": reports,
        "cqi": first_cqi,
        "ri": first_ri,
        "raw_length": data.len(),
    });

    let summary = format!(
        "NR PHY PUCCH fmt={} CQI={} RI={} ({} reports)",
        pucch_format, first_cqi, first_ri, num_reports
    );

    (Some(decoded), summary, !reports.is_empty())
}

// ============================================================================
// GENERIC NR PHY DECODER
// ============================================================================

/// Generic NR PHY decoder for other log codes in 0xB800-0xB80F
pub fn decode_nr_phy_generic(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 2 {
        return (None, format!("NR_PHY_0x{:04X} ({} bytes)", log_code, data.len()), false);
    }

    let version = data[0];
    let decoded = json!({
        "protocol": "NR-PHY",
        "log_code": format!("0x{:04X}", log_code),
        "version": version,
        "raw_length": data.len(),
    });
    let summary = format!("NR PHY 0x{:04X} v{} ({} bytes)", log_code, version, data.len());
    (Some(decoded), summary, true)
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn rnti_type_name(rnti_type: u8) -> &'static str {
    match rnti_type {
        0 => "C-RNTI",
        1 => "CS-RNTI",
        2 => "TC-RNTI",
        3 => "P-RNTI",
        4 => "SI-RNTI",
        5 => "RA-RNTI",
        6 => "MCS-C-RNTI",
        _ => "unknown",
    }
}

fn dci_format_name(fmt: u8) -> &'static str {
    match fmt {
        0 => "0_0",
        1 => "0_1",
        2 => "1_0",
        3 => "1_1",
        4 => "2_0",
        5 => "2_1",
        6 => "2_2",
        7 => "2_3",
        _ => "unknown",
    }
}

fn harq_ack_name(ack: u8) -> &'static str {
    match ack {
        0 => "NACK",
        1 => "ACK",
        2 => "DTX",
        _ => "unknown",
    }
}

/// Estimate PDSCH per-record size from total data length
fn estimate_pdsch_record_size(data: &[u8], num_records: usize) -> usize {
    if num_records == 0 {
        return 16;
    }
    let available = data.len().saturating_sub(4);
    let estimated = available / num_records;
    // Clamp to reasonable range
    estimated.clamp(15, 48)
}

/// Estimate PUSCH per-record size from total data length
fn estimate_pusch_record_size(data: &[u8], num_records: usize) -> usize {
    if num_records == 0 {
        return 12;
    }
    let available = data.len().saturating_sub(4);
    let estimated = available / num_records;
    estimated.clamp(12, 40)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nr_mcs_table1_known_values() {
        // MCS 0 = QPSK, rate 120/1024
        let (mod_name, rate, eff) = nr_mcs_table1(0).unwrap();
        assert_eq!(mod_name, "QPSK");
        assert_eq!(rate, 120);
        assert!((eff - 0.2344).abs() < 0.001);

        // MCS 10 = 16QAM
        let (mod_name, _, _) = nr_mcs_table1(10).unwrap();
        assert_eq!(mod_name, "16QAM");

        // MCS 28 = 64QAM, highest
        let (mod_name, rate, _) = nr_mcs_table1(28).unwrap();
        assert_eq!(mod_name, "64QAM");
        assert_eq!(rate, 948);

        // MCS 29 = reserved
        assert!(nr_mcs_table1(29).is_none());
    }

    #[test]
    fn test_nr_mcs_table2_256qam() {
        // MCS 20 = 256QAM
        let (mod_name, _, _) = nr_mcs_table2(20).unwrap();
        assert_eq!(mod_name, "256QAM");

        // MCS 27 = highest 256QAM
        let (mod_name, rate, _) = nr_mcs_table2(27).unwrap();
        assert_eq!(mod_name, "256QAM");
        assert_eq!(rate, 948);
    }

    #[test]
    fn test_lte_mcs_table() {
        let (mod_name, tbs_idx) = lte_mcs_table(0).unwrap();
        assert_eq!(mod_name, "QPSK");
        assert_eq!(tbs_idx, 0);

        let (mod_name, _) = lte_mcs_table(17).unwrap();
        assert_eq!(mod_name, "64QAM");

        assert!(lte_mcs_table(29).is_none());
    }

    #[test]
    fn test_nr_cqi_table1() {
        assert!(nr_cqi_table1(0).is_none());

        let (mod_name, _, _) = nr_cqi_table1(1).unwrap();
        assert_eq!(mod_name, "QPSK");

        let (mod_name, _, _) = nr_cqi_table1(15).unwrap();
        assert_eq!(mod_name, "64QAM");

        assert!(nr_cqi_table1(16).is_none());
    }

    #[test]
    fn test_nr_cqi_table2_256qam() {
        let (mod_name, _, _) = nr_cqi_table2(15).unwrap();
        assert_eq!(mod_name, "256QAM");
    }

    #[test]
    fn test_lte_cqi_table() {
        let (mod_name, _, _) = lte_cqi_table(7).unwrap();
        assert_eq!(mod_name, "16QAM");
    }

    #[test]
    fn test_mimo_rank_name() {
        assert_eq!(mimo_rank_name(1), "1 layer (SISO/SIMO)");
        assert_eq!(mimo_rank_name(2), "2 layers (2x2 MIMO)");
        assert_eq!(mimo_rank_name(4), "4 layers (4x4 MIMO)");
    }

    #[test]
    fn test_decode_nr_phy_pdsch_basic() {
        // Build a synthetic PDSCH log with 1 record
        let mut data = vec![0u8; 19];
        data[0] = 2;  // version
        data[1] = 1;  // num_records
        data[2] = 0;  // carrier_id
        // Record at offset 4:
        data[4] = 3;  // harq_id
        data[5] = 0;  // rnti_type = C-RNTI
        data[6] = 0x34; data[7] = 0x12; // rnti = 0x1234
        data[8] = 0;  // tb_index
        data[9] = 15; // mcs_index = 15 (16QAM)
        data[10] = 1; // mcs_table = 1
        data[11] = 50; data[12] = 0; // num_rbs = 50
        data[13] = 2; // num_layers = 2
        data[14] = 0; // crc_result = pass
        data[15] = 0x00; data[16] = 0x10; data[17] = 0; data[18] = 0; // tb_size = 4096

        let (decoded, summary, fully) = decode_nr_phy_pdsch(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["total_tbs"], 1);
        assert_eq!(d["crc_pass"], 1);
        assert_eq!(d["crc_fail"], 0);
        assert_eq!(d["bler_percent"], 0.0);
        assert!(summary.contains("PDSCH"));
        assert!(summary.contains("MCS_avg"));
    }

    #[test]
    fn test_decode_nr_phy_pdsch_with_bler() {
        // 2 records: 1 pass, 1 fail
        let mut data = vec![0u8; 34];
        data[0] = 2;  // version
        data[1] = 2;  // num_records
        data[2] = 0;  // carrier_id

        // Record 1 at offset 4: CRC pass
        data[4] = 0; data[5] = 0;
        data[6] = 0x34; data[7] = 0x12;
        data[8] = 0; data[9] = 10;  // mcs=10
        data[10] = 1;
        data[11] = 20; data[12] = 0;
        data[13] = 1; data[14] = 0;  // CRC pass
        data[15] = 0; data[16] = 0x08; data[17] = 0; data[18] = 0; // tb=2048

        // Record 2 at offset 19: CRC fail
        data[19] = 1; data[20] = 0;
        data[21] = 0x34; data[22] = 0x12;
        data[23] = 0; data[24] = 20; // mcs=20
        data[25] = 1;
        data[26] = 40; data[27] = 0;
        data[28] = 1; data[29] = 1;  // CRC fail
        data[30] = 0; data[31] = 0x10; data[32] = 0; data[33] = 0; // tb=4096

        let (decoded, _, fully) = decode_nr_phy_pdsch(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["total_tbs"], 2);
        assert_eq!(d["crc_pass"], 1);
        assert_eq!(d["crc_fail"], 1);
        assert_eq!(d["bler_percent"], 50.0);
    }

    #[test]
    fn test_decode_nr_phy_pusch_basic() {
        let mut data = vec![0u8; 16];
        data[0] = 1;  // version
        data[1] = 1;  // num_records
        data[2] = 0;  // carrier_id
        // Record at offset 4:
        data[4] = 2;  // harq_id
        data[5] = 0x34; data[6] = 0x12; // rnti
        data[7] = 20; // mcs_index = 20 (64QAM)
        data[8] = 1;  // mcs_table
        data[9] = 30; data[10] = 0; // num_rbs
        data[11] = 1; // num_layers
        data[12] = 0; data[13] = 0x08; data[14] = 0; data[15] = 0; // tb_size=2048

        let (decoded, summary, fully) = decode_nr_phy_pusch(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["total_tbs"], 1);
        assert!(summary.contains("PUSCH"));
    }

    #[test]
    fn test_decode_nr_phy_pdcch_basic() {
        let mut data = vec![0u8; 16];
        data[0] = 1;  // version
        data[1] = 1;  // num_dci
        // DCI at offset 4:
        data[4] = 3;  // dci_format = 1_1
        data[5] = 0;  // rnti_type = C-RNTI
        data[6] = 0x34; data[7] = 0x12; // rnti
        data[8] = 2;  // aggregation_level (1<<2=4)
        data[9] = 10; // cce_index
        data[10] = 15; // mcs
        data[11] = 1; // ndi=1, rv=0
        data[12] = 3; // harq_process
        data[13] = 1; // tpc_command
        data[14] = 50; data[15] = 0; // num_rbs

        let (decoded, summary, fully) = decode_nr_phy_pdcch(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["num_dci"], 1);
        assert!(summary.contains("PDCCH"));
    }

    #[test]
    fn test_decode_nr_phy_pucch_csi() {
        let mut data = vec![0u8; 10];
        data[0] = 1;  // version
        data[1] = 2;  // pucch_format
        data[2] = 1;  // num_reports
        // Report at offset 4:
        data[4] = 12; // cqi = 12
        data[5] = 2;  // ri = 2
        data[6] = 5;  // pmi
        data[7] = 1;  // harq_ack = ACK
        data[8] = 0;  // sr = no
        data[9] = 0;  // csi_part2

        let (decoded, summary, fully) = decode_nr_phy_pucch(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["cqi"], 12);
        assert_eq!(d["ri"], 2);
        assert!(summary.contains("CQI=12"));
        assert!(summary.contains("RI=2"));
    }

    #[test]
    fn test_truncated_phy_data() {
        let data = [0u8; 2];
        let (_, _, fully) = decode_nr_phy_pdsch(&data);
        assert!(!fully);
        let (_, _, fully) = decode_nr_phy_pusch(&data);
        assert!(!fully);
        let (_, _, fully) = decode_nr_phy_pdcch(&data);
        assert!(!fully);
        let (_, _, fully) = decode_nr_phy_pucch(&data);
        assert!(!fully);
    }
}
