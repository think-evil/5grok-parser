//! ML1 measurement decoders for NR and LTE
//!
//! Extracts PCI, RSRP, RSRQ, SINR, and neighbor cell data from
//! Qualcomm ML1 measurement logs (0xB8xx for NR, 0xB1xx for LTE).

use super::metadata::{earfcn_to_band, nr_arfcn_to_band};

// ============================================================================
// NR ML1 DECODERS
// ============================================================================

/// Decode NR ML1 measurement log (0xB880, 0xB884, 0xB886, 0xB887, 0xB88A)
pub fn decode_nr_ml1(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    let log_name = match log_code {
        0xB880 => "NR_ML1_Searcher_Meas",
        0xB884 => "NR_ML1_Serving_Cell",
        0xB886 => "NR_ML1_Neighbor_Meas",
        0xB887 => "NR_ML1_SINR",
        0xB88A => "NR_ML1_Beam_Mgmt",
        _ => "NR_ML1_Unknown",
    };

    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];

    match log_code {
        0xB884 => decode_nr_ml1_serving(data, version, log_name),
        0xB880 => decode_nr_ml1_searcher(data, version, log_name),
        0xB886 => decode_nr_ml1_neighbor(data, version, log_name),
        0xB887 => decode_nr_ml1_sinr(data, version, log_name),
        0xB88A => decode_nr_ml1_beam_mgmt(data, version, log_name),
        _ => {
            let decoded = serde_json::json!({
                "protocol": "NR-ML1",
                "log_name": log_name,
                "version": version,
                "raw_length": data.len(),
            });
            let summary = format!("{} v{} ({} bytes)", log_name, version, data.len());
            (Some(decoded), summary, false)
        }
    }
}

/// NR ML1 Serving Cell (0xB884)
/// Versioned struct with PCI, ARFCN, RSRP, RSRQ measurements.
/// RSRP/RSRQ: 16-bit signed, resolution 0.0625 dB.
/// RSRP formula: raw * 0.0625 - 180.0 dBm
/// RSRQ formula: raw * 0.0625 - 30.0 dB
fn decode_nr_ml1_serving(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 16 {
        let decoded = serde_json::json!({
            "protocol": "NR-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let pci = u16::from_le_bytes([data[4], data[5]]);
    let arfcn = if data.len() >= 12 {
        u32::from_le_bytes([data[6], data[7], 0, 0]) // often u16 arfcn within struct
    } else {
        0
    };
    let rsrp_raw = i16::from_le_bytes([data[8], data[9]]);
    let rsrq_raw = i16::from_le_bytes([data[10], data[11]]);
    let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
    let rsrq = rsrq_raw as f64 * 0.0625 - 30.0;

    // SINR at [12-13] if available
    let sinr = if data.len() >= 14 {
        let raw = i16::from_le_bytes([data[12], data[13]]);
        if raw != 0 { Some(raw as f64 * 0.0625 - 23.0) } else { None }
    } else {
        None
    };

    let mut decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "pci": pci,
        "rsrp_dbm": rsrp,
        "rsrq_db": rsrq,
        "raw_length": data.len(),
    });

    if let Some(sinr_val) = sinr {
        decoded["sinr_db"] = serde_json::json!(sinr_val);
    }
    if arfcn > 0 {
        decoded["arfcn"] = serde_json::json!(arfcn);
    }

    let sinr_str = sinr.map_or(String::new(), |s| format!(" SINR={:.1}", s));
    let summary = format!(
        "NR ML1 PCI={} RSRP={:.1} RSRQ={:.1}{}",
        pci, rsrp, rsrq, sinr_str
    );
    (Some(decoded), summary, true)
}

/// NR ML1 Searcher (0xB880) — cell search results with PCI and RSRP per candidate.
fn decode_nr_ml1_searcher(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    // Common layout: version(1) + padding(1) + num_cells(2) + arfcn(4) + [per-cell records]
    let num_cells = u16::from_le_bytes([data[2], data[3]]) as usize;
    let arfcn = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let band = if arfcn > 0 { nr_arfcn_to_band(arfcn) } else { "N/A".into() };

    // Parse per-cell records: PCI(2) + RSRP(2) + RSRQ(2) = 6 bytes each
    let mut cells = Vec::new();
    let record_offset = 8;
    let record_size = 6;
    let actual_cells = num_cells.min(16); // cap at 16

    for i in 0..actual_cells {
        let off = record_offset + i * record_size;
        if off + record_size > data.len() {
            break;
        }
        let pci = u16::from_le_bytes([data[off], data[off + 1]]);
        let rsrp_raw = i16::from_le_bytes([data[off + 2], data[off + 3]]);
        let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;

        cells.push(serde_json::json!({
            "pci": pci,
            "rsrp_dbm": rsrp,
        }));
    }

    // Top-level PCI/RSRP from strongest cell
    let (top_pci, top_rsrp) = if let Some(first) = cells.first() {
        (
            first["pci"].as_u64().map(|v| v as u16),
            first["rsrp_dbm"].as_f64(),
        )
    } else {
        (None, None)
    };

    let mut decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "arfcn": arfcn,
        "band": band,
        "num_cells": num_cells,
        "cells": cells,
        "raw_length": data.len(),
    });

    if let Some(p) = top_pci {
        decoded["pci"] = serde_json::json!(p);
    }
    if let Some(r) = top_rsrp {
        decoded["rsrp_dbm"] = serde_json::json!(r);
    }

    let pci_str = top_pci.map_or("?".to_string(), |p| p.to_string());
    let summary = format!(
        "NR ML1 Searcher {} cells ARFCN={} {} PCI={}",
        num_cells, arfcn, band, pci_str
    );
    (Some(decoded), summary, true)
}

/// NR ML1 Neighbor Meas (0xB886) — neighbor cell measurements.
fn decode_nr_ml1_neighbor(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let num_neighbors = u16::from_le_bytes([data[2], data[3]]) as usize;
    let arfcn = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let band = if arfcn > 0 { nr_arfcn_to_band(arfcn) } else { "N/A".into() };

    // Parse neighbor records: PCI(2) + RSRP(2) + RSRQ(2) = 6 bytes
    let mut neighbors = Vec::new();
    let record_offset = 8;
    let record_size = 6;
    let actual = num_neighbors.min(16);

    for i in 0..actual {
        let off = record_offset + i * record_size;
        if off + record_size > data.len() {
            break;
        }
        let pci = u16::from_le_bytes([data[off], data[off + 1]]);
        let rsrp_raw = i16::from_le_bytes([data[off + 2], data[off + 3]]);
        let rsrq_raw = i16::from_le_bytes([data[off + 4], data[off + 5]]);
        let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
        let rsrq = rsrq_raw as f64 * 0.0625 - 30.0;

        neighbors.push(serde_json::json!({
            "pci": pci,
            "rsrp_dbm": rsrp,
            "rsrq_db": rsrq,
        }));
    }

    let decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "arfcn": arfcn,
        "band": band,
        "num_neighbors": num_neighbors,
        "neighbors": neighbors,
        "raw_length": data.len(),
    });

    let summary = format!(
        "NR ML1 {} neighbors ARFCN={} {}",
        num_neighbors, arfcn, band
    );
    (Some(decoded), summary, true)
}

/// NR ML1 SINR (0xB887) — serving cell SINR measurement.
fn decode_nr_ml1_sinr(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let pci = u16::from_le_bytes([data[4], data[5]]);
    let sinr_raw = i16::from_le_bytes([data[6], data[7]]);
    let sinr = sinr_raw as f64 * 0.0625 - 23.0;

    let decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "pci": pci,
        "sinr_db": sinr,
        "raw_length": data.len(),
    });

    let summary = format!("NR ML1 PCI={} SINR={:.1}dB", pci, sinr);
    (Some(decoded), summary, true)
}

/// NR ML1 Beam Management (0xB88A) — SSB beam measurements.
fn decode_nr_ml1_beam_mgmt(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "NR-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let pci = u16::from_le_bytes([data[4], data[5]]);
    let num_beams = data[2] as usize;

    // Parse beam records: beam_id(1) + rsrp(2) + sinr(2) = 5 bytes
    let mut beams = Vec::new();
    let record_offset = 8;
    let record_size = 5;
    let actual = num_beams.min(8);

    for i in 0..actual {
        let off = record_offset + i * record_size;
        if off + record_size > data.len() {
            break;
        }
        let beam_id = data[off];
        let rsrp_raw = i16::from_le_bytes([data[off + 1], data[off + 2]]);
        let sinr_raw = i16::from_le_bytes([data[off + 3], data[off + 4]]);
        let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
        let sinr = sinr_raw as f64 * 0.0625 - 23.0;

        beams.push(serde_json::json!({
            "beam_id": beam_id,
            "rsrp_dbm": rsrp,
            "sinr_db": sinr,
        }));
    }

    // Top-level RSRP from best beam
    let best_rsrp = beams.iter()
        .filter_map(|b| b["rsrp_dbm"].as_f64())
        .fold(f64::NEG_INFINITY, f64::max);

    let mut decoded = serde_json::json!({
        "protocol": "NR-ML1",
        "log_name": log_name,
        "version": version,
        "pci": pci,
        "num_beams": num_beams,
        "beams": beams,
        "raw_length": data.len(),
    });

    if best_rsrp.is_finite() {
        decoded["rsrp_dbm"] = serde_json::json!(best_rsrp);
    }

    let summary = format!("NR ML1 PCI={} {} beams", pci, num_beams);
    (Some(decoded), summary, true)
}

// ============================================================================
// LTE ML1 DECODERS
// ============================================================================

/// Decode LTE ML1 measurement log (0xB193, 0xB197, 0xB110, 0xB113, 0xB17F)
pub fn decode_lte_ml1(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    let log_name = match log_code {
        0xB193 => "LTE_ML1_Serving_Cell_Meas",
        0xB197 => "LTE_ML1_Neighbor_Meas",
        0xB110 => "LTE_ML1_Connected_Meas",
        0xB113 => "LTE_ML1_Idle_Meas",
        0xB17F => "LTE_ML1_Serving_SINR",
        _ => "LTE_ML1_Unknown",
    };

    if data.len() < 4 {
        return (None, format!("{} ({} bytes)", log_name, data.len()), false);
    }

    let version = data[0];

    match log_code {
        0xB193 => decode_lte_ml1_serving(data, version, log_name),
        0xB197 => decode_lte_ml1_neighbor(data, version, log_name),
        0xB17F => decode_lte_ml1_sinr(data, version, log_name),
        0xB110 => decode_lte_ml1_connected(data, version, log_name),
        0xB113 => decode_lte_ml1_idle(data, version, log_name),
        _ => {
            let decoded = serde_json::json!({
                "protocol": "LTE-ML1",
                "log_name": log_name,
                "version": version,
                "raw_length": data.len(),
            });
            let summary = format!("{} v{} ({} bytes)", log_name, version, data.len());
            (Some(decoded), summary, false)
        }
    }
}

/// LTE ML1 Serving Cell Meas (0xB193)
/// Versioned struct: EARFCN, PCI, RSRP (raw*0.0625-180.0), RSRQ (raw*0.0625-30.0)
fn decode_lte_ml1_serving(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    // Need at least: version(1) + pad(1) + num_sub(2) + earfcn(2) + pci(2) + rsrp(2) + rsrq(2) = 12
    if data.len() < 12 {
        let decoded = serde_json::json!({
            "protocol": "LTE-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let earfcn = u16::from_le_bytes([data[4], data[5]]);
    let pci = u16::from_le_bytes([data[6], data[7]]);
    let rsrp_raw = i16::from_le_bytes([data[8], data[9]]);
    let rsrq_raw = i16::from_le_bytes([data[10], data[11]]);
    let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
    let rsrq = rsrq_raw as f64 * 0.0625 - 30.0;
    let band = earfcn_to_band(earfcn as u32);

    // SINR at [12-13] if available
    let sinr = if data.len() >= 14 {
        let raw = i16::from_le_bytes([data[12], data[13]]);
        if raw != 0 { Some(raw as f64 * 0.0625 - 23.0) } else { None }
    } else {
        None
    };

    let mut decoded = serde_json::json!({
        "protocol": "LTE-ML1",
        "log_name": log_name,
        "version": version,
        "earfcn": earfcn,
        "band": band,
        "pci": pci,
        "rsrp_dbm": rsrp,
        "rsrq_db": rsrq,
        "raw_length": data.len(),
    });

    if let Some(sinr_val) = sinr {
        decoded["sinr_db"] = serde_json::json!(sinr_val);
    }

    let sinr_str = sinr.map_or(String::new(), |s| format!(" SINR={:.1}", s));
    let summary = format!(
        "LTE ML1 PCI={} EARFCN={} {} RSRP={:.1} RSRQ={:.1}{}",
        pci, earfcn, band, rsrp, rsrq, sinr_str
    );
    (Some(decoded), summary, true)
}

/// LTE ML1 Neighbor Meas (0xB197) — neighbor cell list with RSRP/RSRQ.
fn decode_lte_ml1_neighbor(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "LTE-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let num_cells = u16::from_le_bytes([data[2], data[3]]) as usize;
    let earfcn = u16::from_le_bytes([data[4], data[5]]);
    let band = earfcn_to_band(earfcn as u32);

    // Parse neighbor records: PCI(2) + RSRP(2) + RSRQ(2) = 6 bytes each
    let mut neighbors = Vec::new();
    let record_offset = 8;
    let record_size = 6;
    let actual = num_cells.min(16);

    for i in 0..actual {
        let off = record_offset + i * record_size;
        if off + record_size > data.len() {
            break;
        }
        let pci = u16::from_le_bytes([data[off], data[off + 1]]);
        let rsrp_raw = i16::from_le_bytes([data[off + 2], data[off + 3]]);
        let rsrq_raw = i16::from_le_bytes([data[off + 4], data[off + 5]]);
        let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
        let rsrq = rsrq_raw as f64 * 0.0625 - 30.0;

        neighbors.push(serde_json::json!({
            "pci": pci,
            "earfcn": earfcn,
            "rsrp_dbm": rsrp,
            "rsrq_db": rsrq,
        }));
    }

    let decoded = serde_json::json!({
        "protocol": "LTE-ML1",
        "log_name": log_name,
        "version": version,
        "earfcn": earfcn,
        "band": band,
        "num_cells": num_cells,
        "neighbors": neighbors,
        "raw_length": data.len(),
    });

    let summary = format!(
        "LTE ML1 {} neighbors EARFCN={} {}",
        num_cells, earfcn, band
    );
    (Some(decoded), summary, true)
}

/// LTE ML1 Serving SINR (0xB17F) — SINR measurement only.
fn decode_lte_ml1_sinr(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 8 {
        let decoded = serde_json::json!({
            "protocol": "LTE-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let pci = u16::from_le_bytes([data[4], data[5]]);
    let sinr_raw = i16::from_le_bytes([data[6], data[7]]);
    let sinr = sinr_raw as f64 * 0.0625 - 23.0;

    let decoded = serde_json::json!({
        "protocol": "LTE-ML1",
        "log_name": log_name,
        "version": version,
        "pci": pci,
        "sinr_db": sinr,
        "raw_length": data.len(),
    });

    let summary = format!("LTE ML1 PCI={} SINR={:.1}dB", pci, sinr);
    (Some(decoded), summary, true)
}

/// LTE ML1 Connected Meas (0xB110) — serving + neighbor in connected mode.
fn decode_lte_ml1_connected(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    // Same structure as serving + neighbors combined
    if data.len() < 12 {
        let decoded = serde_json::json!({
            "protocol": "LTE-ML1",
            "log_name": log_name,
            "version": version,
            "raw_length": data.len(),
        });
        return (Some(decoded), format!("{} v{} ({} bytes)", log_name, version, data.len()), false);
    }

    let earfcn = u16::from_le_bytes([data[4], data[5]]);
    let pci = u16::from_le_bytes([data[6], data[7]]);
    let rsrp_raw = i16::from_le_bytes([data[8], data[9]]);
    let rsrq_raw = i16::from_le_bytes([data[10], data[11]]);
    let rsrp = rsrp_raw as f64 * 0.0625 - 180.0;
    let rsrq = rsrq_raw as f64 * 0.0625 - 30.0;
    let band = earfcn_to_band(earfcn as u32);

    // Neighbor records after serving cell data (offset varies by version)
    let mut neighbors = Vec::new();
    let num_neighbors = if data.len() >= 14 { data[12] as usize } else { 0 };
    let record_offset = 14;
    let record_size = 6;

    for i in 0..num_neighbors.min(16) {
        let off = record_offset + i * record_size;
        if off + record_size > data.len() {
            break;
        }
        let n_pci = u16::from_le_bytes([data[off], data[off + 1]]);
        let n_rsrp_raw = i16::from_le_bytes([data[off + 2], data[off + 3]]);
        let n_rsrq_raw = i16::from_le_bytes([data[off + 4], data[off + 5]]);
        neighbors.push(serde_json::json!({
            "pci": n_pci,
            "rsrp_dbm": n_rsrp_raw as f64 * 0.0625 - 180.0,
            "rsrq_db": n_rsrq_raw as f64 * 0.0625 - 30.0,
        }));
    }

    let decoded = serde_json::json!({
        "protocol": "LTE-ML1",
        "log_name": log_name,
        "version": version,
        "earfcn": earfcn,
        "band": band,
        "pci": pci,
        "rsrp_dbm": rsrp,
        "rsrq_db": rsrq,
        "serving": {
            "pci": pci,
            "earfcn": earfcn,
            "rsrp_dbm": rsrp,
            "rsrq_db": rsrq,
        },
        "neighbors": neighbors,
        "raw_length": data.len(),
    });

    let summary = format!(
        "LTE ML1 Conn PCI={} RSRP={:.1} +{} neighbors",
        pci, rsrp, neighbors.len()
    );
    (Some(decoded), summary, true)
}

/// LTE ML1 Idle Meas (0xB113) — measurements in idle mode.
fn decode_lte_ml1_idle(
    data: &[u8],
    version: u8,
    log_name: &str,
) -> (Option<serde_json::Value>, String, bool) {
    // Same structure as connected meas
    decode_lte_ml1_connected(data, version, log_name)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nr_ml1_serving() {
        // Construct a synthetic NR ML1 serving cell measurement
        let mut data = vec![0u8; 16];
        data[0] = 5; // version
        data[4] = 75; data[5] = 0; // PCI=75
        // RSRP raw = 1600 => 1600*0.0625-180 = -80.0 dBm
        let rsrp: i16 = 1600;
        data[8..10].copy_from_slice(&rsrp.to_le_bytes());
        // RSRQ raw = 320 => 320*0.0625-30 = -10.0 dB
        let rsrq: i16 = 320;
        data[10..12].copy_from_slice(&rsrq.to_le_bytes());

        let (decoded, summary, fully) = decode_nr_ml1(0xB884, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 75);
        assert!((d["rsrp_dbm"].as_f64().unwrap() - (-80.0)).abs() < 0.1);
        assert!((d["rsrq_db"].as_f64().unwrap() - (-10.0)).abs() < 0.1);
        assert!(summary.contains("PCI=75"));
    }

    #[test]
    fn test_nr_ml1_sinr() {
        let mut data = vec![0u8; 8];
        data[0] = 3; // version
        data[4] = 100; data[5] = 0; // PCI=100
        // SINR raw = 528 => 528*0.0625-23 = 10.0 dB
        let sinr: i16 = 528;
        data[6..8].copy_from_slice(&sinr.to_le_bytes());

        let (decoded, summary, fully) = decode_nr_ml1(0xB887, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 100);
        assert!((d["sinr_db"].as_f64().unwrap() - 10.0).abs() < 0.1);
        assert!(summary.contains("SINR=10.0"));
    }

    #[test]
    fn test_lte_ml1_serving() {
        let mut data = vec![0u8; 14];
        data[0] = 2; // version
        data[4] = 170; data[5] = 0; // EARFCN=170
        data[6] = 171; data[7] = 0; // PCI=171
        // RSRP raw = 1440 => 1440*0.0625-180 = -90.0 dBm
        let rsrp: i16 = 1440;
        data[8..10].copy_from_slice(&rsrp.to_le_bytes());
        // RSRQ raw = 240 => 240*0.0625-30 = -15.0 dB
        let rsrq: i16 = 240;
        data[10..12].copy_from_slice(&rsrq.to_le_bytes());

        let (decoded, summary, fully) = decode_lte_ml1(0xB193, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 171);
        assert_eq!(d["earfcn"], 170);
        assert!((d["rsrp_dbm"].as_f64().unwrap() - (-90.0)).abs() < 0.1);
        assert!((d["rsrq_db"].as_f64().unwrap() - (-15.0)).abs() < 0.1);
        assert!(summary.contains("PCI=171"));
        assert!(summary.contains("EARFCN=170"));
    }

    #[test]
    fn test_lte_ml1_sinr() {
        let mut data = vec![0u8; 8];
        data[0] = 1; // version
        data[4] = 50; data[5] = 0; // PCI=50
        // SINR raw = 688 => 688*0.0625-23 = 20.0 dB
        let sinr: i16 = 688;
        data[6..8].copy_from_slice(&sinr.to_le_bytes());

        let (decoded, summary, fully) = decode_lte_ml1(0xB17F, &data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 50);
        assert!((d["sinr_db"].as_f64().unwrap() - 20.0).abs() < 0.1);
        assert!(summary.contains("SINR=20.0"));
    }

    #[test]
    fn test_truncated_ml1() {
        let data = [0u8; 2]; // too short
        let (_, _, fully) = decode_nr_ml1(0xB884, &data);
        assert!(!fully);
        let (_, _, fully) = decode_lte_ml1(0xB193, &data);
        assert!(!fully);
    }
}
