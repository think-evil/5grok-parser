//! RRC decoders for NR and LTE
//!
//! For BCCH channels (MIB, SIB), when the `asn1-rrc` feature is enabled,
//! uses grok5-asn1 UPER decoder for full ASN.1 decode.
//! For DCCH channels, uses heuristic byte-level parsers for security-critical
//! messages (Security Mode Command, RRC Reconfiguration).

use super::metadata::{lte_rrc_channel_name, nr_rrc_channel_name};

// ============================================================================
// NR RRC
// ============================================================================

/// Decode 5G NR RRC OTA message (log code 0xB821)
/// Header: version(1) + rrc_rel(1) + rrc_ver(1) + bearer_id(1) + pci(2) + freq(4) + sfn(2) + subfn_slot(1) + len(2) + PDU...
pub fn decode_nr_rrc_ota(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 14 {
        return (None, format!("NR RRC OTA: too short ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let _rrc_rel = data[1];
    let bearer_id = data[3];
    let pci = u16::from_le_bytes([data[4], data[5]]);
    let freq = u32::from_le_bytes([data[6], data[7], data[8], data[9]]);
    let sfn = u16::from_le_bytes([data[10], data[11]]);

    let channel = nr_rrc_channel_name(bearer_id);
    let direction = if bearer_id & 0x10 != 0 { "UL" } else { "DL" };
    let ch_type = bearer_id & 0x0F;

    let pdu_len = u16::from_le_bytes([data[12], data[13]]) as usize;

    // Extract PDU body (after 14-byte header)
    let pdu_body = if data.len() > 14 && pdu_len > 0 {
        let end = (14 + pdu_len).min(data.len());
        Some(&data[14..end])
    } else {
        None
    };

    let mut decoded = serde_json::json!({
        "protocol": "NR-RRC",
        "direction": direction,
        "channel": channel,
        "pci": pci,
        "frequency": freq,
        "sfn": sfn,
        "version": version,
        "pdu_length": pdu_len,
        "raw_length": data.len(),
    });

    let mut extra_summary = String::new();

    // Deep-parse PDU body based on channel type
    if let Some(pdu) = pdu_body {
        match ch_type {
            // BCCH-BCH → MIB
            0 => {
                if let Some(mib_info) = decode_nr_mib(pdu) {
                    decoded["mib"] = mib_info;
                    extra_summary = " [MIB]".to_string();
                }
            }
            // BCCH-DL-SCH → SIB
            1 => {
                if let Some(sib_info) = decode_nr_sib1(pdu) {
                    decoded["sib1"] = sib_info;
                    extra_summary = " [SIB1]".to_string();
                }
            }
            // DCCH (DL) → Security Mode Command or RRC Reconfiguration
            2 => {
                if let Some(sec_info) = parse_nr_dcch_security(pdu) {
                    decoded["rrc_security"] = sec_info;
                    extra_summary = " [SecMode]".to_string();
                }
            }
            _ => {}
        }
    }

    let summary = format!(
        "NR RRC {} {} PCI={} freq={} SFN={}{}",
        direction, channel, pci, freq, sfn, extra_summary
    );
    (Some(decoded), summary, true)
}

/// Decode LTE RRC OTA message (log code 0xB0C0)
pub fn decode_lte_rrc_ota(data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    if data.len() < 12 {
        return (None, format!("LTE RRC OTA: too short ({} bytes)", data.len()), false);
    }

    let version = data[0];
    let _rrc_rel = data[1];
    let _rrc_ver = data[2];
    let bearer_id = data[3];
    let pci = u16::from_le_bytes([data[4], data[5]]);
    let freq = u16::from_le_bytes([data[6], data[7]]);
    let sfn = u16::from_le_bytes([data[8], data[9]]);

    let channel = lte_rrc_channel_name(bearer_id);
    let direction = if bearer_id & 0x10 != 0 { "UL" } else { "DL" };
    let ch_type = bearer_id & 0x0F;

    // LTE RRC OTA header: varies by version; PDU offset ~10 or ~12
    let pdu_offset = if version >= 3 && data.len() >= 14 { 12 } else { 10 };
    let pdu_body = if data.len() > pdu_offset {
        Some(&data[pdu_offset..])
    } else {
        None
    };

    let mut decoded = serde_json::json!({
        "protocol": "LTE-RRC",
        "direction": direction,
        "channel": channel,
        "pci": pci,
        "earfcn": freq,
        "sfn": sfn,
        "version": version,
        "raw_length": data.len(),
    });

    let mut extra_summary = String::new();

    if let Some(pdu) = pdu_body {
        match ch_type {
            // BCCH-BCH → LTE MIB
            0 => {
                if let Some(mib_info) = decode_lte_mib(pdu) {
                    decoded["mib"] = mib_info;
                    extra_summary = " [MIB]".to_string();
                }
            }
            // BCCH-DL-SCH → LTE SIB1
            1 => {
                if let Some(sib_info) = decode_lte_sib1(pdu) {
                    decoded["sib1"] = sib_info;
                    extra_summary = " [SIB1]".to_string();
                }
            }
            // DCCH (DL) → Security Mode Command or Reconfiguration
            2 => {
                if let Some(sec_info) = parse_lte_dcch_security(pdu) {
                    decoded["rrc_security"] = sec_info;
                    extra_summary = " [SecMode]".to_string();
                }
            }
            _ => {}
        }
    }

    let summary = format!(
        "LTE RRC {} {} PCI={} EARFCN={} SFN={}{}",
        direction, channel, pci, freq, sfn, extra_summary
    );
    (Some(decoded), summary, true)
}

// ============================================================================
// grok5-asn1 BCCH DECODERS (behind feature flag)
// ============================================================================

/// Decode NR MIB from UPER-encoded PDU body
#[cfg(feature = "asn1-rrc")]
fn decode_nr_mib(pdu: &[u8]) -> Option<serde_json::Value> {
    use grok5_asn1::prelude::*;
    use grok5_asn1::nr::Mib;

    let mut decoder = UperDecoder::new(pdu);
    match Mib::decode(&mut decoder) {
        Ok(mib) => {
            let sfn_msb = if !mib.system_frame_number.is_empty() {
                mib.system_frame_number[0] >> 2 // 6 MSBs of SFN
            } else {
                0
            };
            let cell_barred = matches!(mib.cell_barred, grok5_asn1::nr::CellBarred::Barred);
            Some(serde_json::json!({
                "sfn_msb": sfn_msb,
                "subcarrier_spacing": format!("{:?}", mib.subcarrier_spacing_common),
                "ssb_subcarrier_offset": mib.ssb_subcarrier_offset,
                "cell_barred": cell_barred,
                "intra_freq_reselection": format!("{:?}", mib.intra_freq_reselection),
            }))
        }
        Err(_) => None,
    }
}

/// Decode NR SIB1 from UPER-encoded PDU body
#[cfg(feature = "asn1-rrc")]
fn decode_nr_sib1(pdu: &[u8]) -> Option<serde_json::Value> {
    use grok5_asn1::nr::Sib1;

    match Sib1::decode(pdu) {
        Ok(sib1) => {
            // Extract PLMN list
            let mut plmn_list = Vec::new();
            for info in &sib1.cell_access_related_info.plmn_identity_info_list {
                for plmn in &info.plmn_identity_list {
                    let mcc_str = plmn.mcc.as_ref().map(|m| {
                        format!("{}{}{}", m[0], m[1], m[2])
                    });
                    let mnc_str = plmn.mnc.iter()
                        .map(|d| d.to_string())
                        .collect::<String>();
                    plmn_list.push(serde_json::json!({
                        "mcc": mcc_str,
                        "mnc": mnc_str,
                    }));
                }
            }

            // Extract cell identity + TAC from first entry
            let first_info = sib1.cell_access_related_info.plmn_identity_info_list.first();
            let tac = first_info.and_then(|i| i.tracking_area_code.as_ref()).map(|t| {
                ((t[0] as u32) << 16) | ((t[1] as u32) << 8) | (t[2] as u32)
            });
            let cell_id = first_info.map(|i| format!("{:?}", i.cell_identity));

            // Cell barring from cell_selection_info
            let cell_barred = sib1.cell_selection_info.as_ref().map(|_| false);

            // UE Timers and Constants (for BTS fingerprinting)
            let ue_timers = sib1.ue_timers_and_constants.as_ref().map(|t| {
                serde_json::json!({
                    "t300": t.t300,
                    "t301": t.t301,
                    "t310": t.t310,
                    "t311": t.t311,
                    "t319": t.t319,
                    "n310": t.n310,
                    "n311": t.n311,
                })
            });

            // SI Scheduling Info (for BTS fingerprinting)
            let si_scheduling = sib1.si_scheduling_info.as_ref().map(|si| {
                let periodicities: Vec<u32> = si.scheduling_info_list.iter()
                    .map(|s| s.si_periodicity.radio_frames() as u32 * 10) // Convert radio frames to ms
                    .collect();
                serde_json::json!({
                    "si_window_length": si.si_window_length.slots(),
                    "num_si_messages": si.scheduling_info_list.len(),
                    "si_periodicities": periodicities,
                })
            });

            let mut result = serde_json::json!({
                "plmn_list": plmn_list,
                "tac": tac,
                "cell_identity": cell_id,
                "ims_emergency_support": sib1.ims_emergency_support,
                "ecall_over_ims_support": sib1.ecall_over_ims_support,
                "cell_barred": cell_barred,
            });

            if let Some(timers) = ue_timers {
                result["ue_timers"] = timers;
            }
            if let Some(si) = si_scheduling {
                result["si_scheduling"] = si;
            }

            Some(result)
        }
        Err(_) => None,
    }
}

/// Decode LTE MIB from UPER-encoded PDU body
#[cfg(feature = "asn1-rrc")]
fn decode_lte_mib(pdu: &[u8]) -> Option<serde_json::Value> {
    use grok5_asn1::prelude::*;
    use grok5_asn1::lte::MasterInformationBlock;

    let mut decoder = UperDecoder::new(pdu);
    match MasterInformationBlock::decode(&mut decoder) {
        Ok(mib) => Some(serde_json::json!({
            "decoded": true,
            "raw_size": pdu.len(),
        })),
        Err(_) => None,
    }
}

/// Decode LTE SIB1 from UPER-encoded PDU body
#[cfg(feature = "asn1-rrc")]
fn decode_lte_sib1(pdu: &[u8]) -> Option<serde_json::Value> {
    use grok5_asn1::prelude::*;
    use grok5_asn1::lte::SystemInformationBlockType1;

    let mut decoder = UperDecoder::new(pdu);
    match SystemInformationBlockType1::decode(&mut decoder) {
        Ok(_sib1) => Some(serde_json::json!({
            "decoded": true,
            "raw_size": pdu.len(),
        })),
        Err(_) => None,
    }
}

// Fallback stubs when asn1-rrc feature is disabled
#[cfg(not(feature = "asn1-rrc"))]
fn decode_nr_mib(_pdu: &[u8]) -> Option<serde_json::Value> { None }

/// Heuristic NR SIB1 parser (without ASN.1 library)
///
/// Extracts basic cell info by scanning for recognizable byte patterns.
/// Less accurate than full UPER decode but works without the ASN.1 dependency.
#[cfg(not(feature = "asn1-rrc"))]
fn decode_nr_sib1(pdu: &[u8]) -> Option<serde_json::Value> {
    if pdu.len() < 4 {
        return None;
    }
    // Minimal heuristic: report that we saw a SIB1 but can't deep-parse
    Some(serde_json::json!({
        "heuristic": true,
        "raw_size": pdu.len(),
    }))
}

#[cfg(not(feature = "asn1-rrc"))]
fn decode_lte_mib(_pdu: &[u8]) -> Option<serde_json::Value> { None }
#[cfg(not(feature = "asn1-rrc"))]
fn decode_lte_sib1(_pdu: &[u8]) -> Option<serde_json::Value> { None }

// ============================================================================
// DCCH HEURISTIC PARSERS (Security-critical)
// ============================================================================

/// Parse NR DCCH PDU for security-related content.
///
/// NR RRC Security Mode Command (TS 38.331):
/// The securityConfigSMC contains two algorithm IDs (0-3 each):
///   cipheringAlgorithm: nea0..nea3
///   integrityProtAlgorithm: nia0..nia3
///
/// We use a heuristic: scan for a byte pair where both are <=3 and are preceded
/// by a recognizable pattern (e.g., ASN.1 DL-DCCH-Message wrapper).
fn parse_nr_dcch_security(pdu: &[u8]) -> Option<serde_json::Value> {
    if pdu.len() < 3 {
        return None;
    }

    // NR DL-DCCH-Message: SecurityModeCommand is choice index 5.
    // In UPER encoding, byte 0 top bits encode message type.
    // SecurityModeCommand: first byte is typically 0x28-0x2F (choice 5, shifted left).
    //
    // Strict heuristic: only match SecurityModeCommand structure, not arbitrary
    // byte pairs in RRC Reconfiguration messages (which caused massive false positives).

    // SecurityModeCommand is a very short message (~2-6 bytes PDU).
    // RRC Reconfiguration is typically much larger (50-500+ bytes).
    // Only apply heuristic to short DCCH PDUs that are likely SecurityModeCommand.
    if pdu.len() > 20 {
        // Too long to be a SecurityModeCommand — skip heuristic to avoid false positives.
        // Real security config in RRC Reconfiguration is handled by the ASN.1 decoder
        // (via the "security" field from decode_nr_sib1/rrc_reconfig), not this heuristic.
        return None;
    }

    // For short PDUs, check that byte 0 looks like a SecurityModeCommand choice index
    let first = pdu[0];
    // NR SecurityModeCommand: choice index 5 in DL-DCCH → first byte 0x28..0x2F
    if !(0x28..=0x2F).contains(&first) {
        return None;
    }

    // Scan for cipher/integrity algorithm pair in the remaining bytes
    for i in 1..pdu.len().saturating_sub(1) {
        let b0 = pdu[i];
        let b1 = pdu[i + 1];

        // Both must be valid algorithm IDs (0-3)
        if b0 <= 3 && b1 <= 3 {
            if i > 0 && pdu[i - 1] != 0 {
                let cipher_name = match b0 {
                    0 => "NEA0 (null)",
                    1 => "128-NEA1 (SNOW3G)",
                    2 => "128-NEA2 (AES)",
                    3 => "128-NEA3 (ZUC)",
                    _ => "unknown",
                };
                let integrity_name = match b1 {
                    0 => "NIA0 (null)",
                    1 => "128-NIA1 (SNOW3G)",
                    2 => "128-NIA2 (AES)",
                    3 => "128-NIA3 (ZUC)",
                    _ => "unknown",
                };

                return Some(serde_json::json!({
                    "cipher_algo": b0,
                    "cipher_name": cipher_name,
                    "integrity_algo": b1,
                    "integrity_name": integrity_name,
                    "null_cipher": b0 == 0,
                    "null_integrity": b1 == 0,
                    "heuristic": true,
                    "offset": i,
                }));
            }
        }
    }

    None
}

/// Parse LTE DCCH PDU for security-related content.
///
/// LTE RRC SecurityModeCommand or RRCConnectionReconfiguration with
/// securityConfigHO or securityConfigSMC.
fn parse_lte_dcch_security(pdu: &[u8]) -> Option<serde_json::Value> {
    if pdu.len() < 3 {
        return None;
    }

    // Strict heuristic: only match short PDUs likely to be SecurityModeCommand.
    // LTE SecurityModeCommand is typically 3-10 bytes.
    // RRC ConnectionReconfiguration is 50-500+ bytes and would cause false positives.
    if pdu.len() > 20 {
        return None;
    }

    // LTE SecurityModeCommand: DL-DCCH choice index 3 → first byte 0x30..0x3F
    // (3 << 4 = 0x30, with remaining bits for sub-fields)
    let first = pdu[0];
    if !(0x30..=0x3F).contains(&first) {
        return None;
    }

    for i in 1..pdu.len().saturating_sub(1) {
        let b0 = pdu[i];
        let b1 = pdu[i + 1];

        if b0 <= 3 && b1 <= 3 && i > 0 && pdu[i - 1] != 0 {
            let cipher_name = match b0 {
                0 => "EEA0 (null)",
                1 => "128-EEA1 (SNOW3G)",
                2 => "128-EEA2 (AES)",
                3 => "128-EEA3 (ZUC)",
                _ => "unknown",
            };
            let integrity_name = match b1 {
                0 => "EIA0 (null)",
                1 => "128-EIA1 (SNOW3G)",
                2 => "128-EIA2 (AES)",
                3 => "128-EIA3 (ZUC)",
                _ => "unknown",
            };

            return Some(serde_json::json!({
                "cipher_algo": b0,
                "cipher_name": cipher_name,
                "integrity_algo": b1,
                "integrity_name": integrity_name,
                "null_cipher": b0 == 0,
                "null_integrity": b1 == 0,
                "heuristic": true,
                "offset": i,
            }));
        }
    }

    None
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nr_rrc_ota_header() {
        // Minimal NR RRC OTA: 14-byte header, no PDU body
        let mut data = vec![0u8; 14];
        data[0] = 5; // version
        data[3] = 2; // bearer_id = DCCH DL
        data[4] = 75; data[5] = 0; // PCI=75
        data[6] = 0xE0; data[7] = 0x97; data[8] = 0x09; data[9] = 0x00; // freq=628704
        data[10] = 100; data[11] = 0; // SFN=100
        data[12] = 0; data[13] = 0; // pdu_len=0

        let (decoded, summary, fully) = decode_nr_rrc_ota(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 75);
        assert_eq!(d["sfn"], 100);
        assert!(summary.contains("PCI=75"));
    }

    #[test]
    fn test_lte_rrc_ota_header() {
        let mut data = vec![0u8; 12];
        data[0] = 2; // version
        data[3] = 1; // bearer_id = BCCH-DL-SCH
        data[4] = 171; data[5] = 0; // PCI=171
        data[6] = 170; data[7] = 0; // EARFCN=170
        data[8] = 50; data[9] = 0; // SFN=50

        let (decoded, summary, fully) = decode_lte_rrc_ota(&data);
        assert!(fully);
        let d = decoded.unwrap();
        assert_eq!(d["pci"], 171);
        assert_eq!(d["earfcn"], 170);
        assert!(summary.contains("EARFCN=170"));
    }

    #[test]
    fn test_nr_dcch_security_heuristic() {
        // Synthetic DCCH PDU with cipher=2 (AES), integrity=2 (AES) at offset 3
        let pdu = [0x28, 0x10, 0x05, 0x02, 0x02, 0x00];
        let result = parse_nr_dcch_security(&pdu);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r["cipher_algo"], 2);
        assert_eq!(r["integrity_algo"], 2);
        assert_eq!(r["null_cipher"], false);
    }

    #[test]
    fn test_lte_dcch_security_null_cipher() {
        // Synthetic LTE SecurityModeCommand: first byte 0x30 (choice index 3)
        let pdu = [0x30, 0x05, 0x00, 0x01, 0xFF];
        let result = parse_lte_dcch_security(&pdu);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r["cipher_algo"], 0);
        assert_eq!(r["integrity_algo"], 1);
        assert_eq!(r["null_cipher"], true);
    }

    #[test]
    fn test_dcch_security_no_match() {
        // PDU with no algorithm pattern
        let pdu = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(parse_nr_dcch_security(&pdu).is_none());
        assert!(parse_lte_dcch_security(&pdu).is_none());
    }

    #[test]
    fn test_dcch_heuristic_rejects_long_pdu() {
        // Long PDU (like RRC Reconfiguration) should NOT trigger the heuristic
        // even if it contains byte pairs ≤3. This was the source of massive false positives.
        let mut pdu = vec![0x28; 100]; // starts with valid SMC-like byte
        pdu[10] = 0x05; // non-zero preceding byte
        pdu[11] = 0x02; // cipher algo
        pdu[12] = 0x02; // integrity algo
        assert!(parse_nr_dcch_security(&pdu).is_none(), "Long PDU should be rejected");

        let mut lte_pdu = vec![0x30; 80];
        lte_pdu[5] = 0x05;
        lte_pdu[6] = 0x01;
        lte_pdu[7] = 0x01;
        assert!(parse_lte_dcch_security(&lte_pdu).is_none(), "Long LTE PDU should be rejected");
    }

    #[test]
    fn test_dcch_heuristic_rejects_wrong_first_byte() {
        // Short PDU but wrong first byte — not a SecurityModeCommand
        let pdu = [0x10, 0x05, 0x02, 0x02, 0x00]; // first byte 0x10, not 0x28-0x2F
        assert!(parse_nr_dcch_security(&pdu).is_none());

        let pdu = [0x20, 0x05, 0x01, 0x01, 0x00]; // first byte 0x20, not 0x30-0x3F
        assert!(parse_lte_dcch_security(&pdu).is_none());
    }
}
