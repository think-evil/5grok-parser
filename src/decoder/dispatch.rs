//! Protocol dispatch — routes log codes to the appropriate decoder function

use super::legacy;
use super::macpdcp;
use super::mediatek;
use super::ml1;
use super::nas_5g;
use super::nas_lte;
use super::phy;
use super::rrc;
use super::samsung;

/// Decode protocol data based on log code and chipset vendor
///
/// vendor: 0=Qualcomm (default), 1=MediaTek, 2=Samsung
pub fn decode_protocol(log_code: u16, data: &[u8], vendor: u8) -> (Option<serde_json::Value>, String, bool) {
    match vendor {
        1 => mediatek::decode_mediatek(log_code, data),
        2 => samsung::decode_samsung(log_code, data),
        _ => decode_qualcomm(log_code, data),
    }
}

/// Qualcomm DIAG protocol decoder (original dispatcher)
fn decode_qualcomm(log_code: u16, data: &[u8]) -> (Option<serde_json::Value>, String, bool) {
    match log_code {
        // 5G NAS OTA messages
        0xB0C2 | 0xB0C3 => nas_5g::decode_5g_nas_ota(data),

        // 5G NAS plain OTA (MM + SM)
        0xB0C6 => nas_5g::decode_5g_nas_plain(data),

        // LTE NAS OTA (plain and security-protected)
        0xB0EA | 0xB0EB | 0xB0EC => nas_lte::decode_lte_nas_ota(log_code, data),

        // 5G NR RRC OTA
        0xB821 => rrc::decode_nr_rrc_ota(data),

        // LTE RRC OTA
        0xB0C0 => rrc::decode_lte_rrc_ota(data),

        // NR PHY layer (PDSCH, PUSCH, PDCCH, PUCCH)
        0xB800 => phy::decode_nr_phy_pdsch(data),
        0xB801 => phy::decode_nr_phy_pusch(data),
        0xB802 => phy::decode_nr_phy_pdcch(data),
        0xB803 => phy::decode_nr_phy_pucch(data),
        0xB804..=0xB80F => phy::decode_nr_phy_generic(log_code, data),

        // ML1 measurements (NR)
        0xB880 | 0xB884 | 0xB886 | 0xB887 | 0xB88A => ml1::decode_nr_ml1(log_code, data),

        // ML1 measurements (LTE)
        0xB193 | 0xB197 | 0xB110 | 0xB113 | 0xB17F => ml1::decode_lte_ml1(log_code, data),

        // NR MAC
        0xB890..=0xB8AF => macpdcp::decode_nr_mac(log_code, data),

        // NR PDCP
        0xB840..=0xB84F => macpdcp::decode_nr_pdcp(log_code, data),

        // NR RLC
        0xB850..=0xB85F => macpdcp::decode_nr_rlc(log_code, data),

        // ==================== LEGACY LOG CODES (0x1xxx) ====================

        // NR RRC OTA v1 (legacy format)
        0x1D0B => legacy::decode_nr_rrc_ota_v1(data),

        // LTE RRC OTA v1 (legacy format)
        0x11EB => legacy::decode_lte_rrc_ota_v1(data),

        // LTE RRC Reconfiguration v1
        0x184C => legacy::decode_lte_rrc_reconf_v1(data),

        // LTE RRC Serving Cell v1
        0x1849 => legacy::decode_lte_rrc_srv_cell_v1(data),

        // LTE NAS EMM State v1
        0x1951 => legacy::decode_lte_nas_emm_state_v1(data),

        // NR ML1/PHY measurement logs (legacy 0x1C6x range)
        0x1C6E => legacy::decode_nr_ml1_v1(0x1C6E, "NR_ML1_Serving_Meas_v1", data),
        0x1C6F => legacy::decode_nr_ml1_v1(0x1C6F, "NR_ML1_Neighbor_Meas_v1", data),
        0x1C70 => legacy::decode_nr_ml1_v1(0x1C70, "NR_ML1_Searcher_v1", data),
        0x1C71 => legacy::decode_nr_ml1_v1(0x1C71, "NR_ML1_RRC_Meas_v1", data),
        0x1C72 => legacy::decode_nr_ml1_v1(0x1C72, "NR_ML1_Beam_Mgmt_v1", data),

        // LTE PDCCH Decode
        0x1874 => legacy::decode_lte_pdcch(data),

        // LTE MAC UL TB v1
        0x18F7 => legacy::decode_lte_mac_v1(data),

        // LTE PDCP DL Config v1
        0x14D8 => legacy::decode_lte_pdcp_v1(data),

        // NR RRC misc (0x1850 = NR Serving Cell / Band Combo)
        0x1850 => legacy::decode_nr_misc_v1(0x1850, "NR_Serving_Cell_v1", data),

        // Common timer/utility log
        0x0098 => legacy::decode_common_timer(data),

        // Fallback: provide hex summary
        _ => {
            let preview = if data.len() <= 16 {
                hex::encode(data)
            } else {
                format!("{}...", hex::encode(&data[..16]))
            };
            let summary = format!("0x{:04X} {} bytes [{}]", log_code, data.len(), preview);
            (None, summary, false)
        }
    }
}
