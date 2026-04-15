//! Log code metadata, message name tables, band maps, helper functions

/// Get metadata for a log code (name, RAT, layer)
pub fn get_log_code_metadata(log_code: u16) -> (String, String, String) {
    let known = match log_code {
        0xB821 => ("NR5G_RRC_OTA", "NR", "RRC"),
        0xB822 => ("NR5G_RRC_MIB_Info", "NR", "RRC"),
        0xB823 => ("NR5G_RRC_Serving_Cell", "NR", "RRC"),
        0xB825 => ("NR5G_RRC_SIB", "NR", "RRC"),
        0xB826 => ("NR5G_RRC_Config", "NR", "RRC"),
        0xB0C0 => ("NR5G_NAS_5GMM_State", "NR", "NAS"),
        0xB0C1 => ("NR5G_NAS_5GSM_State", "NR", "NAS"),
        0xB0C2 => ("NR5G_NAS_MM5G_OTA_DL", "NR", "NAS"),
        0xB0C3 => ("NR5G_NAS_MM5G_OTA_UL", "NR", "NAS"),
        0xB0C6 => ("NR5G_NAS_Plain_OTA", "NR", "NAS"),
        0xB0C4 => ("NR5G_NAS_SM5G_OTA_DL", "NR", "NAS"),
        0xB0C5 => ("NR5G_NAS_SM5G_OTA_UL", "NR", "NAS"),
        0xB0CD => ("NR5G_NAS_5GMM_Timer", "NR", "NAS"),
        0xB0CF => ("NR5G_NAS_5GSM_Timer", "NR", "NAS"),
        0xB880 => ("NR5G_ML1_Searcher_Meas", "NR", "ML1"),
        0xB884 => ("NR5G_ML1_Serving_Cell", "NR", "ML1"),
        0xB886 => ("NR5G_ML1_Neighbor_Meas", "NR", "ML1"),
        0xB887 => ("NR5G_ML1_SINR", "NR", "ML1"),
        0xB88A => ("NR5G_ML1_Beam_Mgmt", "NR", "ML1"),
        0xB8DA => ("NR5G_ML1_Meas_DB", "NR", "ML1"),
        0xB890 => ("NR5G_MAC_UL_TB", "NR", "MAC"),
        0xB891 => ("NR5G_MAC_DL_TB", "NR", "MAC"),
        0xB893 => ("NR5G_MAC_RACH", "NR", "MAC"),
        0xB840 => ("NR5G_PDCP_UL_Stats", "NR", "PDCP"),
        0xB841 => ("NR5G_PDCP_DL_Stats", "NR", "PDCP"),
        0xB850 => ("NR5G_RLC_UL_Stats", "NR", "RLC"),
        0xB851 => ("NR5G_RLC_DL_Stats", "NR", "RLC"),
        0xB800 => ("NR5G_PHY_PDSCH", "NR", "PHY"),
        0xB801 => ("NR5G_PHY_PUSCH", "NR", "PHY"),
        0xB802 => ("NR5G_PHY_PDCCH", "NR", "PHY"),
        0xB803 => ("NR5G_PHY_PUCCH", "NR", "PHY"),
        0xB804 => ("NR5G_PHY_CSI_RS", "NR", "PHY"),
        0xB805 => ("NR5G_PHY_SRS", "NR", "PHY"),
        0xB894 => ("NR5G_MAC_DL_Sched", "NR", "MAC"),
        0xB895 => ("NR5G_MAC_UL_Sched", "NR", "MAC"),
        0xB97F => ("NR5G_NAS", "NR", "NAS"),
        // LTE
        0xB193 => ("LTE_ML1_Serving_Cell_Meas", "LTE", "ML1"),
        0xB197 => ("LTE_ML1_Neighbor_Meas", "LTE", "ML1"),
        0xB110 => ("LTE_ML1_Connected_Meas", "LTE", "ML1"),
        0xB113 => ("LTE_ML1_Idle_Meas", "LTE", "ML1"),
        0xB17F => ("LTE_ML1_Serving_SINR", "LTE", "ML1"),
        0xB0EA => ("LTE_NAS_Plain_OTA", "LTE", "NAS"),
        0xB0EB => ("LTE_NAS_ESM_Plain_OTA", "LTE", "NAS"),
        0xB0EC => ("LTE_NAS_Security_OTA", "LTE", "NAS"),
        0xB0E0 => ("LTE_NAS_ESM_State", "LTE", "NAS"),
        0xB0E2 => ("LTE_NAS_EMM_State", "LTE", "NAS"),
        0xB060 => ("LTE_MAC_UL_TB", "LTE", "MAC"),
        0xB063 => ("LTE_MAC_DL_TB", "LTE", "MAC"),
        0xB064 => ("LTE_MAC_RACH_Trigger", "LTE", "MAC"),
        0xB080 => ("LTE_PDCP_DL_Config", "LTE", "PDCP"),
        0xB082 => ("LTE_PDCP_UL_Stats", "LTE", "PDCP"),
        0xB083 => ("LTE_PDCP_DL_Stats", "LTE", "PDCP"),
        0xB091 => ("LTE_RLC_DL_Stats", "LTE", "RLC"),
        0xB092 => ("LTE_RLC_UL_Stats", "LTE", "RLC"),
        // Legacy format
        0x11EB => ("LTE_RRC_OTA_v1", "LTE", "RRC"),
        0x184C => ("LTE_RRC_Reconf_v1", "LTE", "RRC"),
        0x1D0B => ("NR_RRC_OTA_v1", "NR", "RRC"),
        0x1874 => ("LTE_PDCCH_Decode", "LTE", "PHY"),
        0x18F7 => ("LTE_MAC_UL_TB_v1", "LTE", "MAC"),
        0x1849 => ("LTE_RRC_Srv_Cell_v1", "LTE", "RRC"),
        0x14D8 => ("LTE_PDCP_DL_Cfg_v1", "LTE", "PDCP"),
        0x12E8 => ("LTE_ML1_SCell_v1", "LTE", "ML1"),
        0x1951 => ("LTE_NAS_EMM_State_v1", "LTE", "NAS"),
        0x1850 => ("NR_Serving_Cell_v1", "NR", "RRC"),
        0x1C6E => ("NR_ML1_Serving_Meas_v1", "NR", "ML1"),
        0x1C6F => ("NR_ML1_Neighbor_Meas_v1", "NR", "ML1"),
        0x1C70 => ("NR_ML1_Searcher_v1", "NR", "ML1"),
        0x1C71 => ("NR_ML1_RRC_Meas_v1", "NR", "ML1"),
        0x1C72 => ("NR_ML1_Beam_Mgmt_v1", "NR", "ML1"),
        0x0098 => ("System_Timer", "System", "Timer"),
        _ => {
            return get_log_code_metadata_by_range(log_code);
        }
    };
    (known.0.to_string(), known.1.to_string(), known.2.to_string())
}

/// Fallback: derive metadata from log code ranges
fn get_log_code_metadata_by_range(log_code: u16) -> (String, String, String) {
    let (name, rat, layer) = match log_code {
        0xB800..=0xB81F => (format!("NR_PHY_0x{:04X}", log_code), "NR".into(), "PHY".into()),
        0xB820..=0xB82F => (format!("NR_RRC_0x{:04X}", log_code), "NR".into(), "RRC".into()),
        0xB840..=0xB84F => (format!("NR_PDCP_0x{:04X}", log_code), "NR".into(), "PDCP".into()),
        0xB850..=0xB85F => (format!("NR_RLC_0x{:04X}", log_code), "NR".into(), "RLC".into()),
        0xB880..=0xB8AF => (format!("NR_ML1_MAC_0x{:04X}", log_code), "NR".into(), "ML1".into()),
        0xB8D0..=0xB8D3 => (format!("NR_RedCap_0x{:04X}", log_code), "NR".into(), "RedCap".into()),
        0xB8F0..=0xB8F5 => (format!("NR_Sidelink_0x{:04X}", log_code), "NR".into(), "Sidelink".into()),
        0xB950..=0xB9FF => (format!("NR_VENDOR_0x{:04X}", log_code), "NR".into(), "Vendor".into()),
        0xB060..=0xB07F => (format!("LTE_MAC_0x{:04X}", log_code), "LTE".into(), "MAC".into()),
        0xB080..=0xB0AF => (format!("LTE_PDCP_RLC_0x{:04X}", log_code), "LTE".into(), "PDCP".into()),
        0xB0C0..=0xB0CF => (format!("LTE_RRC_NAS_0x{:04X}", log_code), "LTE".into(), "RRC".into()),
        0xB0E0..=0xB0EF => (format!("LTE_NAS_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0xB100..=0xB1FF => (format!("LTE_ML1_0x{:04X}", log_code), "LTE".into(), "ML1".into()),
        0x0D00..=0x0D0F => (format!("MTK_EMM_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0x0D10..=0x0D1F => (format!("MTK_EMM_Auth_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0x0D20..=0x0D2F => (format!("MTK_EMM_Sec_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0x0D30..=0x0D5F => (format!("MTK_EMM_Svc_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0x0D60..=0x0DFF => (format!("MTK_ESM_0x{:04X}", log_code), "LTE".into(), "NAS".into()),
        0x0E00..=0x0E1F => (format!("MTK_LTE_RRC_0x{:04X}", log_code), "LTE".into(), "RRC".into()),
        0x0E20..=0x0EFF => (format!("MTK_LTE_RRC_0x{:04X}", log_code), "LTE".into(), "RRC".into()),
        0x1C00..=0x1C2F => (format!("MTK_5GMM_0x{:04X}", log_code), "NR".into(), "NAS".into()),
        0x1C30..=0x1C5F => (format!("MTK_5GSM_0x{:04X}", log_code), "NR".into(), "NAS".into()),
        0x1D00..=0x1D2F => (format!("MTK_NR_RRC_0x{:04X}", log_code), "NR".into(), "RRC".into()),
        0x1E00..=0x1EFF => (format!("MTK_NR_RRC_0x{:04X}", log_code), "NR".into(), "RRC".into()),
        0x1000..=0x1FFF => (format!("LEGACY_0x{:04X}", log_code), "Multi".into(), "Common".into()),
        0x4000..=0x4FFF => (format!("WCDMA_0x{:04X}", log_code), "WCDMA".into(), "L1".into()),
        0x5000..=0x5FFF => (format!("GSM_0x{:04X}", log_code), "GSM".into(), "L1".into()),
        // GPS pseudo-frame
        0xFD01 => ("GPS_Position".into(), "GPS".into(), "Location".into()),
        // DIAG monitor reserved range
        0xFD00 | 0xFD02..=0xFDFF => (format!("DIAG_MON_0x{:04X}", log_code), "DIAG".into(), "Monitor".into()),
        // Samsung Shannon (synthetic codes)
        0x2001..=0x20FF => (format!("SAMSUNG_NAS_0x{:04X}", log_code), "Multi".into(), "NAS".into()),
        0x2100..=0x21FF => (format!("SAMSUNG_RRC_0x{:04X}", log_code), "Multi".into(), "RRC".into()),
        0x2200..=0x22FF => (format!("SAMSUNG_ML1_0x{:04X}", log_code), "Multi".into(), "ML1".into()),
        0xFE00..=0xFE0F => (format!("MBIM_0x{:04X}", log_code), "MBIM".into(), "Monitor".into()),
        0xFE10..=0xFE1F => (format!("QMI_0x{:04X}", log_code), "QMI".into(), "Monitor".into()),
        0xFF00..=0xFFFF => (format!("AT_0x{:04X}", log_code), "AT".into(), "Monitor".into()),
        _ => (format!("LOG_0x{:04X}", log_code), "Unknown".into(), "Unknown".into()),
    };
    (name, rat, layer)
}

/// Categorize the protocol for display
pub fn categorize_protocol(log_code: u16) -> String {
    match log_code {
        0xB0C2 | 0xB0C3 | 0xB0C6 | 0xB0C1 | 0xB0C4 | 0xB0C5 | 0xB0CD | 0xB0CF => "5G-NAS".into(),
        0xB0E0..=0xB0EF => "LTE-NAS".into(),
        0xB820..=0xB82F => "NR-RRC".into(),
        0xB0C0 => "LTE-RRC".into(),
        0xB880..=0xB88F => "NR-ML1".into(),
        0xB170..=0xB19E => "LTE-ML1".into(),
        0xB800..=0xB81F => "NR-PHY".into(),
        0xB840..=0xB84F => "NR-PDCP".into(),
        0xB850..=0xB85F => "NR-RLC".into(),
        0xB890..=0xB8AF => "NR-MAC".into(),
        0xB060..=0xB07F => "LTE-MAC".into(),
        0xB080..=0xB08F => "LTE-PDCP".into(),
        0xB090..=0xB0AF => "LTE-RLC".into(),
        0xB19F..=0xB1A6 => "NB-IoT".into(),
        0xB1A7..=0xB1AA => "Cat-M".into(),
        0xB8F0..=0xB8F5 => "NR-Sidelink".into(),
        0xB8D0..=0xB8D3 => "RedCap".into(),
        0x1D0B => "NR-RRC".into(),
        0x1850 => "NR-RRC".into(),
        0x1C6E..=0x1C72 => "NR-ML1".into(),
        0x11EB => "LTE-RRC".into(),
        0x184C => "LTE-RRC".into(),
        0x1849 => "LTE-RRC".into(),
        0x1874 => "LTE-PHY".into(),
        0x18F7 => "LTE-MAC".into(),
        0x14D8 => "LTE-PDCP".into(),
        0x1951 => "LTE-NAS".into(),
        0x0098 => "System".into(),
        0x4000..=0x4FFF => "WCDMA".into(),
        0x5000..=0x5FFF => "GSM".into(),
        // GPS
        0xFD01 => "GPS".into(),
        0xFD00 | 0xFD02..=0xFDFF => "DIAG-Mon".into(),
        // Samsung Shannon
        0x2001..=0x20FF => "Samsung-NAS".into(),
        0x2100..=0x21FF => "Samsung-RRC".into(),
        0x2200..=0x22FF => "Samsung-ML1".into(),
        // MediaTek
        0x0C01..=0x0CFF => "MTK-LTE-RRC".into(),
        0x0D00..=0x0DFF => "MTK-LTE-NAS".into(),
        0x0E01..=0x0EFF => "MTK-LTE-NAS".into(),
        0x1C01..=0x1CFF => "MTK-NR-RRC".into(),
        0x1D01..=0x1DFF => "MTK-5G-NAS".into(),
        0x1E01..=0x1EFF => "MTK-5G-NAS".into(),
        0xFE00..=0xFE1F => "MBIM/QMI".into(),
        0xFF00..=0xFFFF => "AT".into(),
        _ => "DIAG".into(),
    }
}

/// Hex preview of data
pub fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let slice = &data[..data.len().min(max_bytes)];
    hex::encode(slice)
}

// ============================================================================
// NAS MESSAGE TYPE LOOKUP TABLES
// ============================================================================

pub fn nas_5gmm_message_name(mt: u8) -> String {
    match mt {
        0x41 => "Registration Request",
        0x42 => "Registration Accept",
        0x43 => "Registration Complete",
        0x44 => "Registration Reject",
        0x45 => "Deregistration Request (UE)",
        0x46 => "Deregistration Accept (UE)",
        0x47 => "Deregistration Request (NW)",
        0x48 => "Deregistration Accept (NW)",
        0x4C => "Service Request",
        0x4D => "Service Reject",
        0x4E => "Service Accept",
        0x54 => "Configuration Update Command",
        0x55 => "Configuration Update Complete",
        0x56 => "Authentication Request",
        0x57 => "Authentication Response",
        0x58 => "Authentication Reject",
        0x59 => "Authentication Failure",
        0x5A => "Authentication Result",
        0x5C => "Identity Request",
        0x5D => "Identity Response",
        0x5E => "Security Mode Command",
        0x5F => "Security Mode Complete",
        0x60 => "Security Mode Reject",
        0x64 => "5GMM Status",
        0x65 => "Notification",
        0x66 => "Notification Response",
        0x67 => "UL NAS Transport",
        0x68 => "DL NAS Transport",
        _ => return format!("5GMM_0x{:02X}", mt),
    }.to_string()
}

pub fn nas_5gsm_message_name(mt: u8) -> String {
    match mt {
        0xC1 => "PDU Session Establishment Request",
        0xC2 => "PDU Session Establishment Accept",
        0xC3 => "PDU Session Establishment Reject",
        0xC5 => "PDU Session Authentication Command",
        0xC6 => "PDU Session Authentication Complete",
        0xC7 => "PDU Session Authentication Result",
        0xC9 => "PDU Session Modification Request",
        0xCA => "PDU Session Modification Reject",
        0xCB => "PDU Session Modification Command",
        0xCC => "PDU Session Modification Complete",
        0xCD => "PDU Session Modification Command Reject",
        0xD1 => "PDU Session Release Request",
        0xD2 => "PDU Session Release Reject",
        0xD3 => "PDU Session Release Command",
        0xD4 => "PDU Session Release Complete",
        0xD6 => "5GSM Status",
        _ => return format!("5GSM_0x{:02X}", mt),
    }.to_string()
}

pub fn nas_emm_message_name(mt: u8) -> String {
    match mt {
        0x41 => "Attach Request",
        0x42 => "Attach Accept",
        0x43 => "Attach Complete",
        0x44 => "Attach Reject",
        0x45 => "Detach Request",
        0x46 => "Detach Accept",
        0x48 => "Tracking Area Update Request",
        0x49 => "Tracking Area Update Accept",
        0x4A => "Tracking Area Update Complete",
        0x4B => "Tracking Area Update Reject",
        0x4C => "Extended Service Request",
        0x4E => "Service Reject",
        0x50 => "GUTI Reallocation Command",
        0x51 => "GUTI Reallocation Complete",
        0x52 => "Authentication Request",
        0x53 => "Authentication Response",
        0x54 => "Authentication Reject",
        0x55 => "Authentication Failure",
        0x5C => "Identity Request",
        0x5D => "Identity Response",
        0x5E => "Security Mode Command",
        0x5F => "Security Mode Complete",
        0x60 => "Security Mode Reject",
        0x61 => "EMM Status",
        0x62 => "EMM Information",
        0x63 => "Downlink NAS Transport",
        0x64 => "Uplink NAS Transport",
        0x68 => "CS Service Notification",
        _ => return format!("EMM_0x{:02X}", mt),
    }.to_string()
}

pub fn nas_esm_message_name(mt: u8) -> String {
    match mt {
        0xC1 => "Activate Default EPS Bearer Request",
        0xC2 => "Activate Default EPS Bearer Accept",
        0xC3 => "Activate Default EPS Bearer Reject",
        0xC5 => "Activate Dedicated EPS Bearer Request",
        0xC6 => "Activate Dedicated EPS Bearer Accept",
        0xC7 => "Activate Dedicated EPS Bearer Reject",
        0xC9 => "Modify EPS Bearer Request",
        0xCA => "Modify EPS Bearer Accept",
        0xCB => "Modify EPS Bearer Reject",
        0xCD => "Deactivate EPS Bearer Request",
        0xCE => "Deactivate EPS Bearer Accept",
        0xD0 => "PDN Connectivity Request",
        0xD1 => "PDN Connectivity Reject",
        0xD2 => "PDN Disconnect Request",
        0xD3 => "PDN Disconnect Reject",
        0xD4 => "Bearer Resource Allocation Request",
        0xD5 => "Bearer Resource Allocation Reject",
        0xD6 => "Bearer Resource Modification Request",
        0xD7 => "Bearer Resource Modification Reject",
        0xD9 => "ESM Information Request",
        0xDA => "ESM Information Response",
        0xDB => "Notification",
        0xDC => "ESM Dummy Message",
        0xE8 => "ESM Status",
        _ => return format!("ESM_0x{:02X}", mt),
    }.to_string()
}

// ============================================================================
// RRC CHANNEL NAMES
// ============================================================================

pub fn nr_rrc_channel_name(bearer_id: u8) -> String {
    let ch = bearer_id & 0x0F;
    match ch {
        0 => "BCCH-BCH (MIB)",
        1 => "BCCH-DL-SCH (SIB)",
        2 => "DCCH (DL)",
        3 => "DCCH (UL)",
        4 => "PCCH",
        5 => "MCCH",
        6 => "BCCH-DL-SCH-BR",
        _ => return format!("CH_{}", ch),
    }.to_string()
}

pub fn lte_rrc_channel_name(bearer_id: u8) -> String {
    let ch = bearer_id & 0x0F;
    match ch {
        0 => "BCCH-BCH",
        1 => "BCCH-DL-SCH",
        2 => "DCCH (DL)",
        3 => "DCCH (UL)",
        4 => "PCCH",
        5 => "MCCH",
        _ => return format!("CH_{}", ch),
    }.to_string()
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Extract a null-terminated or printable ASCII string from data
pub fn extract_ascii_string(data: &[u8], max_len: usize) -> String {
    let mut s = String::new();
    for &b in data.iter().take(max_len) {
        if b == 0 {
            break;
        }
        if b >= 0x20 && b <= 0x7E {
            s.push(b as char);
        }
    }
    s
}

/// EMM state name from state byte
pub fn emm_state_name(state: u8) -> &'static str {
    match state {
        0x00 => "NULL",
        0x01 => "DEREGISTERED",
        0x02 => "REG_INITIATED",
        0x03 => "REGISTERED",
        0x04 => "TAU_INITIATED",
        0x05 => "SR_INITIATED",
        0x06 => "DEREG_INITIATED",
        0x21 => "DEREGISTERED",
        0x23 | 0x81 => "REGISTERED",
        0x45 | 0x46 => "CONNECTED",
        _ => "Unknown",
    }
}

/// EMM sub-state name
pub fn emm_substate_name(substate: u8) -> &'static str {
    match substate {
        0x00 => "NONE",
        0x01 => "NORMAL_SERVICE",
        0x02 => "NORMAL_SERVICE",
        0x03 => "ATTEMPTING_ATTACH",
        0x04 => "PLMN_SEARCH",
        0x05 => "NO_CELL",
        0x06 => "ATTACH_NEEDED",
        _ => "Unknown",
    }
}

/// Map NR-ARFCN to band string
pub fn nr_arfcn_to_band(arfcn: u32) -> String {
    let band = match arfcn {
        123400..=130400 => "n71",
        145800..=149199 => "n12",
        149200..=149800 => "n13",
        151600..=164400 => "n28",
        173800..=178800 => "n5",
        185000..=192000 => "n8",
        285400..=286399 => "n51",
        286400..=303400 => "n50",
        295000..=303600 => "n74",
        342000..=357000 => "n3",
        376000..=384000 => "n39",
        386000..=399000 => "n2",
        402000..=405000 => "n34",
        422000..=434000 => "n1",
        434001..=440000 => "n66",
        460000..=480000 => "n40",
        496700..=499000 => "n53",
        499200..=513999 => "n41",
        514000..=523999 => "n38/n41",
        524000..=537996 => "n7/n41",
        537997..=538000 => "n7",
        620000..=636666 => "n77/n78",
        636667..=646666 => "n48/n77",
        646667..=653334 => "n77/n78",
        653335..=680000 => "n77",
        693334..=733333 => "n79",
        743334..=795000 => "n46",
        2016667..=2054165 => "n258",
        2054166..=2070832 => "n257/n258",
        2070833..=2087497 => "n257/n261",
        2087498..=2104165 => "n257",
        2229166..=2279165 => "n260",
        _ => "",
    };
    if band.is_empty() {
        format!("n?(ARFCN={})", arfcn)
    } else {
        format!("Band {}", band)
    }
}

/// Map LTE EARFCN to band string
pub fn earfcn_to_band(earfcn: u32) -> String {
    let band = match earfcn {
        0..=599 => "B1",
        600..=1199 => "B2",
        1200..=1949 => "B3",
        1950..=2399 => "B4",
        2400..=2649 => "B5",
        2650..=2749 => "B6",
        2750..=3449 => "B7",
        3450..=3799 => "B8",
        3800..=4149 => "B9",
        4150..=4749 => "B10",
        4750..=4949 => "B11",
        5010..=5179 => "B12",
        5180..=5279 => "B13",
        5280..=5379 => "B14",
        5730..=5849 => "B17",
        5850..=5999 => "B18",
        6000..=6149 => "B19",
        6150..=6449 => "B20",
        6450..=6599 => "B21",
        6600..=7399 => "B22",
        7500..=7699 => "B23",
        7700..=8039 => "B24",
        8040..=8689 => "B25",
        8690..=9039 => "B26",
        9040..=9209 => "B27",
        9210..=9659 => "B28",
        9660..=9769 => "B29",
        9770..=9869 => "B30",
        9870..=9919 => "B31",
        9920..=10359 => "B32",
        36000..=36199 => "B33",
        36200..=36349 => "B34",
        36350..=36949 => "B35",
        36950..=37549 => "B36",
        37550..=37749 => "B37",
        37750..=38249 => "B38",
        38250..=38649 => "B39",
        38650..=39649 => "B40",
        39650..=41589 => "B41",
        41590..=43589 => "B42",
        43590..=45589 => "B43",
        45590..=46589 => "B44",
        46590..=46789 => "B45",
        46790..=54539 => "B46",
        54540..=55239 => "B47",
        55240..=56739 => "B48",
        65536..=66435 => "B65",
        66436..=67335 => "B66",
        67336..=67535 => "B67",
        67536..=67835 => "B68",
        67836..=68335 => "B69",
        68336..=68585 => "B70",
        68586..=68935 => "B71",
        _ => "",
    };
    if band.is_empty() {
        format!("B?(EARFCN={})", earfcn)
    } else {
        format!("{}", band)
    }
}
