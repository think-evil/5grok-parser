//! Shared NAS utilities: cause codes, identity types, security algorithms

/// 5GMM cause codes from 3GPP TS 24.501 Table 9.11.3.2.1.
pub fn fgmm_cause_name(cause: u8) -> &'static str {
    match cause {
        3 => "Illegal UE",
        5 => "PEI not accepted",
        6 => "Illegal ME",
        7 => "5GS services not allowed",
        9 => "UE identity cannot be derived",
        10 => "Implicitly deregistered",
        11 => "PLMN not allowed",
        12 => "Tracking area not allowed",
        13 => "Roaming not allowed in TA",
        15 => "No suitable cells in TA",
        20 => "MAC failure",
        21 => "Synch failure",
        22 => "Congestion",
        23 => "UE security capabilities mismatch",
        24 => "Security mode rejected unspecified",
        26 => "Non-5G authentication unacceptable",
        27 => "N1 mode not allowed",
        28 => "Restricted service area",
        31 => "Redirection to EPC",
        43 => "LADN not available",
        62 => "No network slices available",
        65 => "Max PDU sessions reached",
        67 => "Insufficient resources for slice and DNN",
        69 => "Insufficient resources for slice",
        71 => "ngKSI already in use",
        72 => "Non-3GPP access to 5GCN not allowed",
        73 => "Serving network not authorized",
        74 => "Temporarily not authorized",
        75 => "Permanently not authorized",
        76 => "Not authorized for CAG",
        77 => "Wireline access area not allowed",
        90 => "Payload was not forwarded",
        91 => "DNN not supported or not subscribed",
        92 => "Insufficient user-plane resources for PDU session",
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent",
        98 => "Message type not compatible",
        99 => "Information element non-existent",
        100 => "Conditional IE error",
        101 => "Message not compatible",
        111 => "Protocol error unspecified",
        _ => "Unknown",
    }
}

/// LTE EMM cause codes from 3GPP TS 24.301 Table 9.9.3.9.1.
pub fn emm_cause_name(cause: u8) -> &'static str {
    match cause {
        2 => "IMSI unknown in HSS",
        3 => "Illegal UE",
        5 => "IMEI not accepted",
        6 => "Illegal ME",
        7 => "EPS services not allowed",
        8 => "EPS and non-EPS services not allowed",
        9 => "UE identity cannot be derived",
        10 => "Implicitly detached",
        11 => "PLMN not allowed",
        12 => "Tracking area not allowed",
        13 => "Roaming not allowed",
        14 => "EPS services not allowed in PLMN",
        15 => "No suitable cells",
        16 => "MSC temporarily not reachable",
        17 => "Network failure",
        18 => "CS domain not available",
        19 => "ESM failure",
        20 => "MAC failure",
        21 => "Synch failure",
        22 => "Congestion",
        23 => "UE security capabilities mismatch",
        24 => "Security mode rejected unspecified",
        25 => "Not authorized for CSG",
        26 => "Non-EPS authentication unacceptable",
        35 => "Requested service option not authorized",
        39 => "CS service temporarily not available",
        40 => "No EPS bearer context activated",
        42 => "Severe network failure",
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent",
        98 => "Message type not compatible",
        99 => "IE non-existent",
        100 => "Conditional IE error",
        101 => "Message not compatible",
        111 => "Protocol error unspecified",
        _ => "Unknown",
    }
}

/// ESM cause codes from 3GPP TS 24.301 Table 9.9.4.4.1.
pub fn esm_cause_name(cause: u8) -> &'static str {
    match cause {
        8 => "Operator determined barring",
        26 => "Insufficient resources",
        27 => "Missing or unknown APN",
        28 => "Unknown PDN type",
        29 => "User authentication failed",
        30 => "Request rejected by SGW/PGW",
        31 => "Request rejected unspecified",
        32 => "Service option not supported",
        33 => "Requested service option not subscribed",
        34 => "Service option temporarily out of order",
        35 => "PTI already in use",
        36 => "Regular deactivation",
        37 => "EPS QoS not accepted",
        38 => "Network failure",
        39 => "Reactivation requested",
        41 => "Semantic error in TFT",
        42 => "Syntactical error in TFT",
        43 => "Unknown EPS bearer context",
        44 => "Semantic errors in packet filter",
        45 => "Syntactical errors in packet filter",
        46 => "EPS bearer context without TFT already active",
        50 => "PDN type IPv4 only allowed",
        51 => "PDN type IPv6 only allowed",
        52 => "Single address bearers only",
        53 => "ESM information not received",
        54 => "PDN connection does not exist",
        55 => "Multiple PDN connections for given APN not allowed",
        56 => "Collision with network initiated request",
        59 => "Unsupported QCI value",
        95 => "Semantically incorrect message",
        96 => "Invalid mandatory information",
        97 => "Message type non-existent",
        98 => "Message type not compatible with protocol state",
        99 => "Information element non-existent",
        100 => "Conditional IE error",
        101 => "Message not compatible with protocol state",
        111 => "Protocol error unspecified",
        112 => "APN restriction value incompatible",
        _ => "Unknown",
    }
}

/// 5G identity types from 3GPP TS 24.501.
pub fn identity_type_5g_name(t: u8) -> &'static str {
    match t {
        1 => "SUCI",
        2 => "5G-GUTI",
        3 => "IMEI",
        4 => "5G-S-TMSI",
        5 => "IMEISV",
        6 => "MAC address",
        7 => "EUI-64",
        _ => "Unknown",
    }
}

/// LTE identity types from 3GPP TS 24.301.
pub fn identity_type_lte_name(t: u8) -> &'static str {
    match t {
        1 => "IMSI",
        2 => "IMEI",
        3 => "IMEISV",
        4 => "TMSI",
        _ => "Unknown",
    }
}

/// 5G NAS ciphering algorithm identifiers.
pub fn security_algo_5g_cipher(id: u8) -> &'static str {
    match id {
        0 => "5G-EA0 (null)",
        1 => "128-5G-EA1 (SNOW3G)",
        2 => "128-5G-EA2 (AES)",
        3 => "128-5G-EA3 (ZUC)",
        _ => "Unknown",
    }
}

/// 5G NAS integrity protection algorithm identifiers.
pub fn security_algo_5g_integrity(id: u8) -> &'static str {
    match id {
        0 => "5G-IA0 (null)",
        1 => "128-5G-IA1 (SNOW3G)",
        2 => "128-5G-IA2 (AES)",
        3 => "128-5G-IA3 (ZUC)",
        _ => "Unknown",
    }
}

/// LTE NAS ciphering algorithm identifiers.
pub fn security_algo_lte_cipher(id: u8) -> &'static str {
    match id {
        0 => "EEA0 (null)",
        1 => "128-EEA1 (SNOW3G)",
        2 => "128-EEA2 (AES)",
        3 => "128-EEA3 (ZUC)",
        _ => "Unknown",
    }
}

/// LTE NAS integrity protection algorithm identifiers.
pub fn security_algo_lte_integrity(id: u8) -> &'static str {
    match id {
        0 => "EIA0 (null)",
        1 => "128-EIA1 (SNOW3G)",
        2 => "128-EIA2 (AES)",
        3 => "128-EIA3 (ZUC)",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fgmm_cause() {
        assert_eq!(fgmm_cause_name(3), "Illegal UE");
        assert_eq!(fgmm_cause_name(22), "Congestion");
        assert_eq!(fgmm_cause_name(111), "Protocol error unspecified");
        assert_eq!(fgmm_cause_name(255), "Unknown");
    }

    #[test]
    fn test_emm_cause() {
        assert_eq!(emm_cause_name(2), "IMSI unknown in HSS");
        assert_eq!(emm_cause_name(22), "Congestion");
        assert_eq!(emm_cause_name(111), "Protocol error unspecified");
        assert_eq!(emm_cause_name(255), "Unknown");
    }

    #[test]
    fn test_identity_types() {
        // 5G identity types
        assert_eq!(identity_type_5g_name(1), "SUCI");
        assert_eq!(identity_type_5g_name(2), "5G-GUTI");
        assert_eq!(identity_type_5g_name(3), "IMEI");
        assert_eq!(identity_type_5g_name(4), "5G-S-TMSI");
        assert_eq!(identity_type_5g_name(5), "IMEISV");
        assert_eq!(identity_type_5g_name(6), "MAC address");
        assert_eq!(identity_type_5g_name(7), "EUI-64");
        assert_eq!(identity_type_5g_name(0), "Unknown");
        assert_eq!(identity_type_5g_name(255), "Unknown");

        // LTE identity types
        assert_eq!(identity_type_lte_name(1), "IMSI");
        assert_eq!(identity_type_lte_name(2), "IMEI");
        assert_eq!(identity_type_lte_name(3), "IMEISV");
        assert_eq!(identity_type_lte_name(4), "TMSI");
        assert_eq!(identity_type_lte_name(0), "Unknown");
        assert_eq!(identity_type_lte_name(255), "Unknown");
    }

    #[test]
    fn test_security_algos() {
        // 5G ciphering
        assert_eq!(security_algo_5g_cipher(0), "5G-EA0 (null)");
        assert_eq!(security_algo_5g_cipher(1), "128-5G-EA1 (SNOW3G)");
        assert_eq!(security_algo_5g_cipher(2), "128-5G-EA2 (AES)");
        assert_eq!(security_algo_5g_cipher(3), "128-5G-EA3 (ZUC)");
        assert_eq!(security_algo_5g_cipher(255), "Unknown");

        // 5G integrity
        assert_eq!(security_algo_5g_integrity(0), "5G-IA0 (null)");
        assert_eq!(security_algo_5g_integrity(1), "128-5G-IA1 (SNOW3G)");
        assert_eq!(security_algo_5g_integrity(2), "128-5G-IA2 (AES)");
        assert_eq!(security_algo_5g_integrity(3), "128-5G-IA3 (ZUC)");
        assert_eq!(security_algo_5g_integrity(255), "Unknown");

        // LTE ciphering
        assert_eq!(security_algo_lte_cipher(0), "EEA0 (null)");
        assert_eq!(security_algo_lte_cipher(1), "128-EEA1 (SNOW3G)");
        assert_eq!(security_algo_lte_cipher(2), "128-EEA2 (AES)");
        assert_eq!(security_algo_lte_cipher(3), "128-EEA3 (ZUC)");
        assert_eq!(security_algo_lte_cipher(255), "Unknown");

        // LTE integrity
        assert_eq!(security_algo_lte_integrity(0), "EIA0 (null)");
        assert_eq!(security_algo_lte_integrity(1), "128-EIA1 (SNOW3G)");
        assert_eq!(security_algo_lte_integrity(2), "128-EIA2 (AES)");
        assert_eq!(security_algo_lte_integrity(3), "128-EIA3 (ZUC)");
        assert_eq!(security_algo_lte_integrity(255), "Unknown");
    }
}
