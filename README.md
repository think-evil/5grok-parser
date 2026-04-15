# 5grok-parser

Standalone, self-contained DIAG frame parser for **Qualcomm**, **MediaTek**,
and **Samsung Shannon** cellular modems. Decodes NR/LTE/WCDMA/GSM signaling
into structured JSON with no runtime, no server, no database — just a library.

This crate is the parser core of the [5grok](https://github.com/yallasec/5grok)
project, extracted so it can be reused on its own.

## Coverage

| Layer        | NR (5G)                         | LTE (4G)                       |
|--------------|----------------------------------|--------------------------------|
| RRC          | OTA (legacy 0x1D0B + standard), MIB/SIB1 via ASN.1 UPER | OTA, MIB/SIB1 via ASN.1 UPER |
| NAS          | 5GMM / 5GSM deep parse (~95% of messages) | EMM / ESM deep parse           |
| ML1          | Serving/neighbor, SINR, beam mgmt | Serving/neighbor, SINR         |
| MAC/PDCP/RLC | TB, RACH, config, stats          | TB, RACH, config, stats        |
| PHY          | PDSCH, PUSCH, PDCCH, PUCCH (MCS, CQI, BLER, MIMO) | Same |

Vendor dispatch strips CCCI envelopes (MediaTek) and Shannon IPC headers
(Samsung) before reusing the shared NAS/RRC decoders.

## Usage

```toml
[dependencies]
fivegrok-parser = "0.1"
# Optional: full ASN.1 UPER decode of MIB/SIB1
# fivegrok-parser = { version = "0.1", features = ["asn1-rrc"] }
```

```rust
use fivegrok_parser::{DiagFrame, decode_agent_frame};

// DiagFrame::payload MUST be [log_code_le(2) || raw_diag_packet]
let frame = DiagFrame {
    sequence: 0,
    timestamp_wall: 0,
    timestamp_mono: 0,
    log_code: 0x1D0B, // NR_RRC_OTA (legacy Quectel/QXDM numbering)
    payload: raw_bytes,
    vendor: 0, // 0 = Qualcomm, 1 = MediaTek, 2 = Samsung
};

let decoded = decode_agent_frame(&frame);
println!("{} [{}]: {}", decoded.log_name, decoded.protocol, decoded.summary);
if let Some(json) = decoded.decoded {
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}
```

## Frame format

```
payload = [log_code_le(2 bytes)] || [raw DIAG packet]
raw DIAG packet (cmd 0x10 log) = cmd(1) more(1) outer_len(2) entry_len(2)
                                  log_code(2) timestamp(8) protocol_data(...)
```

Protocol bytes start at offset 18 of `payload` for standard Qualcomm log
packets. MediaTek and Samsung envelopes are stripped automatically when
`vendor` is set to 1 or 2.

## License

MIT
