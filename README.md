# 🔐 pqc-tls-scanner

[![Python](https://img.shields.io/badge/python-3.8%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/YOUR_USERNAME/pqc-tls-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/pqc-tls-scanner/actions/workflows/ci.yml)
[![PQC](https://img.shields.io/badge/PQC-ML--KEM%20%2F%20Kyber-purple)](https://csrc.nist.gov/pubs/fips/203/final)

> Scan any HTTPS endpoint to detect whether it supports **Post-Quantum Cryptographic (PQC)** key exchange — specifically the ML-KEM suite (FIPS 203), hybrid groups, and draft Kyber variants.

---

## Why this matters

Quantum computers capable of breaking today's public-key cryptography (RSA, ECDH, …) are approaching viability. NIST finalized **ML-KEM** (FIPS 203, formerly Kyber) as the first standardized post-quantum KEM. Major CDNs — Cloudflare, Google, Amazon — already deploy hybrid PQC key exchange in TLS 1.3. This tool lets you audit any server's readiness.

---

## Features

- **3-layer detection strategy** — Python `ssl`, raw TLS 1.3 ClientHello, and `openssl s_client`
- Detects all standardized and draft **PQC TLS named groups**:
  - Pure ML-KEM: `MLKEM512 / 768 / 1024` (FIPS 203)
  - Hybrid: `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`
  - Draft Kyber: `X25519Kyber768Draft00`, `kyber512 / 768 / 1024`
  - OQS/vendor experimental groups
- Full **certificate inspection**: subject, SAN, issuer, pubkey algorithm & bits, SHA-256 fingerprint
- Clear **YES / NO / PARTIAL / UNKNOWN** verdict with explanation
- **JSON output** for scripting, CI pipelines, and dashboards
- **Colour-coded** terminal output; `--no-color` for log files
- Zero mandatory dependencies beyond the standard library (`cryptography` optional for cert detail)

---

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/pqc-tls-scanner.git
cd pqc-tls-scanner

# Install (optional — enhances certificate parsing)
pip install -r requirements.txt

# Run
python pqc_scanner.py cloudflare.com
```

---

## Usage

```
usage: pqc_scanner [-h] [--timeout SEC] [--no-openssl] [--no-color] [--json] target

positional arguments:
  target           URL or host[:port] to scan

options:
  -h, --help       show this help message and exit
  --timeout SEC    Socket timeout in seconds (default: 6)
  --no-openssl     Skip openssl s_client layer (pure Python)
  --no-color       Disable ANSI colour output
  --json           Output results as JSON
```

### Examples

```bash
# Basic scan
python pqc_scanner.py cloudflare.com

# Full URL
python pqc_scanner.py https://example.com

# Non-standard port
python pqc_scanner.py myserver.internal:8443

# Machine-readable JSON (CI/scripts)
python pqc_scanner.py example.com --json

# No external tools, pure Python
python pqc_scanner.py example.com --no-openssl

# Quiet log-friendly output
python pqc_scanner.py example.com --no-color --timeout 10 > scan.log
```

---

## Sample Output

```
────────────────────────────────────────────────────────────
  Target : cloudflare.com:443  (104.16.133.229)
────────────────────────────────────────────────────────────
  [1/3] Standard TLS handshake … done
  [2/3] PQC group negotiation probe … done
  [3/3] openssl s_client probe … done

╔══════════════════════════════════════════════════════════╗
║          PQC TLS Scanner — Scan Report                  ║
╚══════════════════════════════════════════════════════════╝

  Target    : cloudflare.com:443
  Resolved  : 104.16.133.229
  Scan time : 2026-05-04T19:50:45Z

  ── TLS Information ──────────────────────────────────────
  Version      : TLSv1.3
  Cipher suite : TLS_AES_256_GCM_SHA384
  Cipher bits  : 256

  Certificate:
    Subject  : CN=cloudflare.com
    Issuer   : CN=DigiCert TLS RSA SHA256 2020 CA1, …
    Valid    : 2025-01-01T00:00:00+00:00  →  2026-01-01T23:59:59+00:00
    SAN      : cloudflare.com, www.cloudflare.com
    PubKey   : EC (prime256v1) 256-bit
    SHA-256  : A2:5E:0E:9C:…

  ── PQC Probe ────────────────────────────────────────────
  Selected group ID   : 0x11ec
  Selected group name : X25519MLKEM768
  Is PQC group        : YES
  Hybrid (PQ+classic) : YES
  Standard/spec       : draft+FIPS 203

  ══ VERDICT ═════════════════════════════════════════════

    YES (Hybrid PQC)

  Server selected hybrid PQC key exchange: X25519MLKEM768
  (group 0x11ec, draft+FIPS 203). Classical + post-quantum
  security.
```

---

## How It Works

### Layer 1 — Python `ssl`
Standard TLS handshake using the built-in `ssl` module. Captures TLS version, cipher suite, and the server certificate (parsed in detail if `cryptography` is installed).

### Layer 2 — Raw TLS 1.3 ClientHello (definitive PQC probe)
Constructs a hand-crafted TLS 1.3 `ClientHello` that advertises **all known PQC `supported_groups`** in the extension. Parses the raw `ServerHello` bytes and inspects the `key_share` extension (type `0x0033`) to see exactly which group the server selected. This is the most reliable detection method.

```
Client → Server:  ClientHello
                    supported_groups: [X25519MLKEM768, SecP256r1MLKEM768,
                                       MLKEM768, X25519Kyber768Draft00,
                                       x25519, P-256, P-384, …]
Server → Client:  ServerHello
                    key_share: X25519MLKEM768   ← detected!
```

### Layer 3 — `openssl s_client` (optional)
Falls back to spawning `openssl s_client` with PQC group strings. Parses output for `Server Temp Key` and any PQC-related keywords. Useful when the system's OpenSSL is built with ML-KEM support (OpenSSL ≥ 3.5 or OQS-provider).

---

## PQC Group Registry

| Group ID   | Name                  | Hybrid | Spec              |
|------------|-----------------------|--------|-------------------|
| `0x11EC`   | X25519MLKEM768        | ✅     | draft + FIPS 203  |
| `0x11EB`   | SecP256r1MLKEM768     | ✅     | draft + FIPS 203  |
| `0x11ED`   | SecP384r1MLKEM1024    | ✅     | draft + FIPS 203  |
| `0xFE30`   | X25519Kyber768Draft00 | ✅     | draft             |
| `0xFE31`   | X25519Kyber512Draft00 | ✅     | draft             |
| `0x0248`   | MLKEM768              | ❌     | FIPS 203          |
| `0x0247`   | MLKEM512              | ❌     | FIPS 203          |
| `0x0249`   | MLKEM1024             | ❌     | FIPS 203          |
| `0x023A`   | kyber768              | ❌     | draft             |
| `0x0239`   | kyber512              | ❌     | draft             |
| `0x023B`   | kyber1024             | ❌     | draft             |
| `0x2F39`   | X25519Kyber768(OQS)   | ✅     | OQS/vendor        |

---

## Verdict Meanings

| Verdict | Meaning |
|---|---|
| **YES (Hybrid PQC)** | Server negotiated a classical + ML-KEM hybrid group — best practice today |
| **YES (Pure PQC)** | Server negotiated a pure ML-KEM group |
| **PARTIAL / LIKELY YES** | openssl detected PQC keywords but raw probe inconclusive (e.g. TLS inspection proxy) |
| **NO** | Server selected a classical group only |
| **UNKNOWN** | Probe failed (timeout, connection refused, TLS interception, etc.) |

---

## Known PQC-Enabled Servers (test targets)

| Host | Expected verdict |
|---|---|
| `cloudflare.com` | YES (Hybrid PQC) — X25519MLKEM768 |
| `www.google.com` | YES (Hybrid PQC) — X25519MLKEM768 |
| `s3.amazonaws.com` | YES (Hybrid PQC) |
| `pq.cloudflareresearch.com` | YES (Hybrid PQC) |

---

## Requirements

| Requirement | Notes |
|---|---|
| Python ≥ 3.8 | Core dependency |
| `cryptography` | Optional — enables full cert parsing |
| `openssl` in PATH | Optional — enables layer 3 probe |

---

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [IETF draft-connolly-tls-mlkem-key-agreement](https://datatracker.ietf.org/doc/draft-connolly-tls-mlkem-key-agreement/)
- [IETF draft-tls-westerbaan-xyber768d00](https://datatracker.ietf.org/doc/draft-tls-westerbaan-xyber768d00/)
- [Cloudflare: PQC in TLS 1.3](https://blog.cloudflare.com/post-quantum-crypto-ga/)
- [Open Quantum Safe (OQS) Project](https://openquantumsafe.org/)

---

## License

[MIT](LICENSE) © 2026
