Architecture — 3 Layers
Layer 1 — Python ssl — standard TLS handshake to capture: TLS version, cipher suite, full certificate chain (subject, issuer, SAN, public key algorithm & bit size, SHA-256 fingerprint).
Layer 2 — Raw ClientHello probe — crafts a hand-built TLS 1.3 ClientHello that advertises all known PQC supported_groups. It then parses the ServerHello's key_share extension to see exactly which group the server selected. This is the definitive PQC detection method.
Layer 3 — openssl s_client — subprocess fallback with PQC group strings, parses output for Server Temp Key, group names, and any PQC keyword (MLKEM, Kyber, etc.).


PQC Group Registry (all detected)
Group IDNameHybrid?Spec0x11ECX25519MLKEM768
✅draft+FIPS 2030x11EBSecP256r1MLKEM768
✅draft+FIPS 2030x11EDSecP384r1MLKEM1024
✅draft+FIPS 2030xFE30X25519Kyber768Draft00
✅draft0x0248MLKEM768 (pure)
❌FIPS 203…Kyber512/768/1024
❌draft

Usage
bash# Install dependency
pip install cryptography

# Basic scan
python pqc_scanner.py cloudflare.com

# Custom port
python pqc_scanner.py myserver.example.com:8443

# Machine-readable JSON output (great for CI/scripting)
python pqc_scanner.py example.com --json

# Skip openssl layer (pure Python, no external tools)
python pqc_scanner.py example.com --no-openssl

# No ANSI colors (for logs/files)
python pqc_scanner.py example.com --no-color --timeout 10
Verdict values: YES (Hybrid PQC) / YES (Pure PQC) / PARTIAL / LIKELY YES / NO / UNKNOWN
