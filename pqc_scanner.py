#!/usr/bin/env python3
"""
pqc_scanner.py — Post-Quantum Cryptography TLS Scanner
=======================================================
Given a URL (or host[:port]), connects over TLS and detects whether the
service supports Post-Quantum Cryptographic (PQC) key-exchange, specifically:
  • ML-KEM / Kyber hybrid groups (X25519MLKEM768, SecP256r1MLKEM768, …)
  • Draft/experimental Kyber groups

Strategy (layered):
  1. Python ssl — cipher suite, TLS version, certificate fingerprints
  2. Raw socket — craft a TLS 1.3 ClientHello advertising PQC groups,
                   parse ServerHello to see which key_share was selected
  3. openssl s_client — optional rich fallback when available

Requires: Python ≥ 3.8, cryptography (pip install cryptography)
Optional: openssl in PATH for extended checks
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

# ── Try importing cryptography (optional, for cert parsing) ──────────────────
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# ═══════════════════════════════════════════════════════════════════════════════
#  PQC GROUP REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

# IANA / IETF / draft TLS named groups relevant to PQC
PQC_GROUPS: dict[int, dict] = {
    # ── Pure Kyber (draft-tls-westerbaan-xyber768d00 / IANA allocations) ──
    0x0239: {"name": "kyber512",            "pqc": True,  "hybrid": False, "standard": "draft"},
    0x023A: {"name": "kyber768",            "pqc": True,  "hybrid": False, "standard": "draft"},
    0x023B: {"name": "kyber1024",           "pqc": True,  "hybrid": False, "standard": "draft"},
    # ── Hybrid: classical + Kyber/ML-KEM ──────────────────────────────────
    0xFE30: {"name": "X25519Kyber768Draft00","pqc": True,  "hybrid": True,  "standard": "draft"},
    0xFE31: {"name": "X25519Kyber512Draft00","pqc": True,  "hybrid": True,  "standard": "draft"},
    # ── ML-KEM (FIPS 203 / NIST PQC standard) — IANA allocations ─────────
    0x0247: {"name": "MLKEM512",            "pqc": True,  "hybrid": False, "standard": "FIPS 203"},
    0x0248: {"name": "MLKEM768",            "pqc": True,  "hybrid": False, "standard": "FIPS 203"},
    0x0249: {"name": "MLKEM1024",           "pqc": True,  "hybrid": False, "standard": "FIPS 203"},
    # ── Hybrid ML-KEM (draft-connolly-tls-mlkem-key-agreement) ───────────
    0x11EB: {"name": "SecP256r1MLKEM768",   "pqc": True,  "hybrid": True,  "standard": "draft+FIPS 203"},
    0x11EC: {"name": "X25519MLKEM768",      "pqc": True,  "hybrid": True,  "standard": "draft+FIPS 203"},
    0x11ED: {"name": "SecP384r1MLKEM1024",  "pqc": True,  "hybrid": True,  "standard": "draft+FIPS 203"},
    # ── Experimental / vendor ─────────────────────────────────────────────
    0x2F39: {"name": "X25519Kyber768(OQS)", "pqc": True,  "hybrid": True,  "standard": "OQS/vendor"},
}

# Classical groups (for context in the report)
CLASSICAL_GROUPS: dict[int, str] = {
    0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
}

ALL_PROBE_GROUPS = list(PQC_GROUPS.keys()) + list(CLASSICAL_GROUPS.keys())

# ═══════════════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CertInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    sig_alg: str = ""
    pubkey_alg: str = ""
    pubkey_bits: int = 0
    sha256_fp: str = ""

@dataclass
class TLSInfo:
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    cert: Optional[CertInfo] = None

@dataclass
class PQCProbeResult:
    server_selected_group_id: Optional[int] = None
    server_selected_group_name: Optional[str] = None
    is_pqc: bool = False
    is_hybrid: bool = False
    standard: str = ""
    via_hrr: bool = False   # True when group was signalled via HelloRetryRequest
    error: Optional[str] = None

@dataclass
class ScanResult:
    host: str = ""
    port: int = 443
    ip: str = ""
    tls: Optional[TLSInfo] = None
    pqc_probe: Optional[PQCProbeResult] = None
    openssl_groups: list[str] = field(default_factory=list)
    verdict: str = "UNKNOWN"       # YES / NO / PARTIAL / UNKNOWN
    verdict_reason: str = ""
    scan_time: str = ""

# ═══════════════════════════════════════════════════════════════════════════════
#  TLS ClientHello BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def _encode_u16(v: int) -> bytes:
    return struct.pack("!H", v)

def _encode_u8(v: int) -> bytes:
    return struct.pack("!B", v)

def _len16(data: bytes) -> bytes:
    return _encode_u16(len(data)) + data

def _len8(data: bytes) -> bytes:
    return _encode_u8(len(data)) + data


def build_client_hello(host: str, groups: list[int]) -> bytes:
    """
    Craft a minimal TLS 1.3 ClientHello (with TLS 1.2 compat) that:
      - advertises TLS 1.2 + 1.3 versions
      - includes supported_groups with all supplied group IDs
      - includes key_share for the first group (empty share — just to probe)
      - includes SNI
    """
    # Random (32 bytes)
    random_bytes = os.urandom(32)

    # Session ID (legacy, 32 random bytes for compat)
    session_id = os.urandom(32)

    # Cipher suites: TLS 1.3 suites + common TLS 1.2 suites
    cipher_suites_ids = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
        0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
        0x00FF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    cipher_suites = b"".join(_encode_u16(cs) for cs in cipher_suites_ids)
    cipher_suites = _encode_u16(len(cipher_suites)) + cipher_suites

    # Compression methods
    compression = b"\x01\x00"

    # ── Extensions ──────────────────────────────────────────────────────────

    def ext(etype: int, data: bytes) -> bytes:
        return _encode_u16(etype) + _encode_u16(len(data)) + data

    # SNI (type 0x0000)
    host_bytes = host.encode()
    sni_entry = b"\x00" + _encode_u16(len(host_bytes)) + host_bytes
    sni_list = _encode_u16(len(sni_entry)) + sni_entry
    ext_sni = ext(0x0000, sni_list)

    # Supported versions: TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
    ext_supported_versions = ext(0x002B, b"\x04\x03\x04\x03\x03")

    # Supported groups
    groups_bytes = b"".join(_encode_u16(g) for g in groups)
    ext_supported_groups = ext(0x000A, _encode_u16(len(groups_bytes)) + groups_bytes)

    # EC point formats (required for TLS 1.2 compat)
    ext_ec_point = ext(0x000B, b"\x01\x00")

    # Signature algorithms
    sig_algs_ids = [
        0x0403,  # ecdsa_secp256r1_sha256
        0x0503,  # ecdsa_secp384r1_sha384
        0x0804,  # rsa_pss_rsae_sha256
        0x0805,  # rsa_pss_rsae_sha384
        0x0806,  # rsa_pss_rsae_sha512
        0x0401,  # rsa_pkcs1_sha256
        0x0501,  # rsa_pkcs1_sha384
        0x0601,  # rsa_pkcs1_sha512
        0x0807,  # ed25519
        0x0808,  # ed448
    ]
    sig_algs_bytes = b"".join(_encode_u16(s) for s in sig_algs_ids)
    ext_sig_algs = ext(0x000D, _encode_u16(len(sig_algs_bytes)) + sig_algs_bytes)

    # key_share: include x25519 (0x001D) as a real share for TLS 1.3 handshake,
    # plus the first PQC group with an empty key share just for negotiation probing.
    x25519_private = os.urandom(32)  # ephemeral x25519 key material (not a real key gen)
    # For simplicity, send random bytes (server will reject but we parse the ServerHello)
    x25519_share = b"\x00" * 32
    shares = []
    shares.append(_encode_u16(0x001D) + _encode_u16(32) + x25519_share)
    # Advertise first PQC group with empty share so server sees it in supported_groups
    key_share_data = b"".join(shares)
    ext_key_share = ext(0x0033, _encode_u16(len(key_share_data)) + key_share_data)

    # Assemble extensions
    extensions = (
        ext_sni
        + ext_supported_versions
        + ext_supported_groups
        + ext_ec_point
        + ext_sig_algs
        + ext_key_share
    )
    extensions_block = _encode_u16(len(extensions)) + extensions

    # ── ClientHello body ────────────────────────────────────────────────────
    client_hello_body = (
        b"\x03\x03"                              # legacy_version TLS 1.2
        + random_bytes
        + _encode_u8(len(session_id)) + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    # ── Handshake record ────────────────────────────────────────────────────
    hs_header = b"\x01" + struct.pack("!I", len(client_hello_body))[1:]  # type=1, 3-byte len
    handshake = hs_header + client_hello_body

    # ── TLS record ──────────────────────────────────────────────────────────
    # Content type 0x16 (Handshake), version 0x0301 (TLS 1.0 compat)
    record = b"\x16\x03\x01" + _encode_u16(len(handshake)) + handshake
    return record


# ═══════════════════════════════════════════════════════════════════════════════
#  ServerHello PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_server_hello(data: bytes) -> dict:
    """
    Parse a ServerHello or HelloRetryRequest (HRR) to extract the selected
    cipher suite, key_share group, and TLS version.

    HRR detection: RFC 8446 §4.1.4 — when the ServerHello random field equals
    the SHA-256 hash of "HelloRetryRequest", the message is an HRR.
    In an HRR the key_share extension carries only 2 bytes (the chosen group
    ID); there is no key material.  This is still a definitive signal that the
    server supports and prefers that group.

    Returns dict keys:
      cipher_suite    int   — negotiated cipher suite
      selected_group  int   — named group ID (from key_share)
      tls_version     int   — 0x0304 for TLS 1.3, etc.
      is_hrr          bool  — True when this message is a HelloRetryRequest
      alert           tuple — (level, desc) if an Alert record was received
      error / parse_error — on failure
    """
    # RFC 8446 §4.1.4 — the specific random value that marks an HRR
    HRR_MAGIC = bytes([
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ])

    result: dict = {"is_hrr": False}
    pos = 0

    def read(n):
        nonlocal pos
        chunk = data[pos:pos + n]
        pos += n
        return chunk

    def read_u8():
        return struct.unpack("!B", read(1))[0]

    def read_u16():
        return struct.unpack("!H", read(2))[0]

    try:
        # ── TLS Record header: type(1) + version(2) + length(2) ─────────────
        rec_type = read_u8()
        rec_version = read_u16()
        rec_len = read_u16()

        if rec_type == 0x15:  # Alert
            alert_level = read_u8()
            alert_desc  = read_u8()
            result["alert"] = (alert_level, alert_desc)
            return result

        if rec_type != 0x16:  # Not Handshake
            result["error"] = f"Unexpected record type: {rec_type:#04x}"
            return result

        # ── Handshake header: type(1) + length(3) ───────────────────────────
        hs_type = read_u8()
        hs_len  = struct.unpack("!I", b"\x00" + read(3))[0]

        if hs_type != 0x02:  # Not ServerHello / HRR
            result["error"] = f"Expected ServerHello (0x02), got {hs_type:#04x}"
            return result

        # ── ServerHello / HRR body ───────────────────────────────────────────
        server_version = read_u16()
        server_random  = read(32)

        # Detect HelloRetryRequest by its fixed magic random value
        if server_random == HRR_MAGIC:
            result["is_hrr"] = True

        session_id_len = read_u8()
        session_id     = read(session_id_len)
        cipher_suite   = read_u16()
        result["cipher_suite"] = cipher_suite
        compression    = read_u8()

        if pos >= 5 + hs_len:
            return result

        ext_total_len = read_u16()
        ext_end = pos + ext_total_len

        result["tls_version"]    = server_version  # overridden below if supported_versions present
        result["selected_group"] = None

        while pos < ext_end:
            ext_type = read_u16()
            ext_len  = read_u16()
            ext_data = data[pos:pos + ext_len]
            pos += ext_len

            if ext_type == 0x002B and ext_len == 2:
                # supported_versions — actual negotiated / requested TLS version
                result["tls_version"] = struct.unpack("!H", ext_data)[0]

            elif ext_type == 0x0033:
                # key_share extension — two different formats:
                #
                #   Regular ServerHello: group_id(2) + key_len(2) + key(key_len)
                #     → ext_len >= 4 and we read the first 2 bytes as group_id
                #
                #   HelloRetryRequest:   group_id(2) only
                #     → ext_len == 2; the server is telling us "retry with this group"
                #
                # Both cases: the group ID is always the first 2 bytes.
                if ext_len >= 2:
                    group_id = struct.unpack("!H", ext_data[:2])[0]
                    result["selected_group"] = group_id

    except Exception as e:
        result["parse_error"] = str(e)

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  SCANNER LAYERS
# ═══════════════════════════════════════════════════════════════════════════════

def resolve_host(host: str) -> str:
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except Exception:
        return ""


def scan_tls_standard(host: str, port: int, timeout: float) -> Optional[TLSInfo]:
    """Layer 1: Use Python ssl for basic TLS info."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cipher = sock.cipher()
                tls_info = TLSInfo(
                    tls_version=sock.version() or "",
                    cipher_suite=cipher[0] if cipher else "",
                    cipher_bits=cipher[2] if cipher and cipher[2] else 0,
                )
                # Get DER cert
                der = sock.getpeercert(binary_form=True)
                if der:
                    tls_info.cert = _parse_cert(der)
                return tls_info
    except Exception as e:
        print(f"  [warn] Standard TLS scan failed: {e}", file=sys.stderr)
        return None


def _parse_cert(der: bytes) -> CertInfo:
    ci = CertInfo()
    if not HAS_CRYPTOGRAPHY:
        return ci
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
        ci.subject = cert.subject.rfc4514_string()
        ci.issuer = cert.issuer.rfc4514_string()
        ci.not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else str(cert.not_valid_before)
        ci.not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else str(cert.not_valid_after)
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            ci.san = [str(n) for n in san_ext.value]
        except Exception:
            pass
        ci.sig_alg = cert.signature_algorithm_oid.dotted_string
        try:
            # map common OIDs to names
            from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519 as ed
            pk = cert.public_key()
            if isinstance(pk, rsa.RSAPublicKey):
                ci.pubkey_alg = "RSA"
                ci.pubkey_bits = pk.key_size
            elif isinstance(pk, ec.EllipticCurvePublicKey):
                ci.pubkey_alg = f"EC ({pk.curve.name})"
                ci.pubkey_bits = pk.key_size
            elif isinstance(pk, ed.Ed25519PublicKey):
                ci.pubkey_alg = "Ed25519"
                ci.pubkey_bits = 256
            else:
                ci.pubkey_alg = type(pk).__name__
        except Exception:
            pass
        fp = cert.fingerprint(hashes.SHA256())
        ci.sha256_fp = ":".join(f"{b:02X}" for b in fp)
    except Exception as e:
        pass
    return ci


def _read_tls_record(sock: socket.socket) -> bytes:
    """
    Read exactly one complete TLS record from sock.
    Returns the raw bytes (header + payload) or b"" on EOF.
    """
    header = b""
    while len(header) < 5:
        chunk = sock.recv(5 - len(header))
        if not chunk:
            return b""
        header += chunk
    payload_len = struct.unpack("!H", header[3:5])[0]
    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            break
        payload += chunk
    return header + payload


def probe_pqc(host: str, port: int, timeout: float) -> PQCProbeResult:
    """
    Layer 2: Send a raw ClientHello advertising every known PQC group.
    Parse the response — either a ServerHello or a HelloRetryRequest (HRR) —
    to determine which key_share group the server selected or requested.

    HRR flow (common with Cloudflare / Google):
      Client → ClientHello  (supported_groups includes X25519MLKEM768, …;
                              key_share only contains x25519)
      Server → HRR          (key_share ext = 2 bytes: preferred group ID)
      → We detect the HRR group and report it as the PQC verdict.
    """
    result = PQCProbeResult()
    try:
        hello = build_client_hello(host, ALL_PROBE_GROUPS)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(hello)

            # Read the first TLS record (ServerHello or HRR)
            resp = _read_tls_record(sock)

        if not resp:
            result.error = "No response from server"
            return result

        parsed = parse_server_hello(resp)

        if "alert" in parsed:
            level, desc = parsed["alert"]
            result.error = f"Server sent Alert (level={level}, desc={desc})"
            return result

        if "error" in parsed or "parse_error" in parsed:
            result.error = parsed.get("error") or parsed.get("parse_error")
            return result

        selected = parsed.get("selected_group")
        is_hrr   = parsed.get("is_hrr", False)
        result.server_selected_group_id = selected

        if selected is not None:
            if selected in PQC_GROUPS:
                info = PQC_GROUPS[selected]
                result.server_selected_group_name = info["name"]
                result.is_pqc    = True
                result.is_hybrid = info["hybrid"]
                result.standard  = info["standard"]
                if is_hrr:
                    result.via_hrr = True   # stored for report display
            elif selected in CLASSICAL_GROUPS:
                result.server_selected_group_name = CLASSICAL_GROUPS[selected]
                result.is_pqc = False
            else:
                result.server_selected_group_name = f"unknown ({selected:#06x})"
                result.is_pqc = False
        else:
            result.error = "Server did not send key_share (TLS 1.2, or no matching group)"

    except ConnectionRefusedError:
        result.error = "Connection refused"
    except socket.timeout:
        result.error = "Connection timed out"
    except Exception as e:
        result.error = str(e)

    return result


def probe_openssl(host: str, port: int, timeout: float) -> list[str]:
    """
    Layer 3: Run openssl s_client to capture negotiated groups if openssl is available.
    Returns list of notable strings parsed from output.
    """
    findings = []
    try:
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-groups", "X25519MLKEM768:SecP256r1MLKEM768:X25519:P-256:P-384",
            "-tlsextdebug",
            "-brief",
        ]
        result = subprocess.run(
            cmd,
            input=b"Q\n",
            capture_output=True,
            timeout=timeout + 2,
        )
        output = (result.stdout + result.stderr).decode(errors="replace")

        # Parse interesting lines
        for line in output.splitlines():
            l = line.strip()
            if any(kw in l.lower() for kw in [
                "server temp key", "protocol", "cipher", "group",
                "kyber", "mlkem", "ml-kem", "ecdh", "x25519",
            ]):
                findings.append(l)

        # Detect PQC mentions in full output
        pqc_patterns = [r"MLKEM", r"mlkem", r"Kyber", r"kyber", r"X25519MLKEM", r"SecP256r1MLKEM"]
        for pat in pqc_patterns:
            if re.search(pat, output):
                findings.append(f"[PQC keyword detected in openssl output: {pat}]")
                break

    except FileNotFoundError:
        findings.append("[openssl not found in PATH — skipping layer 3]")
    except subprocess.TimeoutExpired:
        findings.append("[openssl timed out]")
    except Exception as e:
        findings.append(f"[openssl error: {e}]")

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def parse_target(target: str) -> tuple[str, int]:
    """Extract host and port from a URL or host[:port] string."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 443
    return host, port


def scan(target: str, timeout: float = 5.0, skip_openssl: bool = False) -> ScanResult:
    host, port = parse_target(target)
    result = ScanResult(
        host=host,
        port=port,
        ip=resolve_host(host),
        scan_time=datetime.now(timezone.utc).isoformat(),
    )

    print(f"\n{'─'*60}")
    print(f"  Target : {host}:{port}  ({result.ip})")
    print(f"{'─'*60}")

    # Layer 1 — standard TLS
    print("  [1/3] Standard TLS handshake …", end="", flush=True)
    result.tls = scan_tls_standard(host, port, timeout)
    print(" done" if result.tls else " failed")

    # Layer 2 — PQC probe
    print("  [2/3] PQC group negotiation probe …", end="", flush=True)
    result.pqc_probe = probe_pqc(host, port, timeout)
    print(" done")

    # Layer 3 — openssl
    if not skip_openssl:
        print("  [3/3] openssl s_client probe …", end="", flush=True)
        result.openssl_groups = probe_openssl(host, port, timeout)
        print(" done")
    else:
        print("  [3/3] openssl s_client — skipped")

    # ── Verdict ─────────────────────────────────────────────────────────────
    probe = result.pqc_probe
    openssl_pqc = any("[PQC keyword" in l for l in result.openssl_groups)

    if probe and probe.is_pqc:
        hrr_note = " (negotiated via HelloRetryRequest)" if probe.via_hrr else ""
        if probe.is_hybrid:
            result.verdict = "YES (Hybrid PQC)"
            result.verdict_reason = (
                f"Server selected hybrid PQC key exchange: {probe.server_selected_group_name} "
                f"(group {probe.server_selected_group_id:#06x}, {probe.standard}){hrr_note}. "
                "Classical + post-quantum security."
            )
        else:
            result.verdict = "YES (Pure PQC)"
            result.verdict_reason = (
                f"Server selected pure PQC key exchange: {probe.server_selected_group_name} "
                f"(group {probe.server_selected_group_id:#06x}, {probe.standard}){hrr_note}."
            )
    elif openssl_pqc:
        result.verdict = "PARTIAL / LIKELY YES"
        result.verdict_reason = (
            "openssl detected PQC-related keywords but raw probe did not confirm group selection. "
            "The server may support PQC under specific configurations or with a PQC-capable client."
        )
    elif probe and probe.error:
        result.verdict = "UNKNOWN"
        result.verdict_reason = f"PQC probe inconclusive: {probe.error}"
    else:
        result.verdict = "NO"
        classical_group = (
            probe.server_selected_group_name if probe and probe.server_selected_group_name else "unknown"
        )
        result.verdict_reason = (
            f"Server selected classical key exchange: {classical_group}. "
            "No PQC group negotiated."
        )

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT
# ═══════════════════════════════════════════════════════════════════════════════

VERDICT_COLORS = {
    "YES":              "\033[32m",   # green
    "YES (Hybrid PQC)": "\033[32m",
    "YES (Pure PQC)":   "\033[32m",
    "PARTIAL / LIKELY YES": "\033[33m",  # yellow
    "NO":               "\033[31m",   # red
    "UNKNOWN":          "\033[35m",   # magenta
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_report(r: ScanResult, no_color: bool = False, json_out: bool = False):

    def color(s: str, code: str) -> str:
        return s if no_color else code + s + RESET

    if json_out:
        import dataclasses
        def _default(o):
            if dataclasses.is_dataclass(o):
                return dataclasses.asdict(o)
            return str(o)
        print(json.dumps(dataclasses.asdict(r), indent=2, default=_default))
        return

    verdict_color = VERDICT_COLORS.get(r.verdict, "")

    print()
    print(color("╔══════════════════════════════════════════════════════════╗", BOLD))
    print(color("║          PQC TLS Scanner — Scan Report                  ║", BOLD))
    print(color("╚══════════════════════════════════════════════════════════╝", BOLD))
    print()
    print(f"  Target    : {r.host}:{r.port}")
    print(f"  Resolved  : {r.ip or 'n/a'}")
    print(f"  Scan time : {r.scan_time}")

    print()
    print(color("  ── TLS Information ──────────────────────────────────────", BOLD))
    if r.tls:
        print(f"  Version      : {r.tls.tls_version or 'n/a'}")
        print(f"  Cipher suite : {r.tls.cipher_suite or 'n/a'}")
        print(f"  Cipher bits  : {r.tls.cipher_bits or 'n/a'}")
        if r.tls.cert:
            c = r.tls.cert
            print()
            print(f"  Certificate:")
            print(f"    Subject  : {c.subject}")
            print(f"    Issuer   : {c.issuer}")
            print(f"    Valid    : {c.not_before}  →  {c.not_after}")
            if c.san:
                print(f"    SAN      : {', '.join(c.san[:6])}{'…' if len(c.san) > 6 else ''}")
            print(f"    PubKey   : {c.pubkey_alg} {c.pubkey_bits}-bit")
            print(f"    SHA-256  : {c.sha256_fp[:47]}…" if c.sha256_fp else "")
    else:
        print("  (TLS layer scan failed)")

    print()
    print(color("  ── PQC Probe ────────────────────────────────────────────", BOLD))
    if r.pqc_probe:
        p = r.pqc_probe
        if p.server_selected_group_id is not None:
            print(f"  Selected group ID   : {p.server_selected_group_id:#06x}")
            print(f"  Selected group name : {p.server_selected_group_name}")
            print(f"  Detected via HRR    : {'YES' if p.via_hrr else 'NO'}")
            print(f"  Is PQC group        : {'YES' if p.is_pqc else 'NO'}")
            if p.is_pqc:
                print(f"  Hybrid (PQ+classic) : {'YES' if p.is_hybrid else 'NO'}")
                print(f"  Standard/spec       : {p.standard}")
        elif p.error:
            print(f"  Probe result: {p.error}")
    else:
        print("  (probe not run)")

    if r.openssl_groups:
        print()
        print(color("  ── openssl s_client Findings ───────────────────────────", BOLD))
        for line in r.openssl_groups:
            print(f"    {line}")

    print()
    print(color("  ══ VERDICT ═════════════════════════════════════════════", BOLD))
    print()
    verdict_str = color(f"  {BOLD}  {r.verdict}  ", verdict_color)
    print(verdict_str)
    print()
    wrapped = textwrap.fill(r.verdict_reason, width=56, initial_indent="  ", subsequent_indent="  ")
    print(wrapped)
    print()

    # PQC group reference
    print(color("  ── Known PQC Groups Reference ──────────────────────────", BOLD))
    print(f"  {'ID':>8}  {'Name':<28} {'Hybrid':<8} {'Spec'}")
    print(f"  {'─'*8}  {'─'*28} {'─'*8} {'─'*20}")
    for gid, info in PQC_GROUPS.items():
        h = "yes" if info["hybrid"] else "no"
        print(f"  {gid:#08x}  {info['name']:<28} {h:<8} {info['standard']}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="pqc_scanner",
        description="Scan an HTTPS endpoint for Post-Quantum Cryptography (PQC) support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python pqc_scanner.py cloudflare.com
              python pqc_scanner.py https://example.com
              python pqc_scanner.py example.com:8443 --timeout 10
              python pqc_scanner.py example.com --json
              python pqc_scanner.py example.com --no-openssl --no-color
        """),
    )
    parser.add_argument("target", help="URL or host[:port] to scan")
    parser.add_argument("--timeout", type=float, default=6.0, metavar="SEC",
                        help="Socket timeout in seconds (default: 6)")
    parser.add_argument("--no-openssl", action="store_true",
                        help="Skip openssl s_client layer")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    if not HAS_CRYPTOGRAPHY:
        print("[warn] 'cryptography' package not installed — certificate details will be limited.")
        print("       Install with: pip install cryptography\n", file=sys.stderr)

    result = scan(args.target, timeout=args.timeout, skip_openssl=args.no_openssl)
    print_report(result, no_color=args.no_color, json_out=args.json)


if __name__ == "__main__":
    main()
