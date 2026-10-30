#!/usr/bin/env python3
# Etuki Standalone Cryptographic & 563-Leaf Merkle Verifier (v34-truth)
# Second-Channel Public Mirror: https://github.com/cooyun/etuki-gate/blob/main/verify-etuki.py
# Usage: curl -sSfL https://www.etuki.com/verify-etuki.py | python3 -
import json, hashlib, urllib.request

BASE = "https://www.etuki.com"
EXPECTED_BUILD_VER   = "2026.10.30-v34-release"
EXPECTED_SCHEMA_VER  = "2026.10.30-v34-unified"
EXPECTED_SNAP_ID     = "price-20261030-v34-truth"
EXPECTED_PAYLOAD_SHA = "cbbc272fa1eb7392a4de15bc958b435b7f03b52c6327d31bbd6cf920ee938b1a"
EXPECTED_MERKLE_ROOT = "113ab79263c9a3a3e77b0a3da2ff4ad96a215156ebd5a62b1a920581949a8caf"
EXPECTED_CSV_ROOT    = "7d0c01eb444c235420208a6f32716158aa03d7369772dc026b546ecd61948804"

def fetch(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Etuki-Standalone-Verifier/34.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read().decode("utf-8")

# 1. Download 563-leaf plaintext ledger & verify 563 rows, contiguous 000..562 indices, uniqueness, payload SHA & 10-level Merkle root
_, txt = fetch("/api/oracle/leaves-563-hashes.txt?v=34")
rows = []
for line in txt.splitlines():
    s = line.strip()
    if not s or s.startswith("#"): continue
    parts = [p.strip() for p in s.split("|")]
    if len(parts) == 5:
        rows.append((int(parts[0]), parts[1], parts[2], parts[3], parts[4]))

assert len(rows) == 563, f"Expected 563 rows, got {len(rows)}"
assert [r[0] for r in rows] == list(range(563)), "Indices 0..562 not contiguous"
assert len(set(r[1] for r in rows)) == 563, "Duplicate canonical_model_id found"
leaves = [r[4] for r in rows]
assert len(set(leaves)) == 563, "Duplicate leaf hash found"

payload_sha = hashlib.sha256(",".join(leaves).encode("utf-8")).hexdigest()
assert payload_sha == EXPECTED_PAYLOAD_SHA, f"Payload SHA mismatch: {payload_sha}"

lvl = list(leaves)
for _ in range(10):
    if len(lvl) % 2 == 1: lvl.append(lvl[-1])
    lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i+1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
assert lvl[0] == EXPECTED_MERKLE_ROOT, f"Merkle root mismatch: {lvl[0]}"
print("[PASS 1/3] 563 Leaves Contiguity (0..562), Uniqueness, Payload SHA & 10-Level Merkle Root Verified:", lvl[0])

# 2. Fetch Oracle v34 manifest, verify version identity, recompute canonical manifest SHA-256 & verify full 256-byte RS256 signature
_, oracle_body = fetch("/api/oracle/v1.json?v=34")
oracle = json.loads(oracle_body)
mf = oracle["evidence_manifest"]
assert mf["build_version"] == EXPECTED_BUILD_VER, f"Build version mismatch: {mf.get('build_version')}"
assert mf["schema_version"] == EXPECTED_SCHEMA_VER, f"Schema version mismatch: {mf.get('schema_version')}"
assert mf["pricing_snapshot_id"] == EXPECTED_SNAP_ID, f"Snapshot mismatch: {mf.get('pricing_snapshot_id')}"
assert oracle["merkle_root_sha256"] == "sha256:" + EXPECTED_MERKLE_ROOT
assert mf["catalog_root_sha256"] == "sha256:" + EXPECTED_MERKLE_ROOT

em_env = mf["signature_envelope"]
canon_bytes = json.dumps({k: v for k, v in mf.items() if k != "signature_envelope"}, separators=(",", ":"), sort_keys=True).encode("utf-8")
recalc_manifest_sha = hashlib.sha256(canon_bytes).hexdigest()
assert recalc_manifest_sha == em_env["signed_payload_sha256"], "Manifest SHA-256 mismatch"

expected_em = "0001" + ("ff" * 202) + "003031300d060960864801650304020105000420" + recalc_manifest_sha
actual_em = hex(pow(int(em_env["signature_value"], 16), 65537, int(em_env["public_modulus_n_hex"], 16)))[2:].zfill(512)
assert len(actual_em) == 512 and actual_em == expected_em, "RSA-2048 256-byte EMSA encoding mismatch"
print("[PASS 2/3] RS256 256-Byte Exact EMSA-PKCS1-v1_5 Signature Dynamically Verified:", recalc_manifest_sha)

# 3. Cross-check Telemetry, MCP, and Customer-Telemetry against Oracle's signed_payload_sha256 and build_version
for ep in [
    "/api/telemetry/metrics.json?v=34",
    "/api/v1/mcp?call=check_context_cliff&model=gpt-6-1-sol&prompt_tokens=285000&completion_tokens=20000&v=34",
    "/api/v1/customer-telemetry?prompt=my_secret_prompt&v=34",
]:
    _, b = fetch(ep)
    d = json.loads(b)
    b_ver = d.get("build_version") or d.get("evidence_manifest", {}).get("build_version")
    s_sha = d.get("signed_payload_sha256") or d.get("evidence_manifest", {}).get("signature_envelope", {}).get("signed_payload_sha256")
    assert b_ver == EXPECTED_BUILD_VER, f"Build version mismatch on {ep}: {b_ver}"
    assert s_sha == recalc_manifest_sha, f"Manifest SHA mismatch on {ep}: {s_sha}"
print("[PASS 3/3] All 4 Endpoints Synchronized at build_version=" + EXPECTED_BUILD_VER + " & SHA=" + recalc_manifest_sha)
