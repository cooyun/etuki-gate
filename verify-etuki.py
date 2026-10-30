#!/usr/bin/env python3
# Etuki Standalone Cryptographic & 563-Leaf Merkle Verifier (v36-closure)
# Second-Channel Public Mirror: https://github.com/cooyun/etuki-gate/blob/main/verify-etuki.py
# Usage: curl -sSfL https://www.etuki.com/verify-etuki.py | python3 -
import json, hashlib, urllib.request

BASE = "https://www.etuki.com"
EXPECTED_BUILD_VER       = "2026.10.30-v36-release"
EXPECTED_SCHEMA_VER      = "2026.10.30-v36-unified"
EXPECTED_SNAP_ID         = "price-20261030-v35-truth"
EXPECTED_TELEM_ID        = "telemetry-20261030-v35-truth"
EXPECTED_PAYLOAD_SHA     = "6bc877254427a142ff842bfa318350453ffebc62faf90f62337f96fb7fa5db82"
EXPECTED_MERKLE_ROOT     = "d2f517094b814bcf41ea821c1ce654aa29df8ac454acd1c96779d7966ab688f4"
EXPECTED_CSV_ROOT        = "2ab812a460cbab86136bd7afc3a8da9a8c295584b08af68e60a9520181e04f54"
EXPECTED_MAPPING_CSV_SHA = "fbe2e9adecfec9844204976ffe9a9d05b99355f28d4e2bc1afbf80429ed095bb"

# P0 TRUST ANCHOR: Hardcoded Pinned RSA-2048 Public Key Modulus & SPKI Fingerprint
PINNED_TRUSTED_KEY_ID = "etuki-ci-rsa2048-2026-v17"
PINNED_TRUSTED_EXPONENT_E = 65537
PINNED_TRUSTED_MODULUS_N_HEX = "85b8a7d44bfdb14b096f979625902da191770874d19fcd1a03762e6564f07dd1ab04b50dd0dcf139802018e2b39998be19c8e8eb5f51bb015964916734726784a5debbda117c7c88bdff32ceaff42702a3577a3bfab34add0da086ddc9d8bb30a021087f4e2f487bc2d98e509affe41e4189c50f19a94494c0b14f1cdad3354b10224722cd4aca8cd05d8c0d54495b3e623b640245dc5f69a8d98125387902b129edd8f3aa0f101f27fc107ffbd2ae4a77a23f549a96ba96b7868cf5e5bac923d6ad20fd96d4c173f4d8b348458b2cc2c41ea9a9702fe2f79c7857b31cf5a1e9bca91e4c3f8c23f26b9c9e6f1a5aa15c80f610fb165a452965093613f4784bfb"
PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256 = "3c9d2d4e5efec824f01905bcb69b9ace7e567c52f79b1b8cdc9b352e99f5aa3a"

def fetch(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Etuki-Standalone-Verifier/36.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read().decode("utf-8")

# 1. Verify 563-leaf plaintext ledger & 563-row provenance-reality CSV mapping table
_, txt = fetch("/api/oracle/leaves-563-hashes.txt?v=36")
rows = []
for line in txt.splitlines():
    s = line.strip()
    if not s or s.startswith("#"): continue
    parts = [p.strip() for p in s.split("|")]
    if len(parts) == 6:
        rows.append((int(parts[0]), parts[1], parts[2], parts[3], parts[4], parts[5]))

assert len(rows) == 563, f"Expected 563 rows, got {len(rows)}"
assert [r[0] for r in rows] == list(range(563)), "Indices 0..562 not contiguous"
assert len(set(r[1] for r in rows)) == 563, "Duplicate canonical_model_id found"
leaves = [r[5] for r in rows]
assert len(set(leaves)) == 563, "Duplicate leaf hash found"

_, map_csv = fetch("/api/oracle/entity-reality-provenance-mapping.csv?v=36")
assert hashlib.sha256(map_csv.encode("utf-8")).hexdigest() == EXPECTED_MAPPING_CSV_SHA, "563-row mapping CSV SHA mismatch"

s1_ids = [r[1] for r in rows if r[2] == "verified"]
s2_ids = [r[1] for r in rows if r[2] == "router-sourced"]
s3_ids = [r[1] for r in rows if r[2] == "infra-verified"]
assert (len(s1_ids), len(s2_ids), len(s3_ids)) == (32, 453, 78)
csv_canon = json.dumps({
    "schema_version": EXPECTED_SCHEMA_VER,
    "set1_32_sha256": "sha256:" + hashlib.sha256(",".join(s1_ids).encode("utf-8")).hexdigest(),
    "set2_453_sha256": "sha256:" + hashlib.sha256(",".join(s2_ids).encode("utf-8")).hexdigest(),
    "set3_78_sha256": "sha256:" + hashlib.sha256(",".join(s3_ids).encode("utf-8")).hexdigest(),
}, separators=(",", ":"))
recalc_csv_root = hashlib.sha256(csv_canon.encode("utf-8")).hexdigest()
assert recalc_csv_root == EXPECTED_CSV_ROOT, f"CSV Root mismatch: {recalc_csv_root}"

payload_sha = hashlib.sha256(",".join(leaves).encode("utf-8")).hexdigest()
assert payload_sha == EXPECTED_PAYLOAD_SHA, f"Payload SHA mismatch: {payload_sha}"

lvl = list(leaves)
for _ in range(10):
    if len(lvl) % 2 == 1: lvl.append(lvl[-1])
    lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i+1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
assert lvl[0] == EXPECTED_MERKLE_ROOT, f"Merkle root mismatch: {lvl[0]}"
print("[PASS 1/4] 563 Leaves, 563-Row Provenance CSV, 3-Branch CSV Root, Payload SHA & 10-Level Merkle Root Verified!")

# 2. Verify Pinned Public Key against `/.well-known/etuki-ci-pubkey.json`
_, pubkey_body = fetch("/.well-known/etuki-ci-pubkey.json?v=36")
pubkey_doc = json.loads(pubkey_body)
assert pubkey_doc["public_modulus_n_hex"] == PINNED_TRUSTED_MODULUS_N_HEX, "Well-known pubkey modulus mismatch against pinned anchor!"
assert hashlib.sha256(f"RS256:{PINNED_TRUSTED_EXPONENT_E}:{PINNED_TRUSTED_MODULUS_N_HEX}".encode("utf-8")).hexdigest() == PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256
print("[PASS 2/4] Pinned RSA-2048 Trust Anchor Verified (Fingerprint: " + PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256[:16] + "...)")

# 3. Verify Oracle v36 manifest using ONLY the PINNED_TRUSTED_MODULUS_N_HEX
_, oracle_body = fetch("/api/oracle/v1.json?v=36")
oracle = json.loads(oracle_body)
mf = oracle["evidence_manifest"]
assert mf["build_version"] == EXPECTED_BUILD_VER
assert mf["schema_version"] == EXPECTED_SCHEMA_VER
assert mf["pricing_snapshot_id"] == EXPECTED_SNAP_ID
assert mf["telemetry_snapshot_id"] == EXPECTED_TELEM_ID
assert mf["dataset_3branch_csv_root_sha256"] == "sha256:" + EXPECTED_CSV_ROOT
assert oracle["merkle_root_sha256"] == "sha256:" + EXPECTED_MERKLE_ROOT
assert mf["catalog_root_sha256"] == "sha256:" + EXPECTED_MERKLE_ROOT

em_env = mf["signature_envelope"]
assert em_env["signature_key_id"] == PINNED_TRUSTED_KEY_ID
assert em_env["public_modulus_n_hex"] == PINNED_TRUSTED_MODULUS_N_HEX, "Manifest pubkey does not match pinned trust anchor!"
canon_bytes = json.dumps({k: v for k, v in mf.items() if k != "signature_envelope"}, separators=(",", ":"), sort_keys=True).encode("utf-8")
recalc_manifest_sha = hashlib.sha256(canon_bytes).hexdigest()
assert recalc_manifest_sha == em_env["signed_payload_sha256"]

expected_em = "0001" + ("ff" * 202) + "003031300d060960864801650304020105000420" + recalc_manifest_sha
actual_em = hex(pow(int(em_env["signature_value"], 16), PINNED_TRUSTED_EXPONENT_E, int(PINNED_TRUSTED_MODULUS_N_HEX, 16)))[2:].zfill(512)
assert len(actual_em) == 512 and actual_em == expected_em
print("[PASS 3/4] RS256 256-Byte EMSA-PKCS1-v1_5 Signature Verified Against Pinned Public Key:", recalc_manifest_sha)

# 4. Cross-check ALL 5 fields (`build_version`, `schema_version`, `pricing_snapshot_id`, `telemetry_snapshot_id`, `signed_payload_sha256`) across Telemetry, MCP, Customer-Telemetry, and Rolling-24h!
for ep in [
    "/api/telemetry/metrics.json?v=36",
    "/api/v1/mcp?call=check_context_cliff&model=gpt-6-1-sol&prompt_tokens=285000&completion_tokens=20000&v=36",
    "/api/v1/customer-telemetry?prompt=my_secret_prompt&v=36",
]:
    _, b = fetch(ep)
    d = json.loads(b)
    sub_mf = d.get("evidence_manifest", d)
    assert (d.get("build_version") or sub_mf.get("build_version")) == EXPECTED_BUILD_VER, f"build_version mismatch on {ep}"
    assert (d.get("schema_version") or sub_mf.get("schema_version")) == EXPECTED_SCHEMA_VER, f"schema_version mismatch on {ep}"
    assert (d.get("pricing_snapshot_id") or sub_mf.get("pricing_snapshot_id")) == EXPECTED_SNAP_ID, f"pricing_snapshot_id mismatch on {ep}"
    assert (d.get("telemetry_snapshot_id") or sub_mf.get("telemetry_snapshot_id")) == EXPECTED_TELEM_ID, f"telemetry_snapshot_id mismatch on {ep}"
    s_sha = d.get("signed_payload_sha256") or sub_mf.get("signature_envelope", {}).get("signed_payload_sha256")
    assert s_sha == recalc_manifest_sha, f"Manifest SHA mismatch on {ep}"

_, roll_b = fetch("/api/telemetry/live-rolling-24h.json?v=36")
roll_d = json.loads(roll_b)
assert roll_d["immutable_catalog_anchor_sha256"] == recalc_manifest_sha, "Rolling probe anchor SHA mismatch"
print("[PASS 4/4] All Endpoints Verified Identical on build_version, schema_version, pricing_snapshot_id, telemetry_snapshot_id & signed_payload_sha256!")
