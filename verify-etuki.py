#!/usr/bin/env python3
# Etuki Standalone Cryptographic & 563-Leaf Merkle Verifier (v39.1-evidence-closure)
# Second-Channel Public Mirror: https://github.com/cooyun/etuki-gate/blob/main/verify-etuki.py
# Usage: curl -sSfL https://www.etuki.com/verify-etuki.py | python3 -
import csv, io, json, math, hashlib, datetime, urllib.parse, urllib.request

BASE = "https://www.etuki.com"
EXPECTED_BUILD_VER       = "2026.10.30-v39.1-evidence-closure"
EXPECTED_SCHEMA_VER      = "2026.10.30-v39.1-unified"
EXPECTED_SNAP_ID         = "price-20261030-v35-truth"
EXPECTED_TELEM_ID        = "telemetry-20261030-v35-truth"
EXPECTED_PAYLOAD_SHA     = "6bc877254427a142ff842bfa318350453ffebc62faf90f62337f96fb7fa5db82"
EXPECTED_MERKLE_ROOT     = "d2f517094b814bcf41ea821c1ce654aa29df8ac454acd1c96779d7966ab688f4"
EXPECTED_CSV_ROOT        = "d3563e6720c67d0b4102fc3d275e205fd0ad612064216e4aa7a9feccb522a844"
EXPECTED_MAPPING_CSV_SHA = "e19cf49f18863997b687dd75c14ca4f38f6b626cdd3e09bb31adc76767117fa7"

# P0 TRUST ANCHOR: Hardcoded Pinned RSA-2048 Public Key Modulus, Exponent & RFC 5280 ASN.1 DER SPKI SHA-256
PINNED_TRUSTED_KEY_ID = "etuki-ci-rsa2048-2026-v17"
PINNED_TRUSTED_EXPONENT_E = 65537
PINNED_TRUSTED_MODULUS_N_HEX = "85b8a7d44bfdb14b096f979625902da191770874d19fcd1a03762e6564f07dd1ab04b50dd0dcf139802018e2b39998be19c8e8eb5f51bb015964916734726784a5debbda117c7c88bdff32ceaff42702a3577a3bfab34add0da086ddc9d8bb30a021087f4e2f487bc2d98e509affe41e4189c50f19a94494c0b14f1cdad3354b10224722cd4aca8cd05d8c0d54495b3e623b640245dc5f69a8d98125387902b129edd8f3aa0f101f27fc107ffbd2ae4a77a23f549a96ba96b7868cf5e5bac923d6ad20fd96d4c173f4d8b348458b2cc2c41ea9a9702fe2f79c7857b31cf5a1e9bca91e4c3f8c23f26b9c9e6f1a5aa15c80f610fb165a452965093613f4784bfb"
PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256 = "a43a9de120fb8753d66dc4d327687f8632dfc30d09cc047c3aa46b527e9e8cd7"

ALLOWED_SOURCE_DOMAINS = set(["ai.google.dev", "api-docs.deepseek.com", "auth0.com", "aws.amazon.com", "azure.microsoft.com", "betterstack.com", "clerk.com", "clickhouse.com", "cloud.google.com", "cohere.com", "coolify.io", "deno.com", "developers.cloudflare.com", "developers.openai.com", "docs.anthropic.com", "docs.x.ai", "dodopayments.com", "fastspring.com", "fly.io", "grafana.com", "gumroad.com", "help.aliyun.com", "loops.so", "mistral.ai", "neon.tech", "newrelic.com", "northflank.com", "open.bigmodel.cn", "openrouter.ai", "planetscale.com", "platform.minimaxi.com", "platform.moonshot.cn", "polar.sh", "posthog.com", "postmarkapp.com", "qdrant.tech", "railway.com", "razorpay.com", "recurly.com", "redis.io", "render.com", "resend.com", "sendgrid.com", "sentry.io", "stripe.com", "supabase.com", "trigger.dev", "turso.tech", "upstash.com", "us.ovhcloud.com", "vercel.com", "weaviate.io", "wise.com", "workos.com", "wow.groq.com", "www.adyen.com", "www.airwallex.com", "www.chargebee.com", "www.checkout.com", "www.cockroachlabs.com", "www.convex.dev", "www.creem.io", "www.datadoghq.com", "www.datastax.com", "www.digitalocean.com", "www.fastly.com", "www.helicone.ai", "www.hetzner.com", "www.inngest.com", "www.koyeb.com", "www.langchain.com", "www.lemonsqueezy.com", "www.linode.com", "www.mollie.com", "www.mongodb.com", "www.netlify.com", "www.paddle.com", "www.payoneer.com", "www.paypal.com", "www.pinecone.io", "www.scaleway.com", "www.singlestore.com", "www.tigrisdata.com", "www.timescale.com", "www.together.ai", "www.trychroma.com", "www.verifone.com", "www.vultr.com", "www.worldfirst.com", "xata.io", "zilliz.com"])

# Strict Closed 5-Tuple Enumeration: (entity_class, provenance_tier, model_reality_tier, api_probe_status, price_evidence_type)
ALLOWED_CLASSIFICATION_5TUPLES = {
    ("LLM_API_ENDPOINT", "verified", "FRONTIER_SIMULATION_BENCHMARK", "SYNTHETIC_STRESS_TEST_BENCHMARK", "SIMULATION_SCHEDULE"),
    ("LLM_API_ENDPOINT", "router-sourced", "FRONTIER_SIMULATION_BENCHMARK", "SYNTHETIC_STRESS_TEST_BENCHMARK", "SIMULATION_SCHEDULE"),
    ("LLM_API_ENDPOINT", "router-sourced", "PRODUCTION_GA", "HTTP_200_GA_VERIFIED", "OFFICIAL_VENDOR_AND_ROUTER_VERIFIED"),
    ("LLM_API_ENDPOINT", "router-sourced", "PRODUCTION_GA", "ROUTER_CATALOG_SYNCED_GA", "ROUTER_CATALOG_SNAPSHOT"),
    ("CLOUD_AND_MOR_INFRASTRUCTURE", "infra-verified", "PRODUCTION_GA_INFRA", "INFRA_RATE_CARD_VERIFIED", "INFRASTRUCTURE_RATE_CARD"),
}

EXPECTED_WINDOWS = ("W1", "W2", "W3", "W4")
EXPECTED_REGIONS = {"us-west-1", "ap-southeast-1", "eu-central-1"}
EXPECTED_CELLS   = {(w, r) for w in EXPECTED_WINDOWS for r in EXPECTED_REGIONS}
EXPECTED_MODELS  = set(["anthropic/claude-3-5-haiku-20241022", "anthropic/claude-3-7-sonnet-20250219", "deepseek/deepseek-chat", "deepseek/deepseek-reasoner", "google/gemini-2.5-flash", "google/gemini-2.5-pro", "meta-llama/llama-3.3-70b-instruct", "openai/gpt-4.1", "openai/gpt-4o-2024-11-20", "openai/o3-mini"])
EXPECTED_MODEL_SAMPLE_COUNTS = {"openai/gpt-4.1": 15, "openai/gpt-4o-2024-11-20": 15, "openai/o3-mini": 15, "anthropic/claude-3-7-sonnet-20250219": 15, "anthropic/claude-3-5-haiku-20241022": 14, "google/gemini-2.5-pro": 14, "google/gemini-2.5-flash": 14, "deepseek/deepseek-reasoner": 14, "deepseek/deepseek-chat": 14, "meta-llama/llama-3.3-70b-instruct": 14}
MAX_ALLOWED_RETRIES = 2

def fetch(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Etuki-Standalone-Verifier/39.1"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read().decode("utf-8")

def parse_iso_utc(ts_str):
    return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def calc_percentile_nearest_rank(sorted_vals, pct):
    idx = max(0, min(len(sorted_vals) - 1, int(math.ceil((pct / 100.0) * len(sorted_vals))) - 1))
    return sorted_vals[idx]

def compute_rfc5280_spki_sha256(modulus_n_hex, exponent_e):
    assert exponent_e == 65537 and len(modulus_n_hex) == 512
    spki_der = bytes.fromhex(
        "30820122300d06092a864886f70d01010105000382010f003082010a0282010100"
        + modulus_n_hex
        + "0203010001"
    )
    return hashlib.sha256(spki_der).hexdigest()

def verify_rs256_pkcs1_v15(digest_hex, sig_hex):
    expected_em = "0001" + ("ff" * 202) + "003031300d060960864801650304020105000420" + digest_hex
    actual_em = hex(pow(int(sig_hex, 16), PINNED_TRUSTED_EXPONENT_E, int(PINNED_TRUSTED_MODULUS_N_HEX, 16)))[2:].zfill(512)
    return len(actual_em) == 512 and actual_em == expected_em

now_utc = datetime.datetime.now(datetime.timezone.utc)

# 1. Verify 563-leaf ledger + Closed 5-Tuple Semantic Relational Join with `entity-reality-provenance-mapping.csv` + 10 Negative Tests
_, txt = fetch("/api/oracle/leaves-563-hashes.txt?v=39.1")
rows = []
ledger_by_id = {}
for line in txt.splitlines():
    s = line.strip()
    if not s or s.startswith("#"): continue
    parts = [p.strip() for p in s.split("|")]
    if len(parts) == 6:
        idx_i = int(parts[0])
        rows.append((idx_i, parts[1], parts[2], parts[3], parts[4], parts[5]))
        ledger_by_id[parts[1]] = {
            "index": idx_i, "provenance_tier": parts[2],
            "model_reality_tier": parts[3], "cache_price_source": parts[4], "leaf_sha256_hex": parts[5]
        }

assert len(rows) == 563 and len(ledger_by_id) == 563
assert [r[0] for r in rows] == list(range(563))
leaves = [r[5] for r in rows]
assert len(set(leaves)) == 563

_, map_csv = fetch("/api/oracle/entity-reality-provenance-mapping.csv?v=39.1")
assert hashlib.sha256(map_csv.encode("utf-8")).hexdigest() == EXPECTED_MAPPING_CSV_SHA

def validate_mapping_csv_rows(csv_text, ref_ledger, ref_now_utc):
    reader = list(csv.DictReader(io.StringIO(csv_text)))
    if len(reader) != 563: return False, "ROW_COUNT_MISMATCH"
    seen_ids = set()
    for r in reader:
        cid = r["canonical_model_id"]
        if cid in seen_ids or cid not in ref_ledger: return False, "ID_SET_OR_DUPLICATE_ERROR"
        seen_ids.add(cid)
        ref = ref_ledger[cid]
        if int(r["index"]) != ref["index"]: return False, "INDEX_JOIN_MISMATCH"
        if r["provenance_tier"] != ref["provenance_tier"]: return False, "PROVENANCE_JOIN_MISMATCH"
        if r["model_reality_tier"] != ref["model_reality_tier"]: return False, "REALITY_TIER_JOIN_MISMATCH"
        if r["cache_price_source"] != ref["cache_price_source"]: return False, "CACHE_SOURCE_JOIN_MISMATCH"
        if r["leaf_sha256_hex"] != ref["leaf_sha256_hex"]: return False, "LEAF_HASH_JOIN_MISMATCH"
        cls_5tuple = (
            r["entity_class"], r["provenance_tier"],
            r["model_reality_tier"], r["api_probe_status"], r.get("price_evidence_type", "")
        )
        if cls_5tuple not in ALLOWED_CLASSIFICATION_5TUPLES:
            return False, "CLOSED_5TUPLE_ENUM_VIOLATION"
        parsed_u = urllib.parse.urlparse(r["source_url"])
        if parsed_u.scheme != "https" or parsed_u.netloc not in ALLOWED_SOURCE_DOMAINS:
            return False, "UNTRUSTED_OR_INVALID_SOURCE_DOMAIN"
        try:
            v_dt = parse_iso_utc(r["verified_at_utc"])
            if v_dt > ref_now_utc: return False, "FUTURE_VERIFIED_AT_TIMESTAMP"
        except Exception:
            return False, "INVALID_VERIFIED_AT_FORMAT"
    return True, "PASS_563_CLOSED_5TUPLE_RELATIONAL_JOIN"

ok_join, msg_join = validate_mapping_csv_rows(map_csv, ledger_by_id, now_utc)
assert ok_join, f"Relational CSV Join failed: {msg_join}"

csv_lines_raw = map_csv.strip().splitlines()
assert not validate_mapping_csv_rows("\n".join(csv_lines_raw[:-1]), ledger_by_id, now_utc)[0], "NEG-CSV-01 failed"
assert not validate_mapping_csv_rows("\n".join(csv_lines_raw[:2] + [csv_lines_raw[1]] + csv_lines_raw[3:]), ledger_by_id, now_utc)[0], "NEG-CSV-02 failed"
assert not validate_mapping_csv_rows(map_csv.replace(leaves[0], "0"*64, 1), ledger_by_id, now_utc)[0], "NEG-CSV-03 failed"
assert not validate_mapping_csv_rows(map_csv.replace("FRONTIER_SIMULATION_BENCHMARK", "PRODUCTION_GA", 1), ledger_by_id, now_utc)[0], "NEG-CSV-04 failed"
assert not validate_mapping_csv_rows(map_csv.replace("https://", "ftp://", 1), ledger_by_id, now_utc)[0], "NEG-CSV-05 failed"
assert not validate_mapping_csv_rows(map_csv.replace("https://openrouter.ai", "https://untrusted-phishing.example.com", 1), ledger_by_id, now_utc)[0], "NEG-CSV-06 failed"
assert not validate_mapping_csv_rows(map_csv.replace("2026-10-30T02:10:00Z", "2099-12-31T23:59:59Z", 1), ledger_by_id, now_utc)[0], "NEG-CSV-07 failed"
assert not validate_mapping_csv_rows(map_csv.replace("SYNTHETIC_STRESS_TEST_BENCHMARK", "HTTP_200_GA_VERIFIED", 1), ledger_by_id, now_utc)[0], "NEG-CSV-08 failed"
assert not validate_mapping_csv_rows(map_csv.replace("PRODUCTION_GA", "UNLISTED_EXPERIMENTAL_TIER", 1), ledger_by_id, now_utc)[0], "NEG-CSV-09 failed"
assert not validate_mapping_csv_rows(map_csv.replace("SIMULATION_SCHEDULE", "OFFICIAL_VENDOR_AND_ROUTER_VERIFIED", 1), ledger_by_id, now_utc)[0], "NEG-CSV-10 failed"

s1_ids = [r[1] for r in rows if r[2] == "verified"]
s2_ids = [r[1] for r in rows if r[2] == "router-sourced"]
s3_ids = [r[1] for r in rows if r[2] == "infra-verified"]
csv_canon = json.dumps({
    "schema_version": EXPECTED_SCHEMA_VER,
    "set1_32_sha256": "sha256:" + hashlib.sha256(",".join(s1_ids).encode("utf-8")).hexdigest(),
    "set2_453_sha256": "sha256:" + hashlib.sha256(",".join(s2_ids).encode("utf-8")).hexdigest(),
    "set3_78_sha256": "sha256:" + hashlib.sha256(",".join(s3_ids).encode("utf-8")).hexdigest(),
}, separators=(",", ":"))
assert hashlib.sha256(csv_canon.encode("utf-8")).hexdigest() == EXPECTED_CSV_ROOT
assert hashlib.sha256(",".join(leaves).encode("utf-8")).hexdigest() == EXPECTED_PAYLOAD_SHA

lvl = list(leaves)
for _ in range(10):
    if len(lvl) % 2 == 1: lvl.append(lvl[-1])
    lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i+1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
assert lvl[0] == EXPECTED_MERKLE_ROOT
print("[PASS 1/5] 563 Leaves, Closed 5-Tuple CSV Join (+10 Negative Tamper Tests), 3-Branch CSV Root & Merkle Root Verified!")

# 2. Recompute RFC 5280 ASN.1 DER SPKI SHA-256 Fingerprint
recalc_spki_fp = compute_rfc5280_spki_sha256(PINNED_TRUSTED_MODULUS_N_HEX, PINNED_TRUSTED_EXPONENT_E)
assert recalc_spki_fp == PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256
_, pubkey_body = fetch("/.well-known/etuki-ci-pubkey.json?v=39.1")
pubkey_doc = json.loads(pubkey_body)
assert pubkey_doc["public_modulus_n_hex"] == PINNED_TRUSTED_MODULUS_N_HEX
assert compute_rfc5280_spki_sha256(pubkey_doc["public_modulus_n_hex"], int(pubkey_doc["public_exponent_e"])) == PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256
print("[PASS 2/5] RFC 5280 ASN.1 DER SPKI Encoded & Recomputed SHA-256 Fingerprint Verified:", recalc_spki_fp)

# 3. Verify Oracle v39.1 manifest signature & past timestamp chain
_, oracle_body = fetch("/api/oracle/v1.json?v=39.1")
oracle = json.loads(oracle_body)
mf = oracle["evidence_manifest"]
assert mf["build_version"] == EXPECTED_BUILD_VER and mf["schema_version"] == EXPECTED_SCHEMA_VER
assert mf["pricing_snapshot_id"] == EXPECTED_SNAP_ID and mf["telemetry_snapshot_id"] == EXPECTED_TELEM_ID
obs_dt = parse_iso_utc(mf["source_verified_at"])
gen_dt = parse_iso_utc(mf["generated_at"])
assert obs_dt <= gen_dt <= now_utc
em_env = mf["signature_envelope"]
assert em_env["public_modulus_n_hex"] == PINNED_TRUSTED_MODULUS_N_HEX
canon_bytes = json.dumps({k: v for k, v in mf.items() if k != "signature_envelope"}, separators=(",", ":"), sort_keys=True).encode("utf-8")
recalc_manifest_sha = hashlib.sha256(canon_bytes).hexdigest()
assert recalc_manifest_sha == em_env["signed_payload_sha256"]
assert verify_rs256_pkcs1_v15(recalc_manifest_sha, em_env["signature_value"])
print("[PASS 3/5] Oracle Manifest RS256 Signature & Past Timestamp Constraints Verified:", recalc_manifest_sha)

# 4. Verify Dynamic 24h Contiguous Non-Overlapping 4-Window Rules, Left-Closed Right-Open Bounds (`w_b_start <= s_dt < w_b_end`), Retry Semantics & RS256 Signature (P0-2, P0-3, P1-1)
_, roll_b = fetch("/api/telemetry/live-rolling-24h.json?v=39.1")
roll_d = json.loads(roll_b)
assert roll_d["immutable_catalog_anchor_sha256"] == recalc_manifest_sha
win_obj = roll_d["signed_rolling_window_payload"]
win_env = roll_d["rolling_window_signature_envelope"]
assert win_obj["window_status"] == "completed_window"
for tk in ("rolling_24h_start_utc", "rolling_24h_end_utc", "window_start_utc", "window_end_utc", "observed_at_utc", "generated_at_utc", "window_bounds_utc"):
    assert roll_d[tk] == win_obj[tk], f"Outer vs inner {tk} mismatch"

r24_start_dt   = parse_iso_utc(roll_d["rolling_24h_start_utc"])
r24_end_dt     = parse_iso_utc(roll_d["rolling_24h_end_utc"])
w_start_dt     = parse_iso_utc(roll_d["window_start_utc"])
w_end_dt       = parse_iso_utc(roll_d["window_end_utc"])
w_obs_dt       = parse_iso_utc(roll_d["observed_at_utc"])
w_generated_dt = parse_iso_utc(roll_d["generated_at_utc"])
assert (r24_end_dt - r24_start_dt).total_seconds() == 86400, "Rolling cycle must be exactly 24h (86400s)"
assert r24_start_dt < w_start_dt < w_end_dt == r24_end_dt <= w_obs_dt <= w_generated_dt <= now_utc

# Dynamic Contiguous 4-Window Structural Validation (No hardcoded dates needed — P0-3!)
wb_map = win_obj["window_bounds_utc"]
assert tuple(wb_map.keys()) == EXPECTED_WINDOWS
parsed_wb = {}
for idx_w, w_k in enumerate(EXPECTED_WINDOWS):
    ws_dt = parse_iso_utc(wb_map[w_k][0])
    we_dt = parse_iso_utc(wb_map[w_k][1])
    assert (we_dt - ws_dt).total_seconds() == 21600, f"Window {w_k} must be strictly 6h (21600s)"
    if idx_w == 0:
        assert ws_dt == r24_start_dt, "W1 start must equal rolling_24h_start_utc"
    else:
        prev_w = EXPECTED_WINDOWS[idx_w - 1]
        assert ws_dt == parsed_wb[prev_w][1], f"Window {w_k} start must equal {prev_w} end (contiguous non-overlapping)"
    if idx_w == 3:
        assert ws_dt == w_start_dt and we_dt == w_end_dt == r24_end_dt, "W4 must match latest completed 6h window and rolling_24h_end_utc"
    parsed_wb[w_k] = (ws_dt, we_dt)

def validate_probe_sample_row(s_row, idx_s, ref_wb):
    w_c = s_row.get("window_code", "")
    reg_c = s_row.get("region", "")
    b_idx = int(s_row.get("burst_index", 0))
    if w_c not in EXPECTED_WINDOWS or reg_c not in EXPECTED_REGIONS: return False, "INVALID_WIN_OR_REG"
    expected_sid = f"prb_24h_{idx_s:03d}_{w_c}_{reg_c.replace('-', '')}_b{b_idx:02d}"
    if s_row.get("sample_id") != expected_sid: return False, "SAMPLE_ID_ENCODING_MISMATCH"
    s_dt = parse_iso_utc(s_row["observed_at_utc"])
    w_b_start, w_b_end = ref_wb[w_c]
    # Left-closed, right-open interval `[w_b_start, w_b_end)` eliminates boundary overlap ambiguity (P0-2)!
    if not (w_b_start <= s_dt < w_b_end): return False, "TIMESTAMP_OUTSIDE_HALF_OPEN_WINDOW"
    gen_ms = int(s_row["duration_ms"]) - int(s_row["ttft_ms"])
    if gen_ms <= 0 or not (380 <= int(s_row["output_tokens"]) <= 512): return False, "INVALID_GEN_OR_TOKENS"
    if round((int(s_row["output_tokens"]) * 1000.0) / gen_ms, 1) != float(s_row["tps"]): return False, "TPS_DERIVATION_MISMATCH"
    # Explicit retry_count semantics & bounds check (P1-1)!
    r_cnt = int(s_row.get("retry_count", -1))
    b_off = int(s_row.get("retry_backoff_ms", -1))
    p_st  = int(s_row.get("prior_attempt_http_status", -1))
    e2e   = int(s_row.get("end_to_end_elapsed_ms", -1))
    if not (0 <= r_cnt <= MAX_ALLOWED_RETRIES): return False, "RETRY_COUNT_OUT_OF_BOUNDS"
    if r_cnt == 0 and (b_off != 0 or p_st != 0): return False, "ZERO_RETRY_MUST_HAVE_ZERO_BACKOFF"
    if r_cnt > 0 and (b_off <= 0 or p_st not in (429, 502, 503, 504)): return False, "RETRY_MISSING_BACKOFF_OR_PRIOR_STATUS"
    if e2e != int(s_row["duration_ms"]) + b_off: return False, "E2E_ELAPSED_MISMATCH"
    return True, "OK"

raw_144 = roll_d["raw_144_probe_samples"]
assert len(raw_144) == 144 == win_obj["total_stream_samples_24h"] == sum(EXPECTED_MODEL_SAMPLE_COUNTS.values())
assert len(set(s["sample_id"] for s in raw_144)) == 144

by_win_reg = {}
by_model = {}
samples_by_model = {}
for idx_s, s_row in enumerate(raw_144, start=1):
    ok_s, msg_s = validate_probe_sample_row(s_row, idx_s, parsed_wb)
    assert ok_s, f"Sample #{idx_s} failed validation: {msg_s}"
    key_wr = (s_row["window_code"], s_row["region"])
    by_win_reg.setdefault(key_wr, []).append(int(s_row["burst_index"]))
    m_k = s_row["api_model_id"]
    by_model[m_k] = by_model.get(m_k, 0) + 1
    samples_by_model.setdefault(m_k, []).append(s_row)

# Negative tests on sample boundary & retry semantics (P0-2 & P1-1)
assert not validate_probe_sample_row({**raw_144[0], "observed_at_utc": wb_map["W1"][1]}, 1, parsed_wb)[0], "NEG-SAMPLE-BOUNDARY-RIGHT-ENDPOINT failed"
assert not validate_probe_sample_row({**raw_144[0], "retry_count": 5}, 1, parsed_wb)[0], "NEG-SAMPLE-EXCESS-RETRY failed"
assert not validate_probe_sample_row({**raw_144[0], "retry_count": 1, "retry_backoff_ms": 0}, 1, parsed_wb)[0], "NEG-SAMPLE-MISSING-BACKOFF failed"

assert set(by_win_reg.keys()) == EXPECTED_CELLS
for wr_key, burst_list in by_win_reg.items():
    assert sorted(burst_list) == list(range(1, 13))
assert set(samples_by_model.keys()) == EXPECTED_MODELS
assert {p["api_model_id"] for p in roll_d["live_ga_probes"]} == EXPECTED_MODELS
assert by_model == EXPECTED_MODEL_SAMPLE_COUNTS

for p_summary in roll_d["live_ga_probes"]:
    m_rows = samples_by_model[p_summary["api_model_id"]]
    ttfts_s = sorted(int(x["ttft_ms"]) for x in m_rows)
    tpss_s  = sorted(float(x["tps"]) for x in m_rows)
    assert p_summary["min_ttft_ms"] == ttfts_s[0] and p_summary["max_ttft_ms"] == ttfts_s[-1]
    assert p_summary["p50_ttft_ms"] == calc_percentile_nearest_rank(ttfts_s, 50)
    assert p_summary["p90_ttft_ms"] == calc_percentile_nearest_rank(ttfts_s, 90)
    assert p_summary["tps"] == calc_percentile_nearest_rank(tpss_s, 50)

assert hashlib.sha256(json.dumps(raw_144, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest() == win_obj["raw_144_samples_sha256"]
assert hashlib.sha256(json.dumps(roll_d["live_ga_probes"], separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest() == win_obj["sample_payload_sha256"]
recalc_win_sha = hashlib.sha256(json.dumps(win_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
assert recalc_win_sha == roll_d["rolling_telemetry_window_sha256"] == win_env["signed_window_sha256"]
assert verify_rs256_pkcs1_v15(recalc_win_sha, win_env["signature_value"])
print("[PASS 4/5] 144 Samples (Dynamic 24h Contiguous Windows, Half-Open [start, end), Retry Semantics & Sample-Derived Percentiles) Verified:", recalc_win_sha)

# 5. Cross-check ALL 5 version fields AND execute bidirectional 10-Model Field-Level Join across Oracle <-> Telemetry <-> Rolling-24h (P1-2)!
_, telem_b = fetch("/api/telemetry/metrics.json?v=39.1")
telem_d = json.loads(telem_b)

roll_by_id   = {p["api_model_id"]: p for p in roll_d["live_ga_probes"]}
oracle_by_id = {m["api_model_id"]: m for m in oracle["production_ga_10_flagship_telemetry"]}
telem_by_id  = {m["api_model_id"]: m for m in telem_d["production_ga_10_flagship_models"]}
assert set(oracle_by_id.keys()) == set(telem_by_id.keys()) == set(roll_by_id.keys()) == EXPECTED_MODELS
for mid in EXPECTED_MODELS:
    assert oracle_by_id[mid]["ttft_p50_ms"] == telem_by_id[mid]["ttft_p50_ms"] == roll_by_id[mid]["p50_ttft_ms"]
    assert oracle_by_id[mid]["ttft_p90_ms"] == telem_by_id[mid]["ttft_p90_ms"] == roll_by_id[mid]["p90_ttft_ms"]
    assert oracle_by_id[mid]["tps_median"]  == telem_by_id[mid]["tps_median"]  == roll_by_id[mid]["tps"]

for ep in [
    "/api/telemetry/metrics.json?v=39.1",
    "/api/v1/mcp?call=check_context_cliff&model=gpt-6-1-sol&prompt_tokens=285000&completion_tokens=20000&v=39.1",
    "/api/v1/customer-telemetry?prompt=my_secret_prompt&v=39.1",
]:
    _, b = fetch(ep)
    d = json.loads(b)
    sub_mf = d.get("evidence_manifest", d)
    assert (d.get("build_version") or sub_mf.get("build_version")) == EXPECTED_BUILD_VER
    assert (d.get("schema_version") or sub_mf.get("schema_version")) == EXPECTED_SCHEMA_VER
    assert (d.get("pricing_snapshot_id") or sub_mf.get("pricing_snapshot_id")) == EXPECTED_SNAP_ID
    assert (d.get("telemetry_snapshot_id") or sub_mf.get("telemetry_snapshot_id")) == EXPECTED_TELEM_ID
    s_sha = d.get("signed_payload_sha256") or sub_mf.get("signature_envelope", {}).get("signed_payload_sha256")
    assert s_sha == recalc_manifest_sha
print("[PASS 5/5] Oracle <-> Telemetry <-> Rolling-24h 10-Model Join & All 5 Version Fields Verified at build_version=" + EXPECTED_BUILD_VER)
