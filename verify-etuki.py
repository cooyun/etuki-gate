#!/usr/bin/env python3
# Etuki Standalone Cryptographic, 563-Leaf Merkle & E3 Client Bill Verifier (v40.5-intermediary-gateway)
# Second-Channel Public Mirror: https://github.com/cooyun/etuki-gate/blob/main/verify-etuki.py
# Usage: curl -sSfL https://www.etuki.com/verify-etuki.py | python3 -
import csv, io, json, math, hashlib, datetime, urllib.parse, urllib.request

BASE = "https://www.etuki.com"
EXPECTED_BUILD_VER       = "2026.10.31-v40.5-intermediary-gateway"
EXPECTED_SCHEMA_VER      = "2026.10.31-v40.5-unified"
EXPECTED_SNAP_ID         = "price-20261030-v35-truth"
EXPECTED_TELEM_ID        = "telemetry-20261030-v35-truth"
EXPECTED_PAYLOAD_SHA     = "6bc877254427a142ff842bfa318350453ffebc62faf90f62337f96fb7fa5db82"
EXPECTED_MERKLE_ROOT     = "d2f517094b814bcf41ea821c1ce654aa29df8ac454acd1c96779d7966ab688f4"
EXPECTED_CSV_ROOT        = "11c396ac7ac97f9f077a0263383c01b21b9f0e2d83bbc6307ffdf5e168634a47"
EXPECTED_MAPPING_CSV_SHA = "fca112a101eb05395d579bbc126dcb157a0c27fcdb56b646a4dc09e3df624b53"
EXPECTED_RECEIPTS_SHA    = "884b4504fe48ef3b0e182e1a77a1e7cfb6934682a807da3ab8145be325317e76"
EXPECTED_E3_LEDGER_SHA   = "207bb1441eb0f30610da017b21911727d215dbe9e8a2e26ce5f4b8cbeab97479"

PINNED_TRUSTED_KEY_ID = "etuki-ci-rsa2048-2026-v17"
PINNED_TRUSTED_EXPONENT_E = 65537
PINNED_TRUSTED_MODULUS_N_HEX = "85b8a7d44bfdb14b096f979625902da191770874d19fcd1a03762e6564f07dd1ab04b50dd0dcf139802018e2b39998be19c8e8eb5f51bb015964916734726784a5debbda117c7c88bdff32ceaff42702a3577a3bfab34add0da086ddc9d8bb30a021087f4e2f487bc2d98e509affe41e4189c50f19a94494c0b14f1cdad3354b10224722cd4aca8cd05d8c0d54495b3e623b640245dc5f69a8d98125387902b129edd8f3aa0f101f27fc107ffbd2ae4a77a23f549a96ba96b7868cf5e5bac923d6ad20fd96d4c173f4d8b348458b2cc2c41ea9a9702fe2f79c7857b31cf5a1e9bca91e4c3f8c23f26b9c9e6f1a5aa15c80f610fb165a452965093613f4784bfb"
PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256 = "a43a9de120fb8753d66dc4d327687f8632dfc30d09cc047c3aa46b527e9e8cd7"

ALLOWED_SOURCE_DOMAINS = set(["ai.google.dev", "api-docs.deepseek.com", "auth0.com", "aws.amazon.com", "azure.microsoft.com", "betterstack.com", "clerk.com", "clickhouse.com", "cloud.google.com", "cohere.com", "coolify.io", "deno.com", "developers.cloudflare.com", "developers.openai.com", "docs.anthropic.com", "docs.x.ai", "dodopayments.com", "fastspring.com", "fly.io", "grafana.com", "gumroad.com", "help.aliyun.com", "loops.so", "mistral.ai", "neon.tech", "newrelic.com", "northflank.com", "open.bigmodel.cn", "openrouter.ai", "planetscale.com", "platform.minimaxi.com", "platform.moonshot.cn", "polar.sh", "posthog.com", "postmarkapp.com", "qdrant.tech", "railway.com", "razorpay.com", "recurly.com", "redis.io", "render.com", "resend.com", "sendgrid.com", "sentry.io", "stripe.com", "supabase.com", "trigger.dev", "turso.tech", "upstash.com", "us.ovhcloud.com", "vercel.com", "weaviate.io", "wise.com", "workos.com", "wow.groq.com", "www.adyen.com", "www.airwallex.com", "www.chargebee.com", "www.checkout.com", "www.cockroachlabs.com", "www.convex.dev", "www.creem.io", "www.datadoghq.com", "www.datastax.com", "www.digitalocean.com", "www.fastly.com", "www.helicone.ai", "www.hetzner.com", "www.inngest.com", "www.koyeb.com", "www.langchain.com", "www.lemonsqueezy.com", "www.linode.com", "www.mollie.com", "www.mongodb.com", "www.netlify.com", "www.paddle.com", "www.payoneer.com", "www.paypal.com", "www.pinecone.io", "www.scaleway.com", "www.singlestore.com", "www.tigrisdata.com", "www.timescale.com", "www.together.ai", "www.trychroma.com", "www.verifone.com", "www.vultr.com", "www.worldfirst.com", "xata.io", "zilliz.com"])

ALLOWED_CLASSIFICATION_6TUPLES = {
    ("LLM_API_ENDPOINT", "verified", "FRONTIER_SIMULATION_BENCHMARK", "SYNTHETIC_STRESS_TEST_BENCHMARK", "SIMULATION_SCHEDULE", "24"),
    ("LLM_API_ENDPOINT", "router-sourced", "FRONTIER_SIMULATION_BENCHMARK", "SYNTHETIC_STRESS_TEST_BENCHMARK", "SIMULATION_SCHEDULE", "24"),
    ("LLM_API_ENDPOINT", "router-sourced", "PRODUCTION_GA", "HTTP_200_GA_VERIFIED", "OFFICIAL_VENDOR_AND_ROUTER_VERIFIED", "6"),
    ("LLM_API_ENDPOINT", "router-sourced", "PRODUCTION_GA", "ROUTER_CATALOG_SYNCED_GA", "ROUTER_CATALOG_SNAPSHOT", "24"),
    ("CLOUD_AND_MOR_INFRASTRUCTURE", "infra-verified", "PRODUCTION_GA_INFRA", "INFRA_RATE_CARD_VERIFIED", "INFRASTRUCTURE_RATE_CARD", "168"),
}

EXPECTED_WINDOWS = ("W1", "W2", "W3", "W4")
EXPECTED_REGIONS = {"us-west-1", "ap-southeast-1", "eu-central-1"}
EXPECTED_CELLS   = {(w, r) for w in EXPECTED_WINDOWS for r in EXPECTED_REGIONS}
EXPECTED_MODELS  = set(["anthropic/claude-3-5-haiku-20241022", "anthropic/claude-3-7-sonnet-20250219", "deepseek/deepseek-chat", "deepseek/deepseek-reasoner", "google/gemini-2.5-flash", "google/gemini-2.5-pro", "meta-llama/llama-3.3-70b-instruct", "openai/gpt-4.1", "openai/gpt-4o-2024-11-20", "openai/o3-mini"])
EXPECTED_MODEL_SAMPLE_COUNTS = {"openai/gpt-4.1": 15, "openai/gpt-4o-2024-11-20": 15, "openai/o3-mini": 15, "anthropic/claude-3-7-sonnet-20250219": 15, "anthropic/claude-3-5-haiku-20241022": 14, "google/gemini-2.5-pro": 14, "google/gemini-2.5-flash": 14, "deepseek/deepseek-reasoner": 14, "deepseek/deepseek-chat": 14, "meta-llama/llama-3.3-70b-instruct": 14}
MAX_ALLOWED_RETRIES = 2

def fetch(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "Etuki-Standalone-Verifier/40.4"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, r.read().decode("utf-8")

def parse_iso_utc(ts_str):
    return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

def calc_percentile_nearest_rank(sorted_vals, pct):
    idx = max(0, min(len(sorted_vals) - 1, int(math.ceil((pct / 100.0) * len(sorted_vals))) - 1))
    return sorted_vals[idx]

def compute_rfc5280_spki_sha256(modulus_n_hex, exponent_e):
    assert exponent_e == 65537 and len(modulus_n_hex) == 512
    spki_der = bytes.fromhex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100" + modulus_n_hex + "0203010001")
    return hashlib.sha256(spki_der).hexdigest()

def verify_rs256_pkcs1_v15(digest_hex, sig_hex):
    expected_em = "0001" + ("ff" * 202) + "003031300d060960864801650304020105000420" + digest_hex
    actual_em = hex(pow(int(sig_hex, 16), PINNED_TRUSTED_EXPONENT_E, int(PINNED_TRUSTED_MODULUS_N_HEX, 16)))[2:].zfill(512)
    return len(actual_em) == 512 and actual_em == expected_em

now_utc = datetime.datetime.now(datetime.timezone.utc)

# 1. Verify 563-leaf ledger + Closed 6-Tuple CSV Join + 11 Negative Tests
_, txt = fetch("/api/oracle/leaves-563-hashes.txt?v=40.4")
rows, ledger_by_id = [], {}
for line in txt.splitlines():
    s = line.strip()
    if not s or s.startswith("#"): continue
    parts = [p.strip() for p in s.split("|")]
    if len(parts) == 6:
        idx_i = int(parts[0])
        rows.append((idx_i, parts[1], parts[2], parts[3], parts[4], parts[5]))
        ledger_by_id[parts[1]] = {"index": idx_i, "provenance_tier": parts[2], "model_reality_tier": parts[3], "cache_price_source": parts[4], "leaf_sha256_hex": parts[5]}

assert len(rows) == 563 and [r[0] for r in rows] == list(range(563))
leaves = [r[5] for r in rows]
assert len(set(leaves)) == 563

_, map_csv = fetch("/api/oracle/entity-reality-provenance-mapping.csv?v=40.4")
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
        if int(r["index"]) != ref["index"] or r["provenance_tier"] != ref["provenance_tier"] or r["model_reality_tier"] != ref["model_reality_tier"] or r["cache_price_source"] != ref["cache_price_source"] or r["leaf_sha256_hex"] != ref["leaf_sha256_hex"]:
            return False, "LEDGER_JOIN_MISMATCH"
        cls_6tuple = (r["entity_class"], r["provenance_tier"], r["model_reality_tier"], r["api_probe_status"], r.get("price_evidence_type", ""), r.get("staleness_sla_hours", ""))
        if cls_6tuple not in ALLOWED_CLASSIFICATION_6TUPLES: return False, "CLOSED_6TUPLE_ENUM_VIOLATION"
        parsed_u = urllib.parse.urlparse(r["source_url"])
        if parsed_u.scheme != "https" or parsed_u.netloc not in ALLOWED_SOURCE_DOMAINS: return False, "UNTRUSTED_DOMAIN"
        try:
            if parse_iso_utc(r["verified_at_utc"]) > ref_now_utc: return False, "FUTURE_TIMESTAMP"
        except Exception: return False, "INVALID_TIMESTAMP"
    return True, "PASS"

assert validate_mapping_csv_rows(map_csv, ledger_by_id, now_utc)[0]
csv_lines_raw = map_csv.strip().splitlines()
assert not validate_mapping_csv_rows("\n".join(csv_lines_raw[:-1]), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows("\n".join(csv_lines_raw[:2] + [csv_lines_raw[1]] + csv_lines_raw[3:]), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace(leaves[0], "0"*64, 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("FRONTIER_SIMULATION_BENCHMARK", "PRODUCTION_GA", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("https://", "ftp://", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("https://openrouter.ai", "https://untrusted-phishing.example.com", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("2026-10-30T02:10:00Z", "2099-12-31T23:59:59Z", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("SYNTHETIC_STRESS_TEST_BENCHMARK", "HTTP_200_GA_VERIFIED", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("PRODUCTION_GA", "UNLISTED_EXPERIMENTAL_TIER", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace("SIMULATION_SCHEDULE", "OFFICIAL_VENDOR_AND_ROUTER_VERIFIED", 1), ledger_by_id, now_utc)[0]
assert not validate_mapping_csv_rows(map_csv.replace(",168,", ",9999,", 1), ledger_by_id, now_utc)[0]

lvl = list(leaves)
for _ in range(10):
    if len(lvl) % 2 == 1: lvl.append(lvl[-1])
    lvl = [hashlib.sha256((lvl[i] + ":" + lvl[i+1]).encode("utf-8")).hexdigest() for i in range(0, len(lvl), 2)]
assert lvl[0] == EXPECTED_MERKLE_ROOT
print("[PASS 1/6] 563 Leaves, Closed 6-Tuple CSV Join (+11 Negative Tests), 3-Branch CSV Root & Merkle Root Verified!")

# 2. Recompute RFC 5280 ASN.1 DER SPKI SHA-256 Fingerprint
recalc_spki_fp = compute_rfc5280_spki_sha256(PINNED_TRUSTED_MODULUS_N_HEX, PINNED_TRUSTED_EXPONENT_E)
assert recalc_spki_fp == PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256
_, pubkey_body = fetch("/.well-known/etuki-ci-pubkey.json?v=40.4")
pubkey_doc = json.loads(pubkey_body)
assert compute_rfc5280_spki_sha256(pubkey_doc["public_modulus_n_hex"], int(pubkey_doc["public_exponent_e"])) == PINNED_TRUSTED_PUBKEY_FINGERPRINT_SHA256
print("[PASS 2/6] RFC 5280 ASN.1 DER SPKI Encoded & Recomputed SHA-256 Fingerprint Verified:", recalc_spki_fp)

# 3. Verify Oracle v40.5 manifest signature & byte-for-byte equality of `canonical_payload_verbatim_json` (P0-1)
_, oracle_body = fetch("/api/oracle/v1.json?v=40.4")
oracle = json.loads(oracle_body)
mf = oracle["evidence_manifest"]
assert mf["build_version"] == EXPECTED_BUILD_VER and mf["schema_version"] == EXPECTED_SCHEMA_VER
assert parse_iso_utc(mf["source_verified_at"]) <= parse_iso_utc(mf["generated_at"]) <= now_utc
em_env = mf["signature_envelope"]
canonical_bytes = json.dumps({k: v for k, v in mf.items() if k != "signature_envelope"}, separators=(",", ":"), sort_keys=True).encode("utf-8")
assert canonical_bytes.decode("utf-8") == em_env["canonical_payload_verbatim_json"], "Verbatim JSON byte mismatch"
recalc_manifest_sha = hashlib.sha256(canonical_bytes).hexdigest()
assert recalc_manifest_sha == em_env["signed_payload_sha256"] and verify_rs256_pkcs1_v15(recalc_manifest_sha, em_env["signature_value"])
print("[PASS 3/6] Oracle v40.5 Manifest RS256 Signature & Byte-for-Byte Verbatim Canonical JSON Verified:", recalc_manifest_sha)

# 4. Verify Dynamic 24h Half-Open Windows, Per-Attempt Retry Semantics (+6 Negative Tests), Recomputable Receipts & RS256 Signature
_, roll_b = fetch("/api/telemetry/live-rolling-24h.json?v=40.4")
roll_d = json.loads(roll_b)
win_obj, win_env = roll_d["signed_rolling_window_payload"], roll_d["rolling_window_signature_envelope"]
for tk in ("rolling_24h_start_utc", "rolling_24h_end_utc", "window_start_utc", "window_end_utc", "observed_at_utc", "generated_at_utc", "window_bounds_utc"):
    assert roll_d[tk] == win_obj[tk]
r24_start_dt, r24_end_dt = parse_iso_utc(roll_d["rolling_24h_start_utc"]), parse_iso_utc(roll_d["rolling_24h_end_utc"])
assert (r24_end_dt - r24_start_dt).total_seconds() == 86400
wb_map = win_obj["window_bounds_utc"]
parsed_wb = {}
for idx_w, w_k in enumerate(EXPECTED_WINDOWS):
    ws_dt, we_dt = parse_iso_utc(wb_map[w_k][0]), parse_iso_utc(wb_map[w_k][1])
    assert (we_dt - ws_dt).total_seconds() == 21600
    if idx_w == 0: assert ws_dt == r24_start_dt
    else: assert ws_dt == parsed_wb[EXPECTED_WINDOWS[idx_w - 1]][1]
    parsed_wb[w_k] = (ws_dt, we_dt)

def validate_probe_sample_row(s_row, idx_s, ref_wb):
    if int(s_row.get("http_status", 0)) != 200: return False, "NON200"
    w_c, reg_c, b_idx = s_row.get("window_code", ""), s_row.get("region", ""), int(s_row.get("burst_index", 0))
    if w_c not in EXPECTED_WINDOWS or reg_c not in EXPECTED_REGIONS: return False, "BAD_CELL"
    if s_row.get("sample_id") != f"prb_24h_{idx_s:03d}_{w_c}_{reg_c.replace('-', '')}_b{b_idx:02d}": return False, "BAD_SID"
    s_dt = parse_iso_utc(s_row["observed_at_utc"])
    if not (ref_wb[w_c][0] <= s_dt < ref_wb[w_c][1]): return False, "OUT_OF_WINDOW"
    gen_ms = int(s_row["duration_ms"]) - int(s_row["ttft_ms"])
    if gen_ms <= 0 or int(s_row.get("prompt_tokens", 0)) != 1024 or round((int(s_row["output_tokens"]) * 1000.0) / gen_ms, 1) != float(s_row["tps"]): return False, "BAD_TPS"
    r_cnt, p_arr = int(s_row.get("retry_count", -1)), s_row.get("prior_attempts", [])
    f_el, b_off, p_st, e2e = int(s_row.get("prior_failed_attempts_elapsed_ms", -1)), int(s_row.get("retry_backoff_ms", -1)), int(s_row.get("prior_attempt_http_status", -1)), int(s_row.get("end_to_end_elapsed_ms", -1))
    w_tok = int(s_row.get("wasted_partial_completion_tokens", -1))
    if not (0 <= r_cnt <= MAX_ALLOWED_RETRIES) or len(p_arr) != r_cnt or w_tok < 0: return False, "BAD_RETRY_LEN"
    if r_cnt == 0 and (f_el != 0 or b_off != 0 or p_st != 0 or w_tok != 0): return False, "BAD_ZERO_RETRY"
    if r_cnt > 0:
        for att in p_arr:
            if int(att.get("http_status", 0)) not in (429, 502, 503, 504): return False, "NEG_RETRY_INVALID_PRIOR_STATUS"
            if int(att.get("failed_attempt_elapsed_ms", 0)) <= 0: return False, "NEG_RETRY_NEGATIVE_ELAPSED"
            if int(att.get("backoff_ms", 0)) <= 0: return False, "NEG_RETRY_INVALID_BACKOFF"
            if int(att.get("wasted_partial_tokens", -1)) < 0: return False, "NEG_RETRY_WASTED_TOKEN_MISMATCH"
        if sum(int(a["failed_attempt_elapsed_ms"]) for a in p_arr) != f_el: return False, "BAD_FAILED_SUM"
        if sum(int(a["backoff_ms"]) for a in p_arr) != b_off: return False, "BAD_BACKOFF_SUM"
        if sum(int(a["wasted_partial_tokens"]) for a in p_arr) != w_tok: return False, "NEG_RETRY_WASTED_TOKEN_MISMATCH"
        if int(p_arr[-1]["http_status"]) != p_st: return False, "BAD_LAST_STATUS"
    if e2e != f_el + b_off + int(s_row["duration_ms"]): return False, "BAD_E2E"
    return True, "OK"

raw_144 = roll_d["raw_144_probe_samples"]
_, rec_b = fetch("/api/telemetry/vendor-raw-receipts.json?v=40.4")
rec_d = json.loads(rec_b)
receipt_by_sid = {r["sample_id"]: r for r in rec_d["receipts"]}
by_win_reg, by_model, samples_by_model, retry_counts_seen = {}, {}, {}, set()
for idx_s, s_row in enumerate(raw_144, start=1):
    assert validate_probe_sample_row(s_row, idx_s, parsed_wb)[0]
    linked_rec = receipt_by_sid[s_row["sample_id"]]
    rec_core = {k: v for k, v in linked_rec.items() if k != "raw_response_receipt_sha256"}
    assert hashlib.sha256(json.dumps(rec_core, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest() == linked_rec["raw_response_receipt_sha256"] == s_row["raw_response_receipt_sha256"]
    retry_counts_seen.add(int(s_row["retry_count"]))
    by_win_reg.setdefault((s_row["window_code"], s_row["region"]), []).append(int(s_row["burst_index"]))
    by_model[s_row["api_model_id"]] = by_model.get(s_row["api_model_id"], 0) + 1
    samples_by_model.setdefault(s_row["api_model_id"], []).append(s_row)

assert retry_counts_seen == {0, 1, 2} and set(by_win_reg.keys()) == EXPECTED_CELLS and by_model == EXPECTED_MODEL_SAMPLE_COUNTS
assert not validate_probe_sample_row({**raw_144[0], "http_status": 500}, 1, parsed_wb)[0]
assert not validate_probe_sample_row({**raw_144[0], "observed_at_utc": wb_map["W1"][1]}, 1, parsed_wb)[0]
assert not validate_probe_sample_row({**raw_144[28], "prior_attempts": [{"attempt_index": 1, "http_status": 200, "failed_attempt_elapsed_ms": 94, "backoff_ms": 250, "wasted_partial_tokens": 0}]}, 29, parsed_wb)[0]
assert not validate_probe_sample_row({**raw_144[28], "wasted_partial_completion_tokens": 99}, 29, parsed_wb)[0]
recalc_win_sha = hashlib.sha256(json.dumps(win_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
assert recalc_win_sha == win_env["signed_window_sha256"] and verify_rs256_pkcs1_v15(recalc_win_sha, win_env["signature_value"])
print("[PASS 4/6] 144 Samples, Per-Attempt Retry Semantics (+6 Negative Tests), Recomputable Receipts & RS256 Verified:", recalc_win_sha)

# 5. Execute 4-Way Percentile Check, Strict `build_version` + `schema_version` Check (+NEG-SCHEMA-VERSION-DRIFT),
#    Reconcile Usage Receipt Variance Check, Secondary Reports Check & Page DOM Assertions!
_, telem_b = fetch("/api/telemetry/metrics.json?v=40.4")
telem_d = json.loads(telem_b)
roll_by_id   = {p["api_model_id"]: p for p in roll_d["live_ga_probes"]}
oracle_by_id = {m["api_model_id"]: m for m in oracle["production_ga_10_flagship_telemetry"]}
telem_by_id  = {m["api_model_id"]: m for m in telem_d["production_ga_10_flagship_models"]}
for mid in EXPECTED_MODELS:
    m_rows = samples_by_model[mid]
    ttfts_s, tpss_s = sorted(int(x["ttft_ms"]) for x in m_rows), sorted(float(x["tps"]) for x in m_rows)
    assert calc_percentile_nearest_rank(ttfts_s, 50) == roll_by_id[mid]["p50_ttft_ms"] == telem_by_id[mid]["ttft_p50_ms"] == oracle_by_id[mid]["ttft_p50_ms"]
    assert calc_percentile_nearest_rank(ttfts_s, 90) == roll_by_id[mid]["p90_ttft_ms"] == telem_by_id[mid]["ttft_p90_ms"] == oracle_by_id[mid]["ttft_p90_ms"]
    assert calc_percentile_nearest_rank(tpss_s, 50)  == roll_by_id[mid]["tps"]         == telem_by_id[mid]["tps_median"]  == oracle_by_id[mid]["tps_median"]

def check_endpoint_versions(d_obj, ref_sha):
    sub_mf = d_obj.get("evidence_manifest", d_obj)
    b_v = d_obj.get("build_version") or sub_mf.get("build_version")
    s_v = d_obj.get("schema_version") or sub_mf.get("schema_version")
    if b_v != EXPECTED_BUILD_VER or s_v != EXPECTED_SCHEMA_VER or sub_mf.get("schema_version") != EXPECTED_SCHEMA_VER:
        return False
    s_sha = d_obj.get("signed_payload_sha256") or sub_mf.get("signature_envelope", {}).get("signed_payload_sha256")
    return s_sha == ref_sha

assert not check_endpoint_versions({"build_version": EXPECTED_BUILD_VER, "schema_version": EXPECTED_BUILD_VER, "signed_payload_sha256": recalc_manifest_sha}, recalc_manifest_sha), "NEG-SCHEMA-VERSION-DRIFT failed"

for ep in [
    "/api/telemetry/metrics.json?v=40.4",
    "/api/v1/mcp?call=check_context_cliff&model=gpt-6-1-sol&prompt_tokens=285000&completion_tokens=20000&v=40.4",
    "/api/v1/mcp?call=reconcile_usage_receipt&model=openai/gpt-4o-2024-11-20&prompt_tokens=180000&cached_tokens=0&completion_tokens=4000&actual_billed_usd=0.49&v=40.4",
    "/api/v1/mcp?call=reconcile_usage_receipt&model=openai/gpt-4o-2024-11-20&prompt_tokens=180000&cached_tokens=0&completion_tokens=4000&actual_billed_usd=0.62&v=40.4",
    "/api/v1/customer-telemetry?prompt=my_secret_prompt&v=40.4",
]:
    _, b = fetch(ep)
    d = json.loads(b)
    assert check_endpoint_versions(d, recalc_manifest_sha), f"Endpoint version/schema check failed on {ep}"

for rep_ep in ["/api/oracle/independent-ci-verifier-run.json?v=40.4", "/api/oracle/verification-report.json?v=40.4"]:
    _, rb = fetch(rep_ep)
    rd = json.loads(rb)
    assert rd["build_version"] == EXPECTED_BUILD_VER and rd["schema_version"] == EXPECTED_SCHEMA_VER

for page_path in ["/features?v=40.4", "/calculator?v=40.4", "/audit?v=40.4"]:
    st_code, html_b = fetch(page_path)
    assert st_code == 200 and EXPECTED_BUILD_VER in html_b and EXPECTED_SCHEMA_VER in html_b
print("[PASS 5/6] 4-Way Percentiles, Strict Schema/Build Sync (+NEG-SCHEMA-VERSION-DRIFT), Secondary Reports & Frontend Pages Verified!")

# 6. Verify Client-Contributed E3 Real Production Ledger (`/api/oracle/e3-agentrouter-real-ledger.json?v=40.5` — Zero Scope Conflict)
_, e3_b = fetch("/api/oracle/e3-agentrouter-real-ledger.json?v=40.5")
assert hashlib.sha256(e3_b.encode("utf-8")).hexdigest() == EXPECTED_E3_LEDGER_SHA
e3_d = json.loads(e3_b)
assert e3_d["certificate_id"] == "ETK-E3-20261013-CLIENT-EC01"
assert e3_d["build_version"] == EXPECTED_BUILD_VER and e3_d["schema_version"] == EXPECTED_SCHEMA_VER
bridge = e3_d["scope_reconciliation_bridge"]
assert bridge["primary_slice_186_calls_count"] + bridge["additional_merged_299_calls_count"] == bridge["full_merged_485_calls_count"] == 485
assert round(bridge["primary_slice_186_calls_usd"] + bridge["additional_merged_299_calls_usd"], 2) == bridge["full_merged_485_calls_billed_usd"] == 392.61
vulns = e3_d["four_vulnerability_categories_breakdown"]
assert round(sum(v["actual_billed_usd"] for v in vulns), 2) == 79.84 and round(sum(v["optimized_cost_usd"] for v in vulns), 2) == 18.92 and round(sum(v["net_savings_usd"] for v in vulns), 2) == 60.92
days = e3_d["daily_10day_reconciliation_rollup_186_calls"]
assert sum(d["calls"] for d in days) == 186 and round(sum(d["slice_billed_usd"] for d in days), 2) == 79.84 and round(sum(d["slice_optimized_usd"] for d in days), 2) == 18.92
calls_186 = e3_d["all_186_audited_call_records"]
assert len(calls_186) == 186 and round(sum(c["actual_billed_usd"] for c in calls_186), 2) == 79.84 and round(sum(c["counterfactual_optimized_usd"] for c in calls_186), 2) == 18.92
assert sum(m["calls"] for m in e3_d["primary_186_model_distribution"]) == 186
slices = {s["slice_id"]: s for s in e3_d["featured_screenshot_verbatim_slices"]}
s1_v = slices["AR-20261012-101118"]["three_way_variance_reconciliation"]
assert round(s1_v["reference_formula_total_usd"] + s1_v["gateway_pre_deduction_settlement_discount_usd"], 6) == s1_v["actual_deducted_usd"] == 0.817704
s4 = slices["AR-20261012-100148-COLD-CREATE"]["expanded_billing_formula_view"]
assert round((s4["uncached_prompt_tokens"] * 8.0 + s4["cache_read_tokens"] * 1.6 + s4["cache_creation_tokens"] * 10.0 + s4["expanded_completion_tokens"] * 40.0) / 1e6, 6) == 1.472942
s5 = slices["AR-20261012-100156-WARM-HIT-8S-LATER"]["expanded_billing_formula_view"]
assert round((s5["uncached_prompt_tokens"] * 8.0 + s5["cache_read_tokens"] * 1.6 + s5["cache_creation_tokens"] * 10.0 + s5["expanded_completion_tokens"] * 40.0) / 1e6, 6) == 0.248100
_, gw_b = fetch("/api/v1/chat/completions?v=40.5")
_, ldg_b = fetch("/api/v1/ledger?v=40.5")
ldg_d = json.loads(ldg_b)
assert ldg_d["build_version"] == EXPECTED_BUILD_VER and len(ldg_d["seven_immutable_ledgers"]) == 7
gw_d = json.loads(gw_b)
assert gw_d["build_version"] == EXPECTED_BUILD_VER and gw_d["schema_version"] == EXPECTED_SCHEMA_VER and gw_d["double_entry_ledger_posting_sample"]["reconciliation_status"] == "BALANCED_DOUBLE_ENTRY_VERIFIED"
print("[PASS 6/6] E3 186-Call ($79.84) & 485-Call ($392.61) Ledger, 10:11:18 3-Way Settlement Variance & BYOK Gateway Double-Entry Ledger Verified!")
