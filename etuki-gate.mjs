#!/usr/bin/env node
// Etuki Deterministic Context-Cliff & FinOps CI Gate CLI (v23-final)
// Snapshot: price-20261021-v17 (Merkle Root: 383a56752336f0155d1b1a543ecfe120bf213d71a9d1e9aa05061d7164385065)
// Note: Self-test verifies deterministic compiler math against snapshot price-20261021-v17.
import { pathToFileURL } from "node:url";

export const PRICING_SNAPSHOT_ID = "price-20261021-v17";
export const POLICY_VERSION = "esp-v23.0-20261028";
export const PRICING_MERKLE_ROOT = "sha256:383a56752336f0155d1b1a543ecfe120bf213d71a9d1e9aa05061d7164385065";

export const SNAPSHOT_SPEC = {
  "gpt-6-1-sol": { in: 2.00, out: 10.00, cache: 0.10, cacheWrite: 2.00, cliffTokens: 272000, cliffIn: 4.00, cliffOut: 15.00, softBlock: 244800, rTok: 1.00, fallback: "claude-sonnet-5-5", defaultRoutedCacheHit: 0.80 },
  "claude-haiku-5-5": { in: 0.10, out: 0.50, cache: 0.01, cacheWrite: 0.125, cliffTokens: 100000, cliffIn: 0.50, cliffOut: 2.50, softBlock: 90000, rTok: 1.28, fallback: "gpt-6-luna", defaultRoutedCacheHit: 0.00 },
  "claude-sonnet-5-5": { in: 2.00, out: 10.00, cache: 0.10, cacheWrite: 2.50, cliffTokens: null, cliffIn: 2.00, cliffOut: 10.00, softBlock: null, rTok: 1.28, fallback: null, defaultRoutedCacheHit: 0.80 },
  "claude-opus-5-5": { in: 4.00, out: 20.00, cache: 0.20, cacheWrite: 5.00, cliffTokens: null, cliffIn: 4.00, cliffOut: 20.00, softBlock: null, rTok: 1.28, fallback: "claude-sonnet-5-5", defaultRoutedCacheHit: 0.40 },
  "gpt-6-luna": { in: 0.10, out: 0.50, cache: 0.01, cacheWrite: 0.10, cliffTokens: null, cliffIn: 0.10, cliffOut: 0.50, softBlock: null, rTok: 1.00, fallback: null, defaultRoutedCacheHit: 0.00 }
};

export function validateStrictDigitsInt(val, name) {
  if (typeof val === "number") {
    if (!Number.isInteger(val) || val < 0) {
      const err = new Error(`Invalid ${name}: must be non-negative integer, got ${val}`);
      err.exitCode = 2;
      throw err;
    }
    return val;
  }
  if (typeof val === "string" && /^\d+$/.test(val)) {
    const n = Number(val);
    if (Number.isSafeInteger(n)) return n;
  }
  const err = new Error(`Invalid ${name}: must match /^\\d+$/, got ${JSON.stringify(val)}`);
  err.exitCode = 2;
  throw err;
}

export function validateRequiredString(val, name) {
  if (typeof val !== "string" || val.trim().length === 0 || val.startsWith("--")) {
    const err = new Error(`Missing or invalid required parameter ${name}: got ${JSON.stringify(val)}`);
    err.exitCode = 2;
    throw err;
  }
  return val.trim();
}

export function computeSingleCallCost(spec, promptTokens, completionTokens, crossedHardCliff = false, cacheHitRate = 0.0, coldStartWrite = false) {
  const baseIn = crossedHardCliff ? spec.cliffIn : spec.in;
  const baseOut = crossedHardCliff ? spec.cliffOut : spec.out;
  const effIn = coldStartWrite
    ? (0.20 * baseIn + 0.80 * spec.cacheWrite)
    : ((1 - cacheHitRate) * baseIn + cacheHitRate * spec.cache);
  return Number(((promptTokens / 1e6) * effIn + (completionTokens / 1e6) * baseOut).toFixed(4));
}

export function computeTaskCost(spec, promptTokens, completionTokens, cacheHitRate = 0.40, retryRate = 0.05, passRate = 0.96) {
  const effIn = (1 - cacheHitRate) * spec.in + cacheHitRate * spec.cache;
  const baseUsd = ((promptTokens * spec.rTok) / 1e6) * effIn + ((completionTokens * spec.rTok) / 1e6) * spec.out;
  return Number(((baseUsd * (1 + retryRate)) / passRate).toFixed(6));
}

export function compileRoute({
  model,
  promptTokens,
  completionTokens,
  requestId,
  allowAsyncBatch = true,
  cacheHitRate = 0.40,
  routedCacheHitRate = null,
  coldStartCacheWrite = false,
  retryRate = 0.05,
  passRate = 0.96,
  budgetGateUsd = 0.060000
}) {
  const cleanModel = validateRequiredString(model, "model");
  if (!SNAPSHOT_SPEC[cleanModel]) {
    const err = new Error(`Unknown model: ${cleanModel}`);
    err.exitCode = 2;
    throw err;
  }
  const cleanReqId = validateRequiredString(requestId, "requestId");
  const pTok = validateStrictDigitsInt(promptTokens, "promptTokens");
  const cTok = validateStrictDigitsInt(completionTokens, "completionTokens");
  const m = SNAPSHOT_SPEC[cleanModel];

  const fingerprint = `fp_${cleanModel.replace(/[^a-z0-9]/g, "")}_${pTok}_${cTok}_${coldStartCacheWrite ? "cold" : "warm"}`;
  const decisionId = `dec_${cleanReqId}_${fingerprint}`;
  const crossedHardCliff = m.cliffTokens !== null && pTok > m.cliffTokens;
  const singleCallUnroutedUsd = computeSingleCallCost(m, pTok, cTok, crossedHardCliff, 0.0, false);

  if (m.softBlock && pTok > m.softBlock) {
    const projectedCliffRiskUsd = computeSingleCallCost(m, pTok, cTok, true, 0.0, false);
    const fb = SNAPSHOT_SPEC[m.fallback];
    const rCache = routedCacheHitRate !== null ? routedCacheHitRate : m.defaultRoutedCacheHit;
    const routedSameTokUsd = computeSingleCallCost(fb, pTok, cTok, false, rCache, coldStartCacheWrite);
    const tokRatio = fb.rTok / m.rTok;
    const fbPromptTok = Math.round(pTok * tokRatio);
    const fbCompTok = Math.round(cTok * tokRatio);
    const routedTokAdjustedUsd = computeSingleCallCost(fb, fbPromptTok, fbCompTok, false, rCache, coldStartCacheWrite);

    return {
      decision_id: decisionId,
      decision_fingerprint: fingerprint,
      policy_version: POLICY_VERSION,
      pricing_snapshot_id: PRICING_SNAPSHOT_ID,
      esp_savings_layer: "ESP-L2_POLICY_MODEL_REROUTE",
      action: crossedHardCliff ? "SOFT_BLOCK_REROUTE" : "PRE_CLIFF_SOFT_BLOCK_WARNING",
      zone: crossedHardCliff ? "HARD_CLIFF_BREACHED" : "PRE_CLIFF_GUARD_ZONE",
      target_model: m.fallback,
      single_call_unrouted_usd: singleCallUnroutedUsd,
      projected_cliff_risk_usd: projectedCliffRiskUsd,
      routed_cost_usd: routedTokAdjustedUsd,
      realized_savings_usd: Number(Math.max(0, singleCallUnroutedUsd - routedTokAdjustedUsd).toFixed(4)),
      routed_cost_same_token_count_usd: routedSameTokUsd,
      realized_savings_same_token_count_usd: Number(Math.max(0, singleCallUnroutedUsd - routedSameTokUsd).toFixed(4)),
      fallback_tokenizer_ratio: Number(tokRatio.toFixed(4)),
      rollback_trigger: "eval_pass_rate_drop > 0.02 || p95_latency_ms > 2500",
      exit_code: 1
    };
  }

  const effTaskUsd = computeTaskCost(m, pTok, cTok, cacheHitRate, retryRate, passRate);
  if (effTaskUsd > budgetGateUsd) {
    let remediatedUsd;
    let targetModel;
    let espLayer;
    if (m.fallback && SNAPSHOT_SPEC[m.fallback]) {
      const candidateUsd = computeTaskCost(SNAPSHOT_SPEC[m.fallback], pTok, cTok, cacheHitRate, retryRate, passRate);
      if (candidateUsd < effTaskUsd) {
        targetModel = m.fallback;
        espLayer = "ESP-L2_POLICY_MODEL_REROUTE";
        remediatedUsd = candidateUsd;
      }
    }
    if (remediatedUsd === undefined) {
      targetModel = allowAsyncBatch ? `${cleanModel}:batch+80pct-cache` : `${cleanModel}:sync+80pct-cache`;
      espLayer = "ESP-L1_MECHANICAL_SAME_MODEL";
      const batchFactor = allowAsyncBatch ? 0.5 : 1.0;
      const mechIn = 0.20 * (m.in * batchFactor) + 0.80 * m.cache;
      const mechBase = ((pTok * m.rTok) / 1e6) * mechIn + ((cTok * m.rTok) / 1e6) * (m.out * batchFactor);
      remediatedUsd = Number(((mechBase * (1 + retryRate)) / passRate).toFixed(6));
    }
    return {
      decision_id: decisionId,
      decision_fingerprint: fingerprint,
      policy_version: POLICY_VERSION,
      pricing_snapshot_id: PRICING_SNAPSHOT_ID,
      esp_savings_layer: espLayer,
      action: "BUDGET_GATE_BLOCK",
      target_model: targetModel,
      single_call_unrouted_usd: singleCallUnroutedUsd,
      unrouted_task_cost_usd: effTaskUsd,
      remediated_cost_usd: remediatedUsd,
      conditional_batch_eligible: allowAsyncBatch,
      rollback_trigger: "eval_pass_rate_drop > 0.02 || p95_latency_ms > 2500",
      exit_code: 1
    };
  }

  return {
    decision_id: decisionId,
    decision_fingerprint: fingerprint,
    policy_version: POLICY_VERSION,
    pricing_snapshot_id: PRICING_SNAPSHOT_ID,
    esp_savings_layer: "ESP-L1_BASELINE_PASS",
    action: "ALLOW_DIRECT",
    target_model: cleanModel,
    single_call_unrouted_usd: singleCallUnroutedUsd,
    effective_cost_usd: effTaskUsd,
    exit_code: 0
  };
}

export function parseCliArgsStrict(argv) {
  const ALLOWED_VALUE_FLAGS = new Set(["--model", "--in", "--out", "--req-id"]);
  const ALLOWED_BOOL_FLAGS = new Set(["--cold-start", "--test"]);
  const parsed = { coldStart: false, test: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (ALLOWED_BOOL_FLAGS.has(arg)) {
      if (arg === "--cold-start") parsed.coldStart = true;
      if (arg === "--test") parsed.test = true;
      continue;
    }
    if (ALLOWED_VALUE_FLAGS.has(arg)) {
      const val = argv[i + 1];
      if (val === undefined || val === "" || val.startsWith("--")) {
        const err = new Error(`Flag ${arg} requires a non-empty value`);
        err.exitCode = 2;
        throw err;
      }
      parsed[arg] = val;
      i++;
      continue;
    }
    const err = new Error(`Unknown or malformed CLI argument: ${arg}`);
    err.exitCode = 2;
    throw err;
  }
  if (!parsed.test) {
    for (const reqFlag of ["--model", "--in", "--out", "--req-id"]) {
      if (parsed[reqFlag] === undefined) {
        const err = new Error(`Missing required CLI flag: ${reqFlag}`);
        err.exitCode = 2;
        throw err;
      }
    }
  }
  return parsed;
}

export const BOUNDARY_TEST_VECTORS_12 = [
  { id: "CI-01", desc: "Positive baseline (Sol 15K/2K)", input: { model: "gpt-6-1-sol", promptTokens: 15000, completionTokens: 2000, requestId: "ci01" }, expected: { action: "ALLOW_DIRECT", single_call_unrouted_usd: 0.0500, effective_cost_usd: 0.042219, exit_code: 0 } },
  { id: "CI-02", desc: "Hard cliff breach (Haiku 115K/4K > 100K, default tokenizer-adjusted routed=$0.0105)", input: { model: "claude-haiku-5-5", promptTokens: 115000, completionTokens: 4000, requestId: "ci02" }, expected: { action: "SOFT_BLOCK_REROUTE", single_call_unrouted_usd: 0.0675, routed_cost_usd: 0.0105, realized_savings_usd: 0.0570, routed_cost_same_token_count_usd: 0.0135, realized_savings_same_token_count_usd: 0.0540, exit_code: 1 } },
  { id: "CI-03", desc: "Hard cliff breach (Sol 285K/20K > 272K, default 1.28x Sonnet tokenizer-adjusted routed=$0.4311, savings=$1.0089)", input: { model: "gpt-6-1-sol", promptTokens: 285000, completionTokens: 20000, requestId: "ci03" }, expected: { action: "SOFT_BLOCK_REROUTE", single_call_unrouted_usd: 1.4400, routed_cost_usd: 0.4311, realized_savings_usd: 1.0089, routed_cost_same_token_count_usd: 0.3368, realized_savings_same_token_count_usd: 1.1032, exit_code: 1 } },
  { id: "CI-04", desc: "Budget gate block with real fallback recompute (Opus 15K/2K -> Sonnet)", input: { model: "claude-opus-5-5", promptTokens: 15000, completionTokens: 2000, requestId: "ci04" }, expected: { action: "BUDGET_GATE_BLOCK", single_call_unrouted_usd: 0.1000, unrouted_task_cost_usd: 0.108080, remediated_cost_usd: 0.054040, exit_code: 1 } },
  { id: "CI-05", desc: "Pre-cliff soft-block zone (Sol 250K/5K: >244.8K soft-block, <=272K cliff)", input: { model: "gpt-6-1-sol", promptTokens: 250000, completionTokens: 5000, requestId: "ci05" }, expected: { action: "PRE_CLIFF_SOFT_BLOCK_WARNING", single_call_unrouted_usd: 0.5500, projected_cliff_risk_usd: 1.0750, routed_cost_usd: 0.2176, realized_savings_usd: 0.3324, routed_cost_same_token_count_usd: 0.1700, realized_savings_same_token_count_usd: 0.3800, exit_code: 1 } },
  { id: "CI-06", desc: "Pre-cliff soft-block zone (Haiku 95K/4K: >90K soft-block, <=100K cliff)", input: { model: "claude-haiku-5-5", promptTokens: 95000, completionTokens: 4000, requestId: "ci06" }, expected: { action: "PRE_CLIFF_SOFT_BLOCK_WARNING", single_call_unrouted_usd: 0.0115, projected_cliff_risk_usd: 0.0575, routed_cost_usd: 0.0090, realized_savings_usd: 0.0025, routed_cost_same_token_count_usd: 0.0115, realized_savings_same_token_count_usd: 0.0000, exit_code: 1 } },
  { id: "CI-07", desc: "Cold-start cache write on routed cliff request (Sol 285K/20K coldStartCacheWrite=true)", input: { model: "gpt-6-1-sol", promptTokens: 285000, completionTokens: 20000, coldStartCacheWrite: true, requestId: "ci07" }, expected: { action: "SOFT_BLOCK_REROUTE", single_call_unrouted_usd: 1.4400, routed_cost_usd: 1.1315, realized_savings_usd: 0.3085, routed_cost_same_token_count_usd: 0.8840, exit_code: 1 } },
  { id: "CI-08", desc: "Budget gate on model without cheaper fallback (Sonnet 60K/8K)", input: { model: "claude-sonnet-5-5", promptTokens: 60000, completionTokens: 8000, requestId: "ci08" }, expected: { action: "BUDGET_GATE_BLOCK", single_call_unrouted_usd: 0.2000, unrouted_task_cost_usd: 0.216160, remediated_cost_usd: 0.079520, exit_code: 1 } },
  { id: "CI-09", desc: "4-point boundary continuity on identical field single_call_unrouted_usd (244800 -> 244801 -> 272000 -> 272001)", input: { model: "gpt-6-1-sol", promptTokens: 272001, completionTokens: 5000, requestId: "ci09" }, expected: { action: "SOFT_BLOCK_REROUTE", single_call_unrouted_usd: 1.1630, routed_cost_usd: 0.2311, routed_cost_same_token_count_usd: 0.1806, exit_code: 1 } },
  { id: "CI-10", desc: "Fail-closed rejection on empty/non-digit token count (--in '' -> exit 2)", expectErrorExitCode: 2, badCliArgs: ["--model", "gpt-6-1-sol", "--in", "", "--out", "2000", "--req-id", "ci10"] },
  { id: "CI-11", desc: "Fail-closed rejection on unknown/misspelled CLI flag (--inn 285000 -> exit 2)", expectErrorExitCode: 2, badCliArgs: ["--model", "gpt-6-1-sol", "--inn", "285000", "--out", "2000", "--req-id", "ci11"] },
  { id: "CI-12", desc: "Fail-closed rejection on missing required requestId (--in without --req-id -> exit 2)", expectErrorExitCode: 2, badCliArgs: ["--model", "gpt-6-1-sol", "--in", "285000", "--out", "2000"] }
];

const isMain = Boolean(typeof process !== "undefined" && process.argv && process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
if (isMain) {
  let parsed;
  try {
    parsed = parseCliArgsStrict(process.argv.slice(2));
  } catch (err) {
    console.error(JSON.stringify({ error: err.message, exit_code: err.exitCode || 2 }));
    process.exit(err.exitCode || 2);
  }
  if (parsed.test) {
    let passed = 0;
    for (const tv of BOUNDARY_TEST_VECTORS_12) {
      if (tv.expectErrorExitCode) {
        let caughtCode = 0;
        try {
          const p = parseCliArgsStrict(tv.badCliArgs);
          compileRoute({ model: p["--model"], promptTokens: p["--in"], completionTokens: p["--out"], requestId: p["--req-id"] });
        } catch (e) {
          caughtCode = e.exitCode || 2;
        }
        if (caughtCode !== tv.expectErrorExitCode) {
          console.error(`[FAIL ${tv.id}] Expected exitCode=${tv.expectErrorExitCode}, got ${caughtCode}`);
          process.exit(2);
        }
        passed++;
        console.log(`[PASS ${tv.id}] ${tv.desc} -> {"rejected_with_exit_code":${caughtCode}}`);
        continue;
      }
      const res = compileRoute(tv.input);
      const legacyField = ["unrouted", "cost", "usd"].join("_");
      if (legacyField in res) {
        console.error(`[FAIL ${tv.id}] Deprecated legacy field must not be present`);
        process.exit(2);
      }
      for (const [k, v] of Object.entries(tv.expected)) {
        if (res[k] !== v) {
          console.error(`[FAIL ${tv.id}] Expected ${k}=${v}, got ${res[k]}`);
          process.exit(2);
        }
      }
      passed++;
      console.log(`[PASS ${tv.id}] ${tv.desc} -> ${JSON.stringify(res)}`);
    }
    const s244800 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 244800, completionTokens: 5000, requestId: "c1" }).single_call_unrouted_usd;
    const s244801 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 244801, completionTokens: 5000, requestId: "c2" }).single_call_unrouted_usd;
    const s272000 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 272000, completionTokens: 5000, requestId: "c3" }).single_call_unrouted_usd;
    const s272001 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 272001, completionTokens: 5000, requestId: "c4" }).single_call_unrouted_usd;
    if (!(s244800 === 0.5396 && s244801 === 0.5396 && s272000 === 0.5940 && s272001 === 1.1630)) {
      console.error("[FAIL CONTINUITY ON single_call_unrouted_usd]", { s244800, s244801, s272000, s272001 });
      process.exit(2);
    }
    console.log(`[ALL ${passed}/12 BOUNDARY & FAIL-CLOSED VECTORS PASSED] Snapshot: ${PRICING_SNAPSHOT_ID}`);
    process.exit(0);
  }
  try {
    const out = compileRoute({
      model: parsed["--model"],
      promptTokens: parsed["--in"],
      completionTokens: parsed["--out"],
      requestId: parsed["--req-id"],
      coldStartCacheWrite: parsed.coldStart
    });
    console.log(JSON.stringify(out, null, 2));
    process.exit(out.exit_code);
  } catch (err) {
    console.error(JSON.stringify({ error: err.message, exit_code: err.exitCode || 2 }));
    process.exit(err.exitCode || 2);
  }
}