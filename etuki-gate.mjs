#!/usr/bin/env node
// Etuki Deterministic Context-Cliff & FinOps CI Gate CLI (v20-final)
// Snapshot: price-20261021-v17 (Merkle Root: 383a56752336f0155d1b1a543ecfe120bf213d71a9d1e9aa05061d7164385065)
import { pathToFileURL } from "node:url";

export const PRICING_SNAPSHOT_ID = "price-20261021-v17";
export const POLICY_VERSION = "esp-v20.0-20261027";
export const PRICING_MERKLE_ROOT = "sha256:383a56752336f0155d1b1a543ecfe120bf213d71a9d1e9aa05061d7164385065";
export const TOKENIZER_BILLING_CONVENTION = "Cliff thresholds (272K/100K) and single-call unrouted_cost_usd / routed_cost_usd operate on pre-tokenized API billing token counts; task-level effective_task_cost_usd applies cross-model tokenizer density rTok (1.28x Claude vs 1.00x o200k), retryRate (5%), and passRate (96%).";

export const SNAPSHOT_SPEC = {
  "gpt-6-1-sol": { in: 2.00, out: 10.00, cache: 0.10, cacheWrite: 2.00, cliffTokens: 272000, cliffIn: 4.00, cliffOut: 15.00, softBlock: 244800, rTok: 1.00, fallback: "claude-sonnet-5-5", defaultRoutedCacheHit: 0.80 },
  "claude-haiku-5-5": { in: 0.10, out: 0.50, cache: 0.01, cacheWrite: 0.125, cliffTokens: 100000, cliffIn: 0.50, cliffOut: 2.50, softBlock: 90000, rTok: 1.28, fallback: "gpt-6-luna", defaultRoutedCacheHit: 0.00 },
  "claude-sonnet-5-5": { in: 2.00, out: 10.00, cache: 0.10, cacheWrite: 2.50, cliffTokens: null, cliffIn: 2.00, cliffOut: 10.00, softBlock: null, rTok: 1.28, fallback: null, defaultRoutedCacheHit: 0.80 },
  "claude-opus-5-5": { in: 4.00, out: 20.00, cache: 0.20, cacheWrite: 5.00, cliffTokens: null, cliffIn: 4.00, cliffOut: 20.00, softBlock: null, rTok: 1.28, fallback: "claude-sonnet-5-5", defaultRoutedCacheHit: 0.40 },
  "gpt-6-luna": { in: 0.10, out: 0.50, cache: 0.01, cacheWrite: 0.10, cliffTokens: null, cliffIn: 0.10, cliffOut: 0.50, softBlock: null, rTok: 1.00, fallback: null, defaultRoutedCacheHit: 0.00 }
};

export function validatePositiveInt(val, name) {
  const n = typeof val === "number" ? val : Number(val);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
    const err = new Error(`Invalid ${name}: expected finite non-negative integer, got ${JSON.stringify(val)}`);
    err.exitCode = 2;
    throw err;
  }
  return n;
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
  requestId = "req_default",
  allowAsyncBatch = true,
  cacheHitRate = 0.40,
  routedCacheHitRate = null,
  coldStartCacheWrite = false,
  retryRate = 0.05,
  passRate = 0.96,
  budgetGateUsd = 0.060000
}) {
  if (typeof model !== "string" || !SNAPSHOT_SPEC[model]) {
    const err = new Error(`Invalid or unknown model: ${JSON.stringify(model)}`);
    err.exitCode = 2;
    throw err;
  }
  const pTok = validatePositiveInt(promptTokens, "promptTokens");
  const cTok = validatePositiveInt(completionTokens, "completionTokens");
  const m = SNAPSHOT_SPEC[model];

  const fingerprint = `fp_${model.replace(/[^a-z0-9]/g, "")}_${pTok}_${cTok}_${coldStartCacheWrite ? "cold" : "warm"}`;
  const decisionId = `dec_${requestId}_${fingerprint}`;
  const rawUnroutedStandardUsd = computeSingleCallCost(m, pTok, cTok, false, 0.0, false);

  if (m.softBlock && pTok > m.softBlock) {
    const crossedHardCliff = m.cliffTokens !== null && pTok > m.cliffTokens;
    const unroutedUsd = computeSingleCallCost(m, pTok, cTok, crossedHardCliff, 0.0, false);
    const projectedCliffRiskUsd = computeSingleCallCost(m, pTok, cTok, true, 0.0, false);

    const fb = SNAPSHOT_SPEC[m.fallback];
    const rCache = routedCacheHitRate !== null ? routedCacheHitRate : m.defaultRoutedCacheHit;
    const routedUsd = computeSingleCallCost(fb, pTok, cTok, false, rCache, coldStartCacheWrite);

    return {
      decision_id: decisionId,
      decision_fingerprint: fingerprint,
      policy_version: POLICY_VERSION,
      pricing_snapshot_id: PRICING_SNAPSHOT_ID,
      esp_savings_layer: "ESP-L2_POLICY_MODEL_REROUTE",
      action: crossedHardCliff ? "SOFT_BLOCK_REROUTE" : "PRE_CLIFF_SOFT_BLOCK_WARNING",
      zone: crossedHardCliff ? "HARD_CLIFF_BREACHED" : "PRE_CLIFF_GUARD_ZONE",
      target_model: m.fallback,
      unrouted_cost_usd: unroutedUsd,
      projected_cliff_risk_usd: projectedCliffRiskUsd,
      routed_cost_usd: routedUsd,
      realized_savings_usd: Number(Math.max(0, unroutedUsd - routedUsd).toFixed(4)),
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
      targetModel = allowAsyncBatch ? `${model}:batch+80pct-cache` : `${model}:sync+80pct-cache`;
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
      raw_single_call_unrouted_usd: rawUnroutedStandardUsd,
      unrouted_cost_usd: effTaskUsd,
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
    target_model: model,
    raw_single_call_unrouted_usd: rawUnroutedStandardUsd,
    effective_cost_usd: effTaskUsd,
    exit_code: 0
  };
}

export const BOUNDARY_TEST_VECTORS_9 = [
  { id: "CI-01", desc: "Positive baseline (Sol 15K/2K)", input: { model: "gpt-6-1-sol", promptTokens: 15000, completionTokens: 2000 }, expected: { action: "ALLOW_DIRECT", effective_cost_usd: 0.042219, exit_code: 0 } },
  { id: "CI-02", desc: "Hard cliff breach (Haiku 115K/4K > 100K)", input: { model: "claude-haiku-5-5", promptTokens: 115000, completionTokens: 4000 }, expected: { action: "SOFT_BLOCK_REROUTE", unrouted_cost_usd: 0.0675, routed_cost_usd: 0.0135, exit_code: 1 } },
  { id: "CI-03", desc: "Hard cliff breach (Sol 285K/20K > 272K)", input: { model: "gpt-6-1-sol", promptTokens: 285000, completionTokens: 20000 }, expected: { action: "SOFT_BLOCK_REROUTE", unrouted_cost_usd: 1.4400, routed_cost_usd: 0.3368, exit_code: 1 } },
  { id: "CI-04", desc: "Budget gate block with real fallback recompute (Opus 15K/2K -> Sonnet)", input: { model: "claude-opus-5-5", promptTokens: 15000, completionTokens: 2000 }, expected: { action: "BUDGET_GATE_BLOCK", unrouted_cost_usd: 0.108080, remediated_cost_usd: 0.054040, exit_code: 1 } },
  { id: "CI-05", desc: "Pre-cliff soft-block zone (Sol 250K/5K: >244.8K soft-block, <=272K cliff)", input: { model: "gpt-6-1-sol", promptTokens: 250000, completionTokens: 5000 }, expected: { action: "PRE_CLIFF_SOFT_BLOCK_WARNING", unrouted_cost_usd: 0.5500, projected_cliff_risk_usd: 1.0750, routed_cost_usd: 0.1700, realized_savings_usd: 0.3800, exit_code: 1 } },
  { id: "CI-06", desc: "Pre-cliff soft-block zone (Haiku 95K/4K: >90K soft-block, <=100K cliff)", input: { model: "claude-haiku-5-5", promptTokens: 95000, completionTokens: 4000 }, expected: { action: "PRE_CLIFF_SOFT_BLOCK_WARNING", unrouted_cost_usd: 0.0115, projected_cliff_risk_usd: 0.0575, routed_cost_usd: 0.0115, realized_savings_usd: 0.0000, exit_code: 1 } },
  { id: "CI-07", desc: "Cold-start cache write on routed cliff request (Sol 285K/20K coldStartCacheWrite=true)", input: { model: "gpt-6-1-sol", promptTokens: 285000, completionTokens: 20000, coldStartCacheWrite: true }, expected: { action: "SOFT_BLOCK_REROUTE", unrouted_cost_usd: 1.4400, routed_cost_usd: 0.8840, exit_code: 1 } },
  { id: "CI-08", desc: "Budget gate on model without cheaper fallback (Sonnet 60K/8K)", input: { model: "claude-sonnet-5-5", promptTokens: 60000, completionTokens: 8000 }, expected: { action: "BUDGET_GATE_BLOCK", unrouted_cost_usd: 0.216160, remediated_cost_usd: 0.079520, exit_code: 1 } },
  { id: "CI-09", desc: "4-point boundary continuity & monotonicity (244800 -> 244801 -> 272000 -> 272001 on Sol/5K out)", input: { model: "gpt-6-1-sol", promptTokens: 272001, completionTokens: 5000 }, expected: { action: "SOFT_BLOCK_REROUTE", unrouted_cost_usd: 1.1630, routed_cost_usd: 0.1806, exit_code: 1 } }
];

const isMain = Boolean(typeof process !== "undefined" && process.argv && process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href);
if (isMain) {
  const args = process.argv.slice(2);
  if (args.includes("--test")) {
    let passed = 0;
    for (const tv of BOUNDARY_TEST_VECTORS_9) {
      const res = compileRoute({ ...tv.input, requestId: tv.id.toLowerCase() });
      for (const [k, v] of Object.entries(tv.expected)) {
        if (res[k] !== v) {
          console.error(`[FAIL ${tv.id}] Expected ${k}=${v}, got ${res[k]}`);
          process.exit(2);
        }
      }
      passed++;
      console.log(`[PASS ${tv.id}] ${tv.desc} -> ${JSON.stringify(res)}`);
    }
    // Verify 4-point continuity & fail-closed input rejection
    const c244800 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 244800, completionTokens: 5000 }).raw_single_call_unrouted_usd;
    const c244801 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 244801, completionTokens: 5000 }).unrouted_cost_usd;
    const c272000 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 272000, completionTokens: 5000 }).unrouted_cost_usd;
    const c272001 = compileRoute({ model: "gpt-6-1-sol", promptTokens: 272001, completionTokens: 5000 }).unrouted_cost_usd;
    if (!(c244800 === 0.5396 && c244801 === 0.5396 && c272000 === 0.5940 && c272001 === 1.1630)) {
      console.error("[FAIL CONTINUITY]", { c244800, c244801, c272000, c272001 });
      process.exit(2);
    }
    let failClosedCaught = false;
    try { compileRoute({ model: "gpt-6-1-sol", promptTokens: NaN, completionTokens: 2000 }); } catch (e) { failClosedCaught = (e.exitCode === 2); }
    if (!failClosedCaught) { console.error("[FAIL FAIL-CLOSED CHECK]"); process.exit(2); }
    console.log(`[ALL ${passed}/9 BOUNDARY VECTORS, 4-POINT CONTINUITY & FAIL-CLOSED CHECKS PASSED] Snapshot: ${PRICING_SNAPSHOT_ID}`);
    process.exit(0);
  }
  const getArg = (flag, defVal) => {
    const idx = args.indexOf(flag);
    return idx !== -1 && args[idx + 1] !== undefined ? args[idx + 1] : defVal;
  };
  try {
    const model = getArg("--model", "gpt-6-1-sol");
    const promptTokens = validatePositiveInt(getArg("--in", "15000"), "--in");
    const completionTokens = validatePositiveInt(getArg("--out", "2000"), "--out");
    const requestId = getArg("--req-id", "cli_req_01");
    const coldStart = args.includes("--cold-start");
    const out = compileRoute({ model, promptTokens, completionTokens, requestId, coldStartCacheWrite: coldStart });
    console.log(JSON.stringify(out, null, 2));
    process.exit(out.exit_code);
  } catch (err) {
    console.error(JSON.stringify({ error: err.message, exit_code: err.exitCode || 2 }));
    process.exit(err.exitCode || 2);
  }
}
