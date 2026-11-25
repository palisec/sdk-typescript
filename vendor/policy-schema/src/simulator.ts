import { REASON_CODES, RETRYABLE, type ReasonCode } from "./codes";
import type {
  CheckResult,
  Environment,
  EvaluationResult,
  Intent,
  LedgerState,
  Policy,
  Reservation,
} from "./types";
import { NATIVE_TOKEN } from "./types";
import { validatePolicy } from "./validate";

/**
 * Deterministic local evaluator (spec §5.2, §9.4).
 *
 * Same policy + intent + state + environment always yields the same result. It never
 * signs, never broadcasts, and never mutates its inputs: the caller receives
 * `next_state` and decides whether to keep it.
 *
 * This is the reference behaviour for the schema. The production evaluator runs the
 * same checks inside the protected signing boundary against authoritative state.
 */

const WINDOW_SECONDS = 3600;
const RESERVATION_TTL_SECONDS = 300;
const MAX_CALLDATA_BYTES = 65536;
const WEI_PER_ETH = 10n ** 18n;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX = /^0x([0-9a-fA-F]{2})*$/;
const UINT = /^(0|[1-9][0-9]{0,77})$/;

export const EMPTY_STATE: LedgerState = {
  reservations: [],
  seen_request_ids: [],
  calldata_seen: {},
  intent_seen: {},
};

/** 64-bit FNV-1a. A local fingerprint only; the production path uses keccak256. */
export function fingerprint(input: string): string {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < input.length; i++) {
    h ^= BigInt(input.charCodeAt(i));
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return "0x" + h.toString(16).padStart(16, "0");
}

export function selectorOf(data: string): string | null {
  return data.length >= 10 ? data.slice(0, 10).toLowerCase() : null;
}

/** USD micros for an amount of wei, rounded up so limits are never under-counted. */
export function weiToUsdMicros(wei: bigint, priceMicros: bigint): bigint {
  const n = wei * priceMicros;
  return n === 0n ? 0n : (n + WEI_PER_ETH - 1n) / WEI_PER_ETH;
}

const LIVE_CHECKS: Omit<CheckResult, "status" | "detail">[] = [
  { id: "simulate", label: "Execution simulation against chain state", enforcement: "live" },
  { id: "bind", label: "Authorization bound to operation hash, chain, policy version, expiry", enforcement: "live" },
  { id: "sign", label: "Signature from the protected signing path", enforcement: "live" },
  { id: "validate_onchain", label: "Smart-account validation of the Palisec signature", enforcement: "live" },
  { id: "submit", label: "Bundler submission and receipt reconciliation", enforcement: "live" },
];

export function evaluate(
  policy: Policy | null,
  intent: Intent,
  state: LedgerState,
  env: Environment,
): EvaluationResult {
  const checks: CheckResult[] = [];
  let failed: { code: ReasonCode; message: string } | null = null;
  let review: { code: ReasonCode; message: string } | null = null;

  const run = (
    id: string,
    label: string,
    fn: () => { status: "pass" | "fail" | "review"; detail: string; code?: ReasonCode },
  ) => {
    if (failed) {
      checks.push({ id, label, status: "skipped", detail: "Not evaluated: an earlier check denied the request.", enforcement: "local" });
      return;
    }
    const r = fn();
    checks.push({ id, label, status: r.status, detail: r.detail, enforcement: "local" });
    if (r.status === "fail") failed = { code: r.code!, message: r.detail };
    if (r.status === "review" && !review) review = { code: r.code!, message: r.detail };
  };

  // Expire stale reservations before reading budget state.
  const reservations: Reservation[] = state.reservations.map((r) =>
    r.state === "reserved" && r.expires_at <= env.now ? { ...r, state: "released" } : r,
  );

  let usd = 0n;
  let fee = 0n;
  const value = UINT.test(intent.value_wei) ? BigInt(intent.value_wei) : 0n;
  const selector = selectorOf(intent.data);

  run("policy", "Active, valid policy", () => {
    if (!policy) return { status: "fail", code: "PS_POLICY_001", detail: "No policy is configured. A missing policy is never treated as allow-all." };
    const errs = validatePolicy(policy);
    if (errs.length) return { status: "fail", code: "PS_POLICY_001", detail: `Policy failed schema validation: ${errs[0]!.path} ${errs[0]!.message}.` };
    if (policy.status !== "active") return { status: "fail", code: "PS_POLICY_001", detail: `Policy status is "${policy.status}", not active.` };
    return { status: "pass", detail: `${policy.policy_id} v${policy.version} is active.` };
  });

  run("schema", "Request schema", () => {
    const bad =
      !ADDRESS.test(intent.from) ? "from" :
      !ADDRESS.test(intent.to) ? "to" :
      !UINT.test(intent.value_wei) ? "value_wei" :
      !HEX.test(intent.data) ? "data" :
      (intent.data.length - 2) / 2 > MAX_CALLDATA_BYTES ? "data (too long)" :
      !intent.request_id ? "request_id" : null;
    if (bad) return { status: "fail", code: "PS_REQUEST_001", detail: `Invalid field: ${bad}.` };
    return { status: "pass", detail: "All fields well-formed and within size bounds." };
  });

  run("replay", "Request identity, deadline, replay", () => {
    if (state.seen_request_ids.includes(intent.request_id))
      return { status: "fail", code: "PS_REPLAY_001", detail: `request_id ${intent.request_id} was already evaluated.` };
    if (intent.deadline <= env.now)
      return { status: "fail", code: "PS_REPLAY_001", detail: `Deadline ${intent.deadline} has passed (now ${env.now}).` };
    return { status: "pass", detail: `New request; ${intent.deadline - env.now}s until deadline.` };
  });

  run("active", "Emergency stop and agent status", () => {
    if (env.emergency_stop) return { status: "fail", code: "PS_PAUSED_001", detail: "Global emergency stop is active. All new protected executions are denied." };
    if (env.paused_agents.includes(intent.agent_id)) return { status: "fail", code: "PS_PAUSED_001", detail: `Agent ${intent.agent_id} is paused.` };
    return { status: "pass", detail: "No emergency stop; agent is active." };
  });

  run("account_stop", "Emergency stop engaged by the account on the registry", () => accountStopCheck(policy!, intent, env, selector, value));

  run("chain", "Chain and account binding", () => {
    if (intent.chain_id !== policy!.account.chain_id)
      return { status: "fail", code: "PS_TARGET_001", detail: `Chain ${intent.chain_id} does not match policy chain ${policy!.account.chain_id}.` };
    if (intent.from.toLowerCase() !== policy!.account.address.toLowerCase())
      return { status: "fail", code: "PS_POLICY_001", detail: "Sender is not the account this policy protects." };
    return { status: "pass", detail: `Chain ${intent.chain_id}; account matches.` };
  });

  run("denylist", "Explicit deny rules", () => {
    const hit = policy!.contracts.denylist.some((a) => a.toLowerCase() === intent.to.toLowerCase());
    if (hit) return { status: "fail", code: "PS_POLICY_002", detail: "Target is on the explicit denylist. Deny overrides allow." };
    return { status: "pass", detail: "No deny rule matched." };
  });

  const entry = policy?.contracts.allowlist.find((e) => e.address.toLowerCase() === intent.to.toLowerCase());

  run("target", "Target contract allowlist", () => {
    if (!entry) return { status: "fail", code: "PS_TARGET_001", detail: "Target is not on the allowlist; default is deny." };
    if (entry.require_verified_code && env.verified_code[intent.to.toLowerCase()] !== true)
      return { status: "fail", code: "PS_TARGET_001", detail: "Target requires verified code, and verification is missing or failed." };
    return { status: "pass", detail: entry.require_verified_code ? "Allowlisted; code verified per the chain environment's report." : "Allowlisted." };
  });

  run("method", "Function selector", () => {
    if (!selector) return { status: "pass", detail: "Native transfer (no calldata)." };
    if (entry!.selectors.includes(selector as `0x${string}`)) return { status: "pass", detail: `Selector ${selector} is allowed.` };
    if (policy!.human_approval.require_for_unknown_methods)
      return { status: "review", code: "PS_HUMAN_001", detail: `Selector ${selector} is not allowlisted; policy routes unknown methods to human review.` };
    return { status: "fail", code: "PS_METHOD_001", detail: `Selector ${selector} is not allowed.` };
  });

  // Proven on Zolva: read once, after the policy has validated. Malformed input is an engine error.
  let proven: boolean | null = null;
  const unlocked = () => (proven ??= provenUnlocked(policy!, env));
  const PROVEN_NOTE = " Unlocked limit: verified Zolva record (paper trading).";

  run("value", "Per-transaction value limit", () => {
    const max = BigInt(unlocked() ? policy!.proven_record!.unlocked_limits.max_transaction_value_wei : policy!.limits.max_transaction_value_wei);
    const note = unlocked() ? PROVEN_NOTE : "";
    if (value > max) return { status: "fail", code: "PS_BUDGET_001", detail: `Value ${value} wei exceeds the per-transaction limit of ${max} wei.${note}` };
    return { status: "pass", detail: `${value} wei ≤ ${max} wei.${note}` };
  });

  run("fee", "Fee estimate", () => {
    if (env.fee_estimate_wei === null || !UINT.test(env.fee_estimate_wei))
      return { status: "fail", code: "PS_FEE_001", detail: "Fee estimate unavailable. An unknown fee is never treated as zero." };
    fee = BigInt(env.fee_estimate_wei);
    const max = BigInt(policy!.limits.max_gas_cost_wei);
    if (fee > max) return { status: "fail", code: "PS_BUDGET_001", detail: `Estimated fee ${fee} wei exceeds the gas limit of ${max} wei.` };
    return { status: "pass", detail: `Estimated fee ${fee} wei ≤ ${max} wei.` };
  });

  run("price", "Price freshness", () => {
    if (!env.eth_usd) return { status: "fail", code: "PS_STATE_001", detail: "No price available. USD limits cannot be enforced, so the request fails closed." };
    const age = env.now - env.eth_usd.observed_at;
    if (age > policy!.limits.max_price_age_seconds)
      return { status: "fail", code: "PS_STATE_001", detail: `Price is ${age}s old; maximum is ${policy!.limits.max_price_age_seconds}s.` };
    usd = weiToUsdMicros(value + fee, BigInt(env.eth_usd.price_micros));
    return { status: "pass", detail: `Price is ${age}s old. Exposure: ${formatUsd(usd)} (value + fee).` };
  });

  run("spend", "Token spend (simulated outflows and open allowances, in USD)", () => {
    const r = spendCheck(policy!, intent, env, selector, value, usd);
    usd += r.add;
    return r.outcome;
  });

  run("budget", "Rolling hourly budget (atomic reservation)", () => {
    const since = env.now - WINDOW_SECONDS;
    const used = reservations
      .filter((r) => r.state !== "released" && r.created_at > since)
      .reduce((s, r) => s + BigInt(r.amount_usd_micros), 0n);
    const max = BigInt(unlocked() ? policy!.proven_record!.unlocked_limits.hourly_budget_usd_micros : policy!.limits.hourly_budget_usd_micros);
    const note = unlocked() ? PROVEN_NOTE : "";
    if (used + usd > max)
      return { status: "fail", code: "PS_BUDGET_001", detail: `${formatUsd(used)} used + ${formatUsd(usd)} requested exceeds the ${formatUsd(max)} hourly budget.${note}` };
    return { status: "pass", detail: `${formatUsd(used + usd)} of ${formatUsd(max)} after this reservation.${note}` };
  });

  run("pending", "Pending operation limit", () => {
    const open = reservations.filter((r) => r.state === "reserved" || r.state === "pending_approval").length;
    const max = policy!.limits.max_pending_operations;
    if (open >= max) return { status: "fail", code: "PS_RATE_001", detail: `${open} operations pending; limit is ${max}.` };
    return { status: "pass", detail: `${open} of ${max} pending slots in use.` };
  });

  const calldataKey = fingerprint(`${intent.to.toLowerCase()}|${intent.data.toLowerCase()}`);
  const intentKey = fingerprint(`${intent.agent_id}|${intent.to.toLowerCase()}|${selector ?? "native"}|${intent.value_wei}`);

  run("loop", "Repeated calldata and intent", () => {
    const c = state.calldata_seen[calldataKey];
    const cd = policy!.cooldowns.identical_calldata_seconds;
    if (c !== undefined && env.now - c < cd)
      return { status: "fail", code: "PS_LOOP_001", detail: `Identical calldata seen ${env.now - c}s ago; cooldown is ${cd}s.` };
    const i = state.intent_seen[intentKey];
    const id = policy!.cooldowns.identical_intent_seconds;
    if (i !== undefined && env.now - i < id)
      return { status: "fail", code: "PS_LOOP_001", detail: `Equivalent intent seen ${env.now - i}s ago; cooldown is ${id}s.` };
    return { status: "pass", detail: "No repeat within the cooldown windows." };
  });

  run("asset", "Asset safety (simulated balance changes, sell leg, tax, approvals)", () => assetCheck(policy!, intent, env, selector));

  run("recovery", "Recoverable on Upoch (checkpoint, guardian)", () => recoveryCheck(policy!, env));

  run("loss", "Loss limit (account value against the window's peak)", () => lossCheck(policy!, intent, env, selector, value));

  run("human", "Human approval threshold", () => {
    const t = BigInt(policy!.human_approval.usd_threshold_micros);
    if (usd >= t) return { status: "review", code: "PS_HUMAN_001", detail: `${formatUsd(usd)} meets the ${formatUsd(t)} approval threshold.` };
    return { status: "pass", detail: `${formatUsd(usd)} is below the ${formatUsd(t)} approval threshold.` };
  });

  for (const c of LIVE_CHECKS)
    checks.push({ ...c, status: "skipped", detail: "Requires a live protected account. The simulator never signs or broadcasts." });

  // Request IDs are consumed once the request is well-formed, whatever the decision.
  const schemaOk = checks.find((c) => c.id === "schema")?.status === "pass";
  const seen = schemaOk && !state.seen_request_ids.includes(intent.request_id)
    ? [...state.seen_request_ids, intent.request_id]
    : state.seen_request_ids;

  const f = failed as { code: ReasonCode; message: string } | null;
  const rv = review as { code: ReasonCode; message: string } | null;

  if (f) {
    return {
      request_id: intent.request_id,
      decision: "DENY",
      reason_code: f.code,
      policy_id: policy?.policy_id ?? null,
      policy_version: policy?.version ?? null,
      authorization_id: null,
      transaction_hash: null,
      retryable: RETRYABLE[f.code],
      message: f.message,
      checks,
      next_state: { ...state, reservations, seen_request_ids: seen },
    };
  }

  const p = policy!;
  const pending = rv !== null;
  const reservation: Reservation = {
    reservation_id: "ps_res_" + fingerprint(`${intent.request_id}|${p.version}`).slice(2),
    request_id: intent.request_id,
    agent_id: intent.agent_id,
    policy_version: p.version,
    amount_usd_micros: usd.toString(),
    created_at: env.now,
    expires_at: env.now + RESERVATION_TTL_SECONDS,
    state: pending ? "pending_approval" : "reserved",
  };

  return {
    request_id: intent.request_id,
    decision: pending ? "REQUIRES_HUMAN_SIGNATURE" : "ALLOW",
    reason_code: pending ? rv.code : null,
    policy_id: p.policy_id,
    policy_version: p.version,
    authorization_id: pending ? null : "ps_auth_" + fingerprint(`${intent.request_id}|${p.policy_id}|${p.version}`).slice(2),
    transaction_hash: null,
    retryable: false,
    message: pending
      ? `${rv.message} Nothing is signed until an approver signs this exact operation.`
      : "Authorized. Budget reserved; signing and submission happen only on the protected path.",
    checks,
    next_state: {
      reservations: [...reservations, reservation],
      seen_request_ids: seen,
      calldata_seen: { ...state.calldata_seen, [calldataKey]: env.now },
      intent_seen: { ...state.intent_seen, [intentKey]: env.now },
    },
  };
}

// ---------------------------------------------------------------- asset safety (schema 1.1)

const UNLIMITED = 2n ** 128n;

/** Basis points as a percentage with two decimals: 2000 -> "20.00%". */
export function formatBps(bps: number): string {
  return `${Math.floor(bps / 100)}.${String(bps % 100).padStart(2, "0")}%`;
}

const bad = (why: string): never => {
  throw new Error(`asset simulation input: ${why}`);
};
const str = (v: unknown, what: string): string => (typeof v === "string" ? v : bad(`${what} must be a string`));
const amountOf = (v: unknown, what: string): bigint => {
  const s = str(v, what);
  return UINT.test(s) ? BigInt(s) : bad(`${what} must be a decimal integer`);
};
const intOf = (v: unknown, what: string): number =>
  typeof v === "number" && Number.isInteger(v) ? v : bad(`${what} must be an integer`);
const listOf = (v: unknown, what: string): unknown[] => (Array.isArray(v) ? v : bad(`${what} must be an array`));
const recordOf = (v: unknown, what: string): Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : bad(`${what} must be an object`);
const boolOf = (v: unknown, what: string): boolean => (typeof v === "boolean" ? v : bad(`${what} must be a boolean`));

/** token (lowercase) -> amount, summed, in first-seen order. */
function amounts(v: unknown, what: string): Map<string, bigint> {
  const m = new Map<string, bigint>();
  for (const x of listOf(v, what)) {
    const o = recordOf(x, what);
    const t = str(o.token, `${what}.token`).toLowerCase();
    m.set(t, (m.get(t) ?? 0n) + amountOf(o.amount, `${what}.amount`));
  }
  return m;
}

type Outcome = { status: "pass" | "fail" | "review"; detail: string; code?: ReasonCode };

/**
 * Proven on Zolva (schema 1.4): whether the policy's unlocked limits apply. Only with the section on,
 * a link verified from both sides, Zolva's replay check "match", enough verified hours, a fresh read,
 * and an unlock that has already waited out the loosening delay. Anything else: the policy's own
 * (smaller) limits. Malformed input is an engine error, so the dual evaluator fails closed.
 */
export function provenUnlocked(policy: Policy, env: Environment): boolean {
  const rules = policy.proven_record;
  if (!rules || rules.enabled !== true) return false;
  const raw = env.proven_record;
  if (raw === undefined || raw === null) return false;
  const r = recordOf(raw, "proven_record");
  const observed = intOf(r.observed_at, "proven_record.observed_at");
  const linked = boolOf(r.link_verified, "proven_record.link_verified");
  const status = str(r.replay_status, "proven_record.replay_status");
  const hours = intOf(r.hours_verified, "proven_record.hours_verified");
  const at = r.unlocked_at === null ? null : intOf(r.unlocked_at, "proven_record.unlocked_at");
  if (!linked || status !== "match" || hours < rules.min_verified_hours) return false;
  if (observed > env.now || env.now - observed > rules.max_record_age_seconds) return false;
  return at !== null && at <= env.now;
}

/**
 * Asset safety. The simulation is an input (made before evaluation against current chain state);
 * this function only applies the policy's rules to it, so the result is deterministic.
 * Order: availability and freshness, revert, approvals, sell leg (honeypot), tax, declared intent.
 */
function assetCheck(policy: Policy, intent: Intent, env: Environment, selector: string | null): Outcome {
  const rules = policy.asset_safety;
  if (!rules || !rules.enabled) return { status: "pass", detail: "Asset safety is off for this policy." };
  if (!selector) return { status: "pass", detail: "Native transfer: no contract call to simulate." };

  const unavailable = (why: string): Outcome =>
    rules.on_simulation_unavailable === "review"
      ? { status: "review", code: "PS_SIM_001", detail: `${why} The policy holds this for a human instead of allowing it.` }
      : { status: "fail", code: "PS_SIM_001", detail: `${why} Without a simulation the request fails closed.` };

  const raw = env.asset_simulation;
  if (raw === undefined || raw === null) return unavailable("Simulation unavailable.");
  const sim = recordOf(raw, "asset_simulation");
  const block = intOf(sim.block_number, "block_number");
  const age = env.now - intOf(sim.observed_at, "observed_at");
  if (age > rules.max_simulation_age_seconds)
    return unavailable(`Simulation is ${age}s old; maximum is ${rules.max_simulation_age_seconds}s.`);
  if (boolOf(sim.reverted, "reverted"))
    return { status: "fail", code: "PS_SIM_001", detail: `The transaction reverts in simulation at block ${block}.` };

  const declared = intent.asset_intent === undefined ? null : recordOf(intent.asset_intent, "asset_intent");
  const spend = amounts(declared ? declared.spend : [], "asset_intent.spend");
  const receive = amounts(declared ? declared.receive : [], "asset_intent.receive");
  const outflows = amounts(sim.outflows, "outflows");
  const inflows = amounts(sim.inflows, "inflows");
  const approvals = listOf(sim.approvals, "approvals").map((x) => {
    const o = recordOf(x, "approvals");
    return {
      token: str(o.token, "approvals.token").toLowerCase(),
      spender: str(o.spender, "approvals.spender").toLowerCase(),
      amount: amountOf(o.amount, "approvals.amount"),
    };
  });
  const sellReverted = sim.sell === null ? null : boolOf(recordOf(sim.sell, "sell").reverted, "sell.reverted");
  const tax = sim.tax_bps === null ? null : intOf(sim.tax_bps, "tax_bps");
  const loss = sim.round_trip_loss_bps === null ? null : intOf(sim.round_trip_loss_bps, "round_trip_loss_bps");

  if (rules.block_unlimited_approvals) {
    const deny = policy.contracts.denylist.map((a) => a.toLowerCase());
    const trusted = (a: string) => !deny.includes(a) && policy.contracts.allowlist.some((e) => e.address.toLowerCase() === a);
    for (const ap of approvals) {
      if (ap.amount === 0n || trusted(ap.spender)) continue;
      const allowed = spend.get(ap.token);
      // An exact declared amount is fine; an unlimited one never is, declared or not.
      if (allowed !== undefined && ap.amount === allowed && ap.amount < UNLIMITED) continue;
      const what = ap.amount >= UNLIMITED ? "an unlimited amount" : ap.amount.toString();
      const of = allowed === undefined ? "" : ` of ${allowed}`;
      return {
        status: "fail",
        code: "PS_APPROVAL_001",
        detail: `Approves ${what} of ${ap.token} to ${ap.spender}, which is not an allowlisted contract, and the amount is not the declared spend${of}.`,
      };
    }
  }

  const received = [...inflows.keys()].filter((t) => t !== NATIVE_TOKEN);
  if (received.length > 0 && rules.require_sell_simulation) {
    if (sellReverted === null) return unavailable(`No sell leg could be simulated for ${received[0]}.`);
    if (sellReverted)
      return { status: "fail", code: "PS_ASSET_001", detail: `Selling ${received[0]} back reverts in simulation at block ${block}: likely a honeypot.` };
  }
  if (tax !== null && tax > rules.max_transfer_tax_bps)
    return { status: "fail", code: "PS_ASSET_002", detail: `Transfer tax ${formatBps(tax)} exceeds the policy maximum of ${formatBps(rules.max_transfer_tax_bps)}.` };

  for (const [token, out] of outflows) {
    const allowed = spend.get(token);
    if (allowed === undefined)
      return { status: "fail", code: "PS_ASSET_003", detail: `${out} of ${token} leaves the account, but the request declares no spend of it.` };
    if (out > allowed)
      return { status: "fail", code: "PS_ASSET_003", detail: `${out} of ${token} leaves the account, more than the declared ${allowed}.` };
  }
  for (const [token, quoted] of receive) {
    const got = inflows.get(token) ?? 0n;
    const min = (quoted * BigInt(10000 - rules.max_slippage_bps)) / 10000n;
    if (got < min)
      return {
        status: "fail",
        code: "PS_ASSET_003",
        detail: `Receives ${got} of ${token}, below the quoted ${quoted} less ${formatBps(rules.max_slippage_bps)} slippage.`,
      };
  }

  const parts = [
    `Simulated at block ${block} (${age}s old)`,
    `tax ${tax === null ? "n/a" : formatBps(tax)}`,
    `round-trip loss ${loss === null ? "n/a" : formatBps(loss)}`,
    `approvals ${approvals.length}`,
    `${outflows.size} token(s) out, ${inflows.size} in`,
  ];
  if (received.length > 0) parts.push(sellReverted === false ? "sell leg ok" : "sell leg not required");
  return { status: "pass", detail: parts.join("; ") + "." };
}

// ---------------------------------------------------------------- Upoch recovery (schema 1.2)

const UPOCH_READ_MAX_AGE = 60;

/**
 * The agent must be recoverable on Upoch. The workflow is read from the Upoch ledger before evaluation
 * (an input, like the simulation); this applies the policy's rules to it. Order: availability,
 * workflow set, linked, active, has a checkpoint, guardian, checkpoint age.
 */
function recoveryCheck(policy: Policy, env: Environment): Outcome {
  const rules = policy.upoch_recovery;
  if (!rules || !rules.require_upoch_recoverable) return { status: "pass", detail: "Upoch recovery is not required by this policy." };
  const unavailable = (why: string): Outcome =>
    rules.on_unavailable === "review"
      ? { status: "review", code: "PS_RECOVERY_003", detail: `${why} The policy holds this for a human instead of allowing it.` }
      : { status: "fail", code: "PS_RECOVERY_003", detail: `${why} Without Upoch data the request fails closed.` };
  const raw = env.upoch;
  if (raw === undefined || raw === null) return unavailable("Upoch data unavailable.");
  const u = recordOf(raw, "upoch");
  const wf = str(u.workflow_id, "workflow_id");
  const observed = intOf(u.observed_at, "observed_at");
  const linked = boolOf(u.linked, "linked");
  const active = boolOf(u.active, "active");
  const count = intOf(u.checkpoint_count, "checkpoint_count");
  const last = u.last_checkpoint_at === null ? null : intOf(u.last_checkpoint_at, "last_checkpoint_at");
  const guardians = intOf(u.guardians, "guardians");
  const readAge = env.now - observed;
  if (readAge > UPOCH_READ_MAX_AGE) return unavailable(`Upoch data is ${readAge}s old; maximum is ${UPOCH_READ_MAX_AGE}s.`);
  if (wf === "") return { status: "fail", code: "PS_RECOVERY_001", detail: "No Upoch workflow is set for this agent." };
  if (!linked)
    return { status: "fail", code: "PS_RECOVERY_001", detail: `Upoch workflow ${wf} is not linked to this account: neither its owner nor a guardian is an owner of the account.` };
  if (!active) return { status: "fail", code: "PS_RECOVERY_001", detail: `Upoch workflow ${wf} is paused.` };
  if (count === 0 || last === null) return { status: "fail", code: "PS_RECOVERY_001", detail: `Upoch workflow ${wf} has no checkpoint.` };
  if (rules.require_guardian && guardians === 0) return { status: "fail", code: "PS_RECOVERY_001", detail: `Upoch workflow ${wf} has no guardian.` };
  const age = env.now - last;
  if (age > rules.max_checkpoint_age_seconds)
    return { status: "fail", code: "PS_RECOVERY_002", detail: `The last Upoch checkpoint is ${age}s old; maximum is ${rules.max_checkpoint_age_seconds}s.` };
  return { status: "pass", detail: `Upoch workflow ${wf}: ${count} checkpoint(s), last ${age}s ago, ${guardians} guardian(s).` };
}

// ---------------------------------------------------------------- loss limit (schema 1.3)

export const LOSS_SNAPSHOT_MAX_AGE = 60;
const TRANSFER_SELECTOR = "0xa9059cbb";
const LOSS_CODES = ["PS_LOSS_001", "PS_LOSS_002"] as const;

/** USD micros for `amount` base units at `price` micros per whole token; up rounds against the account. */
export function tokenUsdMicros(amount: bigint, price: bigint, decimals: number, up: boolean): bigint {
  const scale = 10n ** BigInt(decimals);
  const n = amount * price;
  return up ? (n + scale - 1n) / scale : n / scale;
}

/** Drawdown from `peak` to `value`, in whole basis points (rounded down). */
export function drawdownBps(peak: bigint, value: bigint): bigint {
  const loss = peak > value ? peak - value : 0n;
  return peak === 0n ? 0n : (loss * 10000n) / peak;
}

/**
 * The breach a loss of (peak - value) means under the policy's limits, USD first: "PS_LOSS_002",
 * "PS_LOSS_001" or null. Shared by the evaluator and the server's snapshots (the latch).
 */
export function lossBreach(rules: { max_drawdown_bps: number; max_loss_usd_micros: string }, peak: bigint, value: bigint): "PS_LOSS_001" | "PS_LOSS_002" | null {
  const loss = peak > value ? peak - value : 0n;
  const usdMax = BigInt(rules.max_loss_usd_micros);
  if (usdMax > 0n && loss >= usdMax) return "PS_LOSS_002";
  if (rules.max_drawdown_bps > 0 && drawdownBps(peak, value) >= BigInt(rules.max_drawdown_bps)) return "PS_LOSS_001";
  return null;
}

/** The recipient of an ERC-20 `transfer(address,uint256)` call, lowercase, or null. */
function transferRecipient(data: string): string | null {
  if (data.length < 138 || data.slice(0, 10).toLowerCase() !== TRANSFER_SELECTOR) return null;
  if (!/^0{24}$/.test(data.slice(10, 34))) return null;
  return "0x" + data.slice(34, 74).toLowerCase();
}

/**
 * Loss limit. The account's value (Chainlink prices, deposits and withdrawals taken out) and the window's
 * peak are an input made before evaluation; this applies the policy's rules to them and to this
 * operation's simulated balance changes, so the result is deterministic. Order: withdrawal to an exit
 * address, snapshot availability and age, this operation's flows, paused (latched or already over the
 * limit: only risk-reducing actions), then whether this operation would cross the limit.
 */
function lossCheck(policy: Policy, intent: Intent, env: Environment, selector: string | null, value: bigint): Outcome {
  const rules = policy.loss_limit;
  if (!rules || !rules.enabled) return { status: "pass", detail: "Loss limit is off for this policy." };
  const exits = rules.exit_addresses.map((a) => a.toLowerCase());
  const stables = rules.stablecoins.map((a) => a.toLowerCase());
  const unavailable = (why: string): Outcome =>
    rules.on_valuation_unavailable === "review"
      ? { status: "review", code: "PS_LOSS_003", detail: `${why} The policy holds this for a human instead of allowing it.` }
      : { status: "fail", code: "PS_LOSS_003", detail: `${why} Without a reliable account value, nothing that adds risk is allowed.` };
  const breach = (code: ReasonCode, why: string): Outcome =>
    rules.on_breach === "review"
      ? { status: "review", code, detail: `${why} The policy holds this for a human.` }
      : { status: "fail", code, detail: `${why} Only risk-reducing actions are allowed until the owner resets the limit.` };
  const to = intent.to.toLowerCase();
  const rawSim = env.asset_simulation;

  // A withdrawal to the owner or recovery wallet is never a loss, and needs no price.
  if (selector === null && exits.includes(to)) return { status: "pass", detail: `Transfer to exit address ${to}: a withdrawal, not a loss.` };
  const recipient = selector === TRANSFER_SELECTOR && value === 0n ? transferRecipient(intent.data) : null;
  if (recipient !== null && exits.includes(recipient)) {
    let pure = true;
    if (rawSim !== undefined && rawSim !== null) {
      const sim = recordOf(rawSim, "asset_simulation");
      const out = amounts(sim.outflows, "outflows");
      const inn = amounts(sim.inflows, "inflows");
      pure = inn.size === 0 && [...out.keys()].every((t) => t === to);
    } else {
      // Without a simulation, only a transfer of one of the policy's stablecoins is taken at its word.
      pure = stables.includes(to);
    }
    if (pure) return { status: "pass", detail: `Token transfer to exit address ${recipient}: a withdrawal, not a loss.` };
  }

  const raw = env.loss_snapshot;
  if (raw === undefined || raw === null) return unavailable("Account value unavailable.");
  const snap = recordOf(raw, "loss_snapshot");
  const age = env.now - intOf(snap.observed_at, "loss_snapshot.observed_at");
  if (age > LOSS_SNAPSHOT_MAX_AGE) return unavailable(`Account value is ${age}s old; maximum is ${LOSS_SNAPSHOT_MAX_AGE}s.`);
  let paused: ReasonCode | null = null;
  if (snap.paused !== null) {
    const p = str(snap.paused, "loss_snapshot.paused");
    paused = (LOSS_CODES as readonly string[]).includes(p) ? (p as ReasonCode) : bad("loss_snapshot.paused must be PS_LOSS_001, PS_LOSS_002 or null");
  }
  const prices = new Map<string, { price: bigint; decimals: number }>();
  for (const x of listOf(snap.prices, "loss_snapshot.prices")) {
    const o = recordOf(x, "loss_snapshot.prices");
    const t = str(o.token, "prices.token").toLowerCase();
    const price = amountOf(o.price_micros, "prices.price_micros");
    const decimals = intOf(o.decimals, "prices.decimals");
    if (decimals < 0 || decimals > 36) bad("prices.decimals must be between 0 and 36");
    if (!prices.has(t)) prices.set(t, { price, decimals });
  }
  const missing = new Set(listOf(snap.unavailable, "loss_snapshot.unavailable").map((t) => str(t, "unavailable").toLowerCase()));
  const valueNow = snap.value_usd_micros === null ? null : amountOf(snap.value_usd_micros, "loss_snapshot.value_usd_micros");
  const peak = snap.baseline_usd_micros === null ? null : amountOf(snap.baseline_usd_micros, "loss_snapshot.baseline_usd_micros");

  // What this operation does to the account's assets.
  let out = new Map<string, bigint>();
  let inn = new Map<string, bigint>();
  let approvals: { spender: string; amount: bigint }[] = [];
  if (selector === null) {
    if (value > 0n) out.set(NATIVE_TOKEN, value);
  } else {
    if (rawSim === undefined || rawSim === null) return unavailable("No simulation of this operation, so its effect on the account's value is unknown.");
    const sim = recordOf(rawSim, "asset_simulation");
    const simAge = env.now - intOf(sim.observed_at, "observed_at");
    if (simAge > LOSS_SNAPSHOT_MAX_AGE) return unavailable(`Simulation is ${simAge}s old; maximum is ${LOSS_SNAPSHOT_MAX_AGE}s.`);
    out = amounts(sim.outflows, "outflows");
    inn = amounts(sim.inflows, "inflows");
    approvals = listOf(sim.approvals, "approvals").map((x) => {
      const o = recordOf(x, "approvals");
      return { spender: str(o.spender, "approvals.spender").toLowerCase(), amount: amountOf(o.amount, "approvals.amount") };
    });
  }
  /** Value of a set of amounts; null when one of them has no reliable price right now. */
  const worth = (m: Map<string, bigint>, up: boolean): bigint | null => {
    let sum = 0n;
    for (const [t, a] of m) {
      if (missing.has(t)) return null;
      const p = prices.get(t);
      if (p) sum += tokenUsdMicros(a, p.price, p.decimals, up);
    }
    return sum;
  };

  if (paused === null && valueNow !== null && peak !== null) paused = lossBreach(rules, peak, valueNow);

  // While paused, every approval must be bounded and to an allowlisted contract (no later drain).
  const deny = policy.contracts.denylist.map((a) => a.toLowerCase());
  const trusted = (a: string) => !deny.includes(a) && policy.contracts.allowlist.some((e) => e.address.toLowerCase() === a);
  const safeApprovals = approvals.every((a) => a.amount < UNLIMITED && trusted(a.spender));
  const approvalBreach = (code: ReasonCode) =>
    breach(code, `The loss limit was reached (${code}) and this operation grants an approval that is not bounded or not to an allowlisted contract.`);

  if (out.size === 0 && inn.size === 0) {
    if (paused === null) return { status: "pass", detail: "No value moves in this operation." };
    if (safeApprovals) return { status: "pass", detail: "No value moves (bounded approvals to allowlisted contracts only): allowed while paused." };
    return approvalBreach(paused);
  }

  if (paused !== null) {
    const reducing = inn.size > 0 && [...inn.keys()].every((t) => stables.includes(t));
    if (!reducing) return breach(paused, `The loss limit was reached (${paused}) and this operation adds risk.`);
    if (!safeApprovals) return approvalBreach(paused);
    const sold = worth(out, true);
    const got = worth(inn, false);
    if (sold === null || got === null) return unavailable("A price needed to check this exit swap is unavailable.");
    const min = (sold * BigInt(10000 - rules.max_exit_slippage_bps)) / 10000n;
    if (got < min)
      return breach(paused, `Exit swap returns ${formatUsd(got)} for ${formatUsd(sold)}, more than the ${formatBps(rules.max_exit_slippage_bps)} exit slippage allowed while paused.`);
    return { status: "pass", detail: `Risk-reducing swap into a stablecoin (${formatUsd(got)} for ${formatUsd(sold)}): allowed while paused.` };
  }

  if (valueNow === null || peak === null) return unavailable("A price for an asset the account holds is unavailable.");
  const sold = worth(out, true);
  const got = worth(inn, false);
  if (sold === null || got === null) return unavailable("A price for an asset this operation moves is unavailable.");
  const after = valueNow + got > sold ? valueNow + got - sold : 0n;
  const loss = peak > after ? peak - after : 0n;
  const dd = drawdownBps(peak, after);
  const code = lossBreach(rules, peak, after);
  if (code === "PS_LOSS_002")
    return breach(code, `This operation would bring the loss to ${formatUsd(loss)}, at or above the ${formatUsd(BigInt(rules.max_loss_usd_micros))} limit (peak ${formatUsd(peak)}, value after ${formatUsd(after)}).`);
  if (code === "PS_LOSS_001")
    return breach(code, `This operation would bring the drawdown to ${formatBps(Number(dd))}, at or above the ${formatBps(rules.max_drawdown_bps)} limit (peak ${formatUsd(peak)}, value after ${formatUsd(after)}).`);
  return { status: "pass", detail: `Loss after this operation ${formatUsd(loss)}, drawdown ${formatBps(Number(dd))} (peak ${formatUsd(peak)}, value after ${formatUsd(after)}).` };
}

// ---------------------------------------------------------------- account stop (ERC-8511 registry)

export const REGISTRY_STOP_MAX_AGE = 60;

/**
 * A stop the account engaged itself on the registry stops Palisec's decisions too, until the account lifts it.
 * Nothing that adds risk is co-signed; only a withdrawal (ETH or an ERC-20 transfer) to one of the loss limit's
 * exit addresses stays allowed. The registry read is an input; unreadable or stale fails closed.
 */
function accountStopCheck(policy: Policy, intent: Intent, env: Environment, selector: string | null, value: bigint): Outcome {
  const raw = env.registry_stop;
  if (raw === undefined) return { status: "pass", detail: "The account does not publish to a policy registry." };
  if (raw === null) return { status: "fail", code: "PS_STATE_001", detail: "The account's stop on the policy registry could not be read, so the request fails closed." };
  const r = recordOf(raw, "registry_stop");
  const held = boolOf(r.held_by_account, "registry_stop.held_by_account");
  const age = env.now - intOf(r.observed_at, "registry_stop.observed_at");
  if (age > REGISTRY_STOP_MAX_AGE)
    return { status: "fail", code: "PS_STATE_001", detail: `The registry read is ${age}s old; maximum is ${REGISTRY_STOP_MAX_AGE}s.` };
  if (!held) return { status: "pass", detail: "No stop engaged by the account on the registry." };
  const exits = (policy.loss_limit?.exit_addresses ?? []).map((a) => a.toLowerCase());
  const to = intent.to.toLowerCase();
  const recipient = selector === null ? to : selector === TRANSFER_SELECTOR && value === 0n ? transferRecipient(intent.data) : null;
  if (recipient !== null && exits.includes(recipient))
    return { status: "pass", detail: `The account engaged its stop; a withdrawal to exit address ${recipient} stays allowed.` };
  return { status: "fail", code: "PS_PAUSED_001", detail: "The account engaged its emergency stop on the registry. Nothing that adds risk is co-signed until the account lifts it." };
}

// ---------------------------------------------------------------- token spend (schema 1.5)

export const SPEND_INPUT_MAX_AGE = 60;
const APPROVE_SELECTOR = "0x095ea7b3";

/**
 * Token spend limits. With the rule on, the exposure the limits count is the ETH value and fee (already
 * priced) plus, in USD, every token the simulation shows leaving the account, any ETH it sends beyond
 * the value, and every allowance still open after the operation. Prices are an input read before
 * evaluation (checked Chainlink prices); a spent token without one is never counted as $0. A native
 * transfer is simulated too: the target may be a contract that pulls tokens through an older allowance. Order:
 * simulation availability and age, revert, output back to the account, unbounded allowances, prices,
 * then the per-transaction USD cap. `base` is the exposure so far (value + fee); `add` is what this adds.
 */
function spendCheck(policy: Policy, intent: Intent, env: Environment, selector: string | null, value: bigint, base: bigint): { outcome: Outcome; add: bigint } {
  const rules = policy.token_spend;
  if (!rules || !rules.enabled) return { outcome: { status: "pass", detail: "Token spend is not counted by this policy: the limits count ETH value and fee only." }, add: 0n };
  const cap = BigInt(rules.max_transaction_usd_micros);
  const capped = (total: bigint, what: string): Outcome =>
    total > cap
      ? { status: "fail", code: "PS_BUDGET_001", detail: `Exposure ${formatUsd(total)} (${what}) exceeds the per-transaction limit of ${formatUsd(cap)}.` }
      : { status: "pass", detail: `Exposure ${formatUsd(total)} (${what}) ≤ ${formatUsd(cap)}.` };
  const unknown = (why: string): { outcome: Outcome; add: bigint } => ({
    outcome: { status: "fail", code: "PS_SIM_002", detail: `${why} The tokens this transaction spends are unknown, so it fails closed.` },
    add: 0n,
  });
  const raw = env.asset_simulation;
  if (raw === undefined || raw === null) return unknown("Simulation unavailable.");
  const sim = recordOf(raw, "asset_simulation");
  const block = intOf(sim.block_number, "block_number");
  const age = env.now - intOf(sim.observed_at, "observed_at");
  if (age > SPEND_INPUT_MAX_AGE) return unknown(`Simulation is ${age}s old; maximum is ${SPEND_INPUT_MAX_AGE}s.`);
  if (boolOf(sim.reverted, "reverted"))
    return { outcome: { status: "fail", code: "PS_SIM_001", detail: `The transaction reverts in simulation at block ${block}.` }, add: 0n };
  const outflows = amounts(sim.outflows, "outflows");
  const inflows = amounts(sim.inflows, "inflows");
  const allowanceList = (v: unknown, what: string) =>
    listOf(v, what).map((x) => {
      const o = recordOf(x, what);
      return { token: str(o.token, `${what}.token`).toLowerCase(), spender: str(o.spender, `${what}.spender`).toLowerCase(), amount: amountOf(o.amount, `${what}.amount`) };
    });
  const approvals = allowanceList(sim.approvals, "approvals");
  // Allowance left open per (token, spender): read at the end of the operation when the simulation has
  // it, otherwise the last amount approved. Either way it could be spent later without another check.
  const open = new Map<string, { token: string; spender: string; amount: bigint }>();
  for (const a of sim.allowances_after === undefined ? approvals : allowanceList(sim.allowances_after, "allowances_after")) open.set(`${a.token}|${a.spender}`, a);

  const spent = [...outflows].filter(([t]) => t !== NATIVE_TOKEN);
  if (rules.require_output_to_account && selector !== TRANSFER_SELECTOR && selector !== APPROVE_SELECTOR && spent.length > 0 && inflows.size === 0)
    return {
      outcome: { status: "fail", code: "PS_ASSET_003", detail: `${spent[0]![1]} of ${spent[0]![0]} leaves the account and nothing comes back into it: a swap's output must return to the account.` },
      add: 0n,
    };
  for (const a of open.values())
    if (a.amount >= UNLIMITED)
      return {
        outcome: { status: "fail", code: "PS_BUDGET_001", detail: `Leaves an unlimited allowance of ${a.token} to ${a.spender}, which no spending limit can cover.` },
        add: 0n,
      };

  // What is counted, per token: what leaves now plus what stays approved.
  const counted = new Map<string, bigint>();
  for (const [t, a] of spent) counted.set(t, a);
  for (const a of open.values()) if (a.amount > 0n) counted.set(a.token, (counted.get(a.token) ?? 0n) + a.amount);
  const nativeOut = outflows.get(NATIVE_TOKEN) ?? 0n;
  const extraWei = nativeOut > value ? nativeOut - value : 0n;
  let add = extraWei > 0n ? weiToUsdMicros(extraWei, BigInt(env.eth_usd!.price_micros)) : 0n;
  if (counted.size === 0) return { outcome: capped(base + add, "value + fee; no tokens leave the account"), add };

  const noPrice = (why: string): { outcome: Outcome; add: bigint } => {
    if (base + add > cap) return { outcome: capped(base + add, "value + fee + priced tokens"), add };
    return rules.on_price_unavailable === "review"
      ? { outcome: { status: "review", code: "PS_PRICE_001", detail: `${why} The policy holds this for a human instead of allowing it.` }, add }
      : { outcome: { status: "fail", code: "PS_PRICE_001", detail: `${why} A spent token is never counted as $0, so the request fails closed.` }, add };
  };
  const rawPrices = env.spend_prices;
  if (rawPrices === undefined || rawPrices === null) return noPrice("Token prices unavailable.");
  const sp = recordOf(rawPrices, "spend_prices");
  const priceAge = env.now - intOf(sp.observed_at, "spend_prices.observed_at");
  if (priceAge > SPEND_INPUT_MAX_AGE) return noPrice(`Token prices are ${priceAge}s old; maximum is ${SPEND_INPUT_MAX_AGE}s.`);
  const prices = new Map<string, { price: bigint; decimals: number }>();
  for (const x of listOf(sp.prices, "spend_prices.prices")) {
    const o = recordOf(x, "spend_prices.prices");
    const t = str(o.token, "prices.token").toLowerCase();
    const price = amountOf(o.price_micros, "prices.price_micros");
    const decimals = intOf(o.decimals, "prices.decimals");
    if (decimals < 0 || decimals > 36) bad("prices.decimals must be between 0 and 36");
    if (!prices.has(t)) prices.set(t, { price, decimals });
  }
  const missing = new Set(listOf(sp.unavailable, "spend_prices.unavailable").map((t) => str(t, "unavailable").toLowerCase()));
  let tokens = 0n;
  let unpriced: string | null = null;
  for (const [t, a] of counted) {
    const p = prices.get(t);
    if (missing.has(t) || !p) {
      unpriced ??= t;
      continue;
    }
    tokens += tokenUsdMicros(a, p.price, p.decimals, true);
  }
  add += tokens;
  if (unpriced !== null) return noPrice(`No reliable price for ${unpriced}, which this transaction spends or leaves approved.`);
  const allowances = [...open.values()].filter((a) => a.amount > 0n).length;
  return { outcome: capped(base + add, `value + fee + ${formatUsd(tokens)} in ${counted.size} token(s)${allowances ? `, ${allowances} open allowance(s)` : ""}`), add };
}

export function formatUsd(micros: bigint): string {
  const neg = micros < 0n;
  const abs = neg ? -micros : micros;
  const dollars = abs / 1_000_000n;
  const cents = (abs % 1_000_000n) / 10_000n;
  return `${neg ? "-" : ""}$${dollars.toLocaleString("en-US")}.${cents.toString().padStart(2, "0")}`;
}

export function describe(code: ReasonCode): string {
  return REASON_CODES[code];
}
