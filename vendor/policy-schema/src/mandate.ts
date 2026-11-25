import type { Address, Hex, Policy } from "./types";
import { validatePolicy } from "./validate";

/**
 * Holder mandates: the pure parts (no I/O), shared by the server, the SDK and the recount
 * script. A mandate is an envelope (owner-set hard limits) plus typed proposals that token holders vote
 * on. A passed proposal compiles into an ordinary policy version, so the engines decide as before.
 */

/** Owner-set hard limits: votes can never move the policy outside these. */
export interface MandateEnvelope {
  max_transaction_value_wei: string;
  max_hourly_budget_usd_micros: string;
  /** Holders cannot lower the human-approval threshold below this. */
  min_approval_threshold_usd_micros: string;
  /** The only contracts (and functions) a vote may ever allowlist. */
  allowed_contracts: { address: Address; selectors: Hex[] }[];
  /** Token spend (schema 1.5): the highest per-transaction USD limit a vote may set. Absent: holders cannot set it. */
  max_transaction_usd_micros?: string;
}

export type MandateChange =
  | { kind: "set_hourly_budget"; usd_micros: string }
  | { kind: "set_max_transaction_value"; wei: string }
  | { kind: "set_max_transaction_usd"; usd_micros: string }
  | { kind: "set_approval_threshold"; usd_micros: string }
  | { kind: "allow_contract"; address: Address; selectors: Hex[] }
  | { kind: "remove_contract"; address: Address }
  | { kind: "add_deny"; address: Address }
  | { kind: "remove_deny"; address: Address };

export interface MandateRules {
  voting_period_seconds: number;
  /** Token units (wei) of votes cast needed for a valid result. */
  quorum: string;
  /** For must exceed this share of for + against, in basis points (5000 = more than 50%). */
  pass_bps: number;
  /** Token units a proposer must hold at the snapshot block. */
  proposer_min: string;
}

const UINT = /^(0|[1-9][0-9]{0,77})$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const SEL = /^0x[0-9a-fA-F]{8}$/;
const lc = (a: string) => a.toLowerCase();

export function validateEnvelope(e: unknown): string[] {
  const errs: string[] = [];
  const o = e as Record<string, unknown>;
  if (!o || typeof o !== "object") return ["envelope must be an object"];
  for (const k of Object.keys(o))
    if (!["max_transaction_value_wei", "max_hourly_budget_usd_micros", "min_approval_threshold_usd_micros", "allowed_contracts", "max_transaction_usd_micros"].includes(k)) errs.push(`unknown field ${k}`);
  if (o.max_transaction_usd_micros !== undefined && (typeof o.max_transaction_usd_micros !== "string" || !UINT.test(o.max_transaction_usd_micros)))
    errs.push("max_transaction_usd_micros must be a non-negative integer string");
  for (const k of ["max_transaction_value_wei", "max_hourly_budget_usd_micros", "min_approval_threshold_usd_micros"])
    if (typeof o[k] !== "string" || !UINT.test(o[k] as string)) errs.push(`${k} must be a non-negative integer string`);
  if (!Array.isArray(o.allowed_contracts) || o.allowed_contracts.length > 64) errs.push("allowed_contracts must be an array of at most 64");
  else
    (o.allowed_contracts as { address: unknown; selectors: unknown }[]).forEach((c, i) => {
      if (!c || typeof c.address !== "string" || !ADDR.test(c.address)) errs.push(`allowed_contracts[${i}].address must be an address`);
      if (!Array.isArray(c?.selectors) || c.selectors.some((s) => typeof s !== "string" || !SEL.test(s))) errs.push(`allowed_contracts[${i}].selectors must be 4-byte selectors`);
    });
  return errs;
}

export function validateChange(c: unknown): string[] {
  const o = c as Record<string, unknown>;
  if (!o || typeof o !== "object" || typeof o.kind !== "string") return ["change must be an object with a kind"];
  const only = (keys: string[]) => Object.keys(o).filter((k) => k !== "kind" && !keys.includes(k)).map((k) => `unknown field ${k}`);
  switch (o.kind) {
    case "set_hourly_budget":
    case "set_approval_threshold":
    case "set_max_transaction_usd":
      return [...only(["usd_micros"]), ...(typeof o.usd_micros === "string" && UINT.test(o.usd_micros) ? [] : ["usd_micros must be a non-negative integer string"])];
    case "set_max_transaction_value":
      return [...only(["wei"]), ...(typeof o.wei === "string" && UINT.test(o.wei) ? [] : ["wei must be a non-negative integer string"])];
    case "allow_contract":
      return [
        ...only(["address", "selectors"]),
        ...(typeof o.address === "string" && ADDR.test(o.address) ? [] : ["address must be an address"]),
        ...(Array.isArray(o.selectors) && o.selectors.length <= 64 && o.selectors.every((s) => typeof s === "string" && SEL.test(s)) ? [] : ["selectors must be 4-byte selectors"]),
      ];
    case "remove_contract":
    case "add_deny":
    case "remove_deny":
      return [...only(["address"]), ...(typeof o.address === "string" && ADDR.test(o.address) ? [] : ["address must be an address"])];
    default:
      return [`unknown change kind ${String(o.kind)}`];
  }
}

/** Why a change falls outside the envelope, or null when it is inside. */
export function outsideEnvelope(change: MandateChange, env: MandateEnvelope): string | null {
  switch (change.kind) {
    case "set_hourly_budget":
      return BigInt(change.usd_micros) > BigInt(env.max_hourly_budget_usd_micros) ? "hourly budget above the envelope maximum" : null;
    case "set_max_transaction_value":
      return BigInt(change.wei) > BigInt(env.max_transaction_value_wei) ? "per-transaction value above the envelope maximum" : null;
    case "set_approval_threshold":
      return BigInt(change.usd_micros) < BigInt(env.min_approval_threshold_usd_micros) ? "approval threshold below the envelope minimum" : null;
    case "set_max_transaction_usd":
      if (env.max_transaction_usd_micros === undefined) return "the envelope sets no per-transaction USD maximum";
      return BigInt(change.usd_micros) > BigInt(env.max_transaction_usd_micros) ? "per-transaction USD limit above the envelope maximum" : null;
    case "allow_contract": {
      const e = env.allowed_contracts.find((a) => lc(a.address) === lc(change.address));
      if (!e) return "contract not in the envelope's allowed list";
      const ok = new Set(e.selectors.map(lc));
      return change.selectors.every((s) => ok.has(lc(s))) ? null : "function not in the envelope's allowed list";
    }
    case "remove_deny":
      // The owner's deny rules are part of the hard limits: holders can add deny rules, never remove one.
      return "removing a deny rule is not allowed by a vote";
    default:
      return null; // removing an allowance or adding a deny rule only tightens
  }
}

/** The whole policy must sit inside the envelope (checked again at compile time). */
export function policyInsideEnvelope(p: Policy, env: MandateEnvelope): string | null {
  if (BigInt(p.limits.max_transaction_value_wei) > BigInt(env.max_transaction_value_wei)) return "per-transaction value above the envelope maximum";
  if (BigInt(p.limits.hourly_budget_usd_micros) > BigInt(env.max_hourly_budget_usd_micros)) return "hourly budget above the envelope maximum";
  if (BigInt(p.human_approval.usd_threshold_micros) < BigInt(env.min_approval_threshold_usd_micros)) return "approval threshold below the envelope minimum";
  if (p.token_spend?.enabled && env.max_transaction_usd_micros !== undefined && BigInt(p.token_spend.max_transaction_usd_micros) > BigInt(env.max_transaction_usd_micros))
    return "per-transaction USD limit above the envelope maximum";
  for (const a of p.contracts.allowlist) {
    const e = env.allowed_contracts.find((x) => lc(x.address) === lc(a.address));
    if (!e) return `contract ${a.address} is not in the envelope`;
    const ok = new Set(e.selectors.map(lc));
    if (!a.selectors.every((s) => ok.has(lc(s)))) return `a function on ${a.address} is not in the envelope`;
  }
  return null;
}

/** The next policy document for a passed proposal (version and status are set by activation). */
export function compileChange(current: Policy, change: MandateChange): Policy {
  const p = JSON.parse(JSON.stringify(current)) as Policy;
  switch (change.kind) {
    case "set_hourly_budget":
      p.limits.hourly_budget_usd_micros = change.usd_micros;
      break;
    case "set_max_transaction_value":
      p.limits.max_transaction_value_wei = change.wei;
      break;
    case "set_approval_threshold":
      p.human_approval.usd_threshold_micros = change.usd_micros;
      break;
    case "set_max_transaction_usd":
      if (p.token_spend) p.token_spend.max_transaction_usd_micros = change.usd_micros;
      break;
    case "allow_contract": {
      const i = p.contracts.allowlist.findIndex((e) => lc(e.address) === lc(change.address));
      const entry = { address: change.address, selectors: [...new Set(change.selectors.map(lc))] as Hex[], require_verified_code: true };
      if (i >= 0) p.contracts.allowlist[i] = { ...p.contracts.allowlist[i]!, selectors: [...new Set([...p.contracts.allowlist[i]!.selectors.map(lc), ...entry.selectors])] as Hex[] };
      else p.contracts.allowlist.push(entry);
      break;
    }
    case "remove_contract":
      p.contracts.allowlist = p.contracts.allowlist.filter((e) => lc(e.address) !== lc(change.address));
      break;
    case "add_deny":
      if (!p.contracts.denylist.some((a) => lc(a) === lc(change.address))) p.contracts.denylist.push(change.address);
      break;
    case "remove_deny":
      p.contracts.denylist = p.contracts.denylist.filter((a) => lc(a) !== lc(change.address));
      break;
  }
  return p;
}

/** Compile and check: schema-valid and inside the envelope, or an error (nothing changes). */
export function compileProposal(current: Policy, change: MandateChange, env: MandateEnvelope): { ok: true; document: Policy } | { ok: false; reason: string } {
  const out = outsideEnvelope(change, env);
  if (out) return { ok: false, reason: out };
  if (change.kind === "set_max_transaction_usd" && current.token_spend?.enabled !== true)
    return { ok: false, reason: "the policy does not count token spend (token_spend is off)" };
  const doc = compileChange(current, change);
  const errs = validatePolicy({ ...doc, status: "active", version: 1 });
  if (errs.length) return { ok: false, reason: `compiled policy is invalid: ${errs[0]!.path} ${errs[0]!.message}` };
  const inside = policyInsideEnvelope(doc, env);
  if (inside) return { ok: false, reason: inside };
  return { ok: true, document: doc };
}

// ---------------------------------------------------------------- votes

export const VOTE_CHOICES = ["for", "against", "abstain"] as const;
export type VoteChoice = (typeof VOTE_CHOICES)[number];

/** EIP-712 typed data a holder signs (gasless). `mandate` is the mandate's slug. */
export function voteTypedData(chainId: number, v: { mandate: string; proposalId: string; choice: VoteChoice; snapshotBlock: bigint | number | string }) {
  return {
    domain: { name: "Palisec Mandates", version: "1", chainId },
    types: {
      Vote: [
        { name: "mandate", type: "string" },
        { name: "proposalId", type: "string" },
        { name: "choice", type: "uint8" },
        { name: "snapshotBlock", type: "uint256" },
      ],
    },
    primaryType: "Vote" as const,
    message: { mandate: v.mandate, proposalId: v.proposalId, choice: VOTE_CHOICES.indexOf(v.choice), snapshotBlock: BigInt(v.snapshotBlock) },
  };
}

/** Proposal creation is signed too, by a holder with at least the proposer minimum. */
export function proposalTypedData(chainId: number, p: { mandate: string; title: string; change: string; nonce: string }) {
  return {
    domain: { name: "Palisec Mandates", version: "1", chainId },
    types: {
      Proposal: [
        { name: "mandate", type: "string" },
        { name: "title", type: "string" },
        { name: "change", type: "string" },
        { name: "nonce", type: "string" },
      ],
    },
    primaryType: "Proposal" as const,
    message: p,
  };
}

export interface TallyInput {
  rules: Pick<MandateRules, "quorum" | "pass_bps">;
  /** One per voter (the latest valid one), with its weight at the snapshot block. */
  votes: { voter: string; choice: VoteChoice; weight: string }[];
}

export interface Tally {
  for: string;
  against: string;
  abstain: string;
  cast: string;
  quorum: string;
  quorum_reached: boolean;
  passed: boolean;
}

/** Deterministic count: quorum on everything cast; passes if for/(for+against) is strictly above pass_bps. */
export function tally(t: TallyInput): Tally {
  let f = 0n, a = 0n, ab = 0n;
  for (const v of t.votes) {
    const w = BigInt(v.weight);
    if (v.choice === "for") f += w;
    else if (v.choice === "against") a += w;
    else ab += w;
  }
  const cast = f + a + ab;
  const quorum = BigInt(t.rules.quorum);
  const reached = cast >= quorum;
  const decided = f + a;
  const passed = reached && decided > 0n && f * 10000n > decided * BigInt(t.rules.pass_bps);
  return { for: f.toString(), against: a.toString(), abstain: ab.toString(), cast: cast.toString(), quorum: quorum.toString(), quorum_reached: reached, passed };
}

/** Balances at a block from Transfer events (from, to, value) in chain order: the snapshot. */
export function replayBalances(transfers: { from: string; to: string; value: bigint }[]): Map<string, bigint> {
  const b = new Map<string, bigint>();
  const zero = "0x0000000000000000000000000000000000000000";
  for (const t of transfers) {
    const from = lc(t.from), to = lc(t.to);
    if (from !== zero) b.set(from, (b.get(from) ?? 0n) - t.value);
    if (to !== zero) b.set(to, (b.get(to) ?? 0n) + t.value);
  }
  for (const [k, v] of b) if (v === 0n) b.delete(k);
  return b;
}
