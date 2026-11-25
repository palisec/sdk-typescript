import type { ReasonCode } from "./codes";

/** Decimal integer encoded as a string, e.g. wei or USD micros. Never a float. */
export type UintString = string;
export type Address = `0x${string}`;
export type Hex = `0x${string}`;

/** The version new policies are written in. 1.0 documents stay valid; 1.1 adds `asset_safety`. */
export const SCHEMA_VERSION = "1.1" as const;
export const SCHEMA_VERSIONS = ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5"] as const;
export type SchemaVersion = (typeof SCHEMA_VERSIONS)[number];

/** Native ETH in balance changes and declared intent (the common 0xEeee… convention), lowercase. */
export const NATIVE_TOKEN = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" as const;

/**
 * Schema 1.1: what the transaction actually does to the account's assets, checked against a
 * simulation on current chain state before PALISEC allows (and co-signs) it.
 */
export interface AssetSafety {
  enabled: boolean;
  /** Highest acceptable transfer tax on a received token (buy or sell leg), basis points. */
  max_transfer_tax_bps: number;
  /** How far below the declared (quoted) amount a received token may come in, basis points. */
  max_slippage_bps: number;
  /** Tokens received must survive a simulated sell leg (sent back to the pool they came from). */
  require_sell_simulation: boolean;
  /** Approvals must be for the declared amount, or to a contract on the allowlist. */
  block_unlimited_approvals: boolean;
  /** No usable simulation: deny (default) or hold for a human. Never allow. */
  on_simulation_unavailable: "deny" | "review";
  /** A simulation older than this counts as unavailable. */
  max_simulation_age_seconds: number;
}

/** Schema 1.2: the agent must be recoverable on Upoch, read from chain before evaluation. */
export interface UpochRecovery {
  require_upoch_recoverable: boolean;
  /** The newest checkpoint may be at most this old. */
  max_checkpoint_age_seconds: number;
  require_guardian: boolean;
  /** Upoch data cannot be read: deny (default) or hold for a human. Never allow. */
  on_unavailable: "deny" | "review";
}

/**
 * Schema 1.3: a loss limit outside the agent. The account's value is measured before each
 * decision (an input, like the simulation); breaching the limit pauses everything that adds risk
 * until the owner resets it (a new version with `reset_epoch` + 1, which is a loosening).
 */
export interface LossLimit {
  enabled: boolean;
  /** Largest drawdown from the window's peak, basis points (500 = 5%). 0 = not used. */
  max_drawdown_bps: number;
  /** Largest loss from the window's peak, USD micros. "0" = not used. At least one limit is set. */
  max_loss_usd_micros: UintString;
  /** Rolling window, seconds (1 h to 7 d). */
  window_seconds: number;
  /** Breach: deny everything that adds risk, or hold it for a human. */
  on_breach: "pause_risk" | "review";
  /** No reliable account value: deny (default) or hold for a human. Never allow. */
  on_valuation_unavailable: "deny" | "review";
  /** What a risk-reducing swap may swap into. */
  stablecoins: Address[];
  /** Owner and recovery wallets: transfers here are withdrawals, not losses, and stay allowed. */
  exit_addresses: Address[];
  /** A risk-reducing swap while paused may lose at most this much of the value it sells. */
  max_exit_slippage_bps: number;
  /** Stock-token prices while markets are closed may be at most this old (read by the valuation). */
  max_closed_market_price_age_seconds: number;
  /** Raised by the owner to reset a breach; the window starts again when it activates. */
  reset_epoch: number;
}

/**
 * Schema 1.4: an agent starts on the policy's limits and unlocks bigger ones once it has a verified
 * track record on Zolva (paper trading). The record is read before evaluation (an input, like the
 * simulation). Anything missing, stale or unclear keeps the policy's own, smaller limits.
 */
export interface ProvenRecord {
  enabled: boolean;
  source: "zolva";
  /** Zolva must have verified at least this many hours of the agent's record by replay. */
  min_verified_hours: number;
  /** The record must have been read at most this long ago. */
  max_record_age_seconds: number;
  /** The limits used once unlocked. Each is at least the policy's own limit. */
  unlocked_limits: {
    max_transaction_value_wei: UintString;
    hourly_budget_usd_micros: UintString;
  };
}

/**
 * Schema 1.5: the spending limits count tokens, not only ETH. With this on, a transaction's exposure is
 * the ETH it sends plus the fee plus, in USD, every token the simulation shows leaving the account and
 * every allowance still open after it. That exposure counts in the per-transaction USD cap below, the
 * hourly budget and the human approval threshold. Spent tokens are priced from Chainlink (the same
 * checked prices the loss limit uses); a token with no reliable price is never counted as $0.
 */
export interface TokenSpend {
  enabled: boolean;
  /** Largest exposure of one transaction (ETH, fee and tokens), USD micros. */
  max_transaction_usd_micros: UintString;
  /** A spent token or open allowance has no reliable price: deny (default) or hold for a human. Never allow. */
  on_price_unavailable: "deny" | "review";
  /** Stock-token prices while markets are closed may be at most this old (read by the valuation). */
  max_closed_market_price_age_seconds: number;
  /** A contract call that spends tokens must bring something back into the account (a swap's output). */
  require_output_to_account: boolean;
}

/** Prices for the tokens a transaction spends, read before evaluation (schema 1.5). */
export interface SpendPrices {
  /** Unix seconds of the read. */
  observed_at: number;
  /** USD micros per whole token. */
  prices: { token: Address; price_micros: UintString; decimals: number }[];
  /** Tokens with a feed whose price is unavailable right now (stale, paused, depegged). */
  unavailable: Address[];
}

/** The agent's Zolva record as Palisec last read it. */
export interface ProvenRecordStatus {
  /** Unix seconds of the read. */
  observed_at: number;
  /** The account declared the Zolva agent on chain and the Zolva agent names the account back. */
  link_verified: boolean;
  /** Zolva's replay check of the agent's record. */
  replay_status: "match" | "differs" | "no_history";
  hours_verified: number;
  /** When the unlock took effect after the loosening delay; null while locked or pending. */
  unlocked_at: number | null;
}

/** The account's value before this decision, from Chainlink prices and Palisec's own snapshots. */
export interface LossSnapshot {
  /** Unix seconds of the read. */
  observed_at: number;
  /** Account value now, USD micros; null when an asset it holds cannot be priced. */
  value_usd_micros: UintString | null;
  /** Peak of the flow-adjusted value in the window, at today's deposits and withdrawals (>= value). */
  baseline_usd_micros: UintString | null;
  /** The account is paused by an earlier breach (latched until the owner resets), with its code. */
  paused: "PS_LOSS_001" | "PS_LOSS_002" | null;
  /** USD micros per whole token. A token not listed here and not unavailable has no price ($0). */
  prices: { token: Address; price_micros: UintString; decimals: number }[];
  /** Tokens the policy allows whose price is unavailable (stale, paused, depegged). */
  unavailable: Address[];
}

/** The agent's Upoch workflow as read from the Upoch ledger contract; workflow_id "" when none is set. */
export interface UpochStatus {
  workflow_id: string;
  /** Unix seconds of the read. */
  observed_at: number;
  /** The workflow's owner or a guardian is an owner of the agent's account. */
  linked: boolean;
  active: boolean;
  checkpoint_count: number;
  last_checkpoint_at: number | null;
  guardians: number;
}

export interface AssetAmount {
  /** ERC-20 address, or NATIVE_TOKEN for ETH. */
  token: Address;
  amount: UintString;
}

/** What the agent says the operation spends (at most) and receives (quoted). Optional. */
export interface AssetIntent {
  spend: AssetAmount[];
  receive: AssetAmount[];
}

/** One simulation of the exact operation from the account, produced before evaluation. */
export interface AssetSimulation {
  block_number: number;
  /** Unix seconds of the simulated block. */
  observed_at: number;
  reverted: boolean;
  /** Net amounts leaving and entering the account, per token (gas excluded). */
  outflows: AssetAmount[];
  inflows: AssetAmount[];
  /** Allowances the account granted during the operation. */
  approvals: { token: Address; spender: Address; amount: UintString }[];
  /**
   * What the operation leaves newly approved to each spender above: the allowance at its end less the
   * allowance before it (never below zero). Absent: unknown, and the token spend rule counts the approved
   * amounts instead.
   */
  allowances_after?: { token: Address; spender: Address; amount: UintString }[];
  /** Sell leg for received tokens; null when nothing was received or no leg could be built. */
  sell: { reverted: boolean } | null;
  /** Highest transfer tax seen on the buy or sell leg, basis points; null if nothing was received. */
  tax_bps: number | null;
  /** Value lost buying and immediately selling back, basis points; null when no route quotes it. */
  round_trip_loss_bps: number | null;
}

export interface AllowlistEntry {
  address: Address;
  /** 4-byte function selectors. Empty array means no methods are allowed. */
  selectors: Hex[];
  require_verified_code: boolean;
}

export interface Policy {
  schema_version: SchemaVersion;
  policy_id: string;
  /** Monotonic version assigned on activation. */
  version: number;
  account: { chain_id: number; address: Address };
  status: "draft" | "active" | "disabled";
  limits: {
    max_transaction_value_wei: UintString;
    max_gas_cost_wei: UintString;
    hourly_budget_usd_micros: UintString;
    max_pending_operations: number;
    /** USD limits are only enforceable with a fresh price. Older prices fail closed. */
    max_price_age_seconds: number;
  };
  cooldowns: {
    identical_calldata_seconds: number;
    identical_intent_seconds: number;
  };
  contracts: {
    default: "deny";
    allowlist: AllowlistEntry[];
    denylist: Address[];
  };
  human_approval: {
    usd_threshold_micros: UintString;
    require_for_unknown_methods: boolean;
  };
  failure_mode: "closed";
  /** Schema 1.1 and later. Absent means off. */
  asset_safety?: AssetSafety;
  /** Schema 1.2. Absent means off. */
  upoch_recovery?: UpochRecovery;
  /** Schema 1.3. Absent means off. */
  loss_limit?: LossLimit;
  /** Schema 1.4. Absent means off. */
  proven_record?: ProvenRecord;
  /** Schema 1.5. Absent means off: the limits count ETH and the fee only. */
  token_spend?: TokenSpend;
}

/** A proposed action from an agent. Typed intent, never free text. */
export interface Intent {
  request_id: string;
  agent_id: string;
  chain_id: number;
  from: Address;
  to: Address;
  value_wei: UintString;
  data: Hex;
  /** Unix seconds. Requests past their deadline are rejected. */
  deadline: number;
  /** Declared asset movement, checked against the simulation when asset safety is on. */
  asset_intent?: AssetIntent;
}

/** Inputs that come from outside the request. Each may be unavailable. */
export interface Environment {
  /** Unix seconds. Passed in explicitly so evaluation is deterministic. */
  now: number;
  fee_estimate_wei: UintString | null;
  eth_usd: { price_micros: UintString; observed_at: number } | null;
  /** Code verification result per address, as reported by the chain worker. */
  verified_code: Record<string, boolean>;
  emergency_stop: boolean;
  paused_agents: string[];
  /** Simulation of this exact operation; absent or null means unavailable (fails closed). */
  asset_simulation?: AssetSimulation | null;
  /** Upoch: the agent's Upoch workflow; absent or null means unavailable (fails closed when required). */
  upoch?: UpochStatus | null;
  /** Loss limits: the account's value; absent or null means unavailable (fails closed when a loss limit is on). */
  loss_snapshot?: LossSnapshot | null;
  /** Proven on Zolva: the agent's record; absent or null means the policy's own limits apply. */
  proven_record?: ProvenRecordStatus | null;
  /**
   * The account's emergency stop on the policy registry (ERC-8511), for accounts that publish there. Absent: not
   * published, nothing to check. Null: the registry could not be read (fails closed). A stop the account holds
   * stops Palisec's decisions too: only withdrawals to the loss limit's exit addresses stay allowed.
   */
  registry_stop?: { held_by_account: boolean; observed_at: number } | null;
  /** Token spend limits: prices for spent tokens; absent or null means none (spent tokens fail closed). */
  spend_prices?: SpendPrices | null;
}

export type ReservationState = "reserved" | "pending_approval" | "released" | "finalized";

export interface Reservation {
  reservation_id: string;
  request_id: string;
  agent_id: string;
  policy_version: number;
  amount_usd_micros: UintString;
  created_at: number;
  expires_at: number;
  state: ReservationState;
}

/** Authoritative state snapshot. Evaluation never mutates it; it returns the next snapshot. */
export interface LedgerState {
  reservations: Reservation[];
  seen_request_ids: string[];
  /** fingerprint -> last seen unix seconds */
  calldata_seen: Record<string, number>;
  intent_seen: Record<string, number>;
}

export type Decision = "ALLOW" | "DENY" | "REQUIRES_HUMAN_SIGNATURE";

export type CheckStatus = "pass" | "fail" | "review" | "skipped";

export interface CheckResult {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  /** "local" checks run in the simulator. "live" checks need a protected account. */
  enforcement: "local" | "live";
}

export interface EvaluationResult {
  request_id: string;
  decision: Decision;
  reason_code: ReasonCode | null;
  policy_id: string | null;
  policy_version: number | null;
  authorization_id: string | null;
  /** Always null here: the simulator never signs or broadcasts. */
  transaction_hash: null;
  retryable: boolean;
  message: string;
  checks: CheckResult[];
  next_state: LedgerState;
}
