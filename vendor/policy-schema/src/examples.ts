import { NATIVE_TOKEN, type AssetSafety, type AssetSimulation, type Environment, type Intent, type Policy } from "./types";

/**
 * Illustrative data for the local simulator and documentation.
 * These addresses and limits are not live deployments or recommended production limits.
 */

export const EXAMPLE_ACCOUNT = "0x1111111111111111111111111111111111111111" as const;
export const EXAMPLE_TOKEN = "0x2222222222222222222222222222222222222222" as const;
export const EXAMPLE_ROUTER = "0x3333333333333333333333333333333333333333" as const;
export const EXAMPLE_UNKNOWN = "0x4444444444444444444444444444444444444444" as const;
export const EXAMPLE_DENIED = "0x5555555555555555555555555555555555555555" as const;
export const EXAMPLE_RECIPIENT = "000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd";

export const SELECTORS = {
  transfer: "0xa9059cbb",
  approve: "0x095ea7b3",
  swapExactTokensForTokens: "0x38ed1739",
} as const;

export const EXAMPLE_POLICY: Policy = {
  schema_version: "1.0",
  policy_id: "policy_trading_001",
  version: 7,
  account: { chain_id: 4663, address: EXAMPLE_ACCOUNT },
  status: "active",
  limits: {
    max_transaction_value_wei: "100000000000000000",
    max_gas_cost_wei: "5000000000000000",
    hourly_budget_usd_micros: "500000000",
    max_pending_operations: 3,
    max_price_age_seconds: 60,
  },
  cooldowns: {
    identical_calldata_seconds: 60,
    identical_intent_seconds: 15,
  },
  contracts: {
    default: "deny",
    allowlist: [
      { address: EXAMPLE_TOKEN, selectors: [SELECTORS.transfer], require_verified_code: true },
      { address: EXAMPLE_ROUTER, selectors: [SELECTORS.swapExactTokensForTokens], require_verified_code: true },
    ],
    denylist: [EXAMPLE_DENIED],
  },
  human_approval: {
    usd_threshold_micros: "150000000",
    require_for_unknown_methods: true,
  },
  failure_mode: "closed",
};

/** Simulated clock origin: 2026-01-01T00:00:00Z. */
export const SIM_EPOCH = 1767225600;

export const EXAMPLE_ENV: Environment = {
  now: SIM_EPOCH,
  fee_estimate_wei: "120000000000000",
  eth_usd: { price_micros: "3200000000", observed_at: SIM_EPOCH },
  verified_code: { [EXAMPLE_TOKEN]: true, [EXAMPLE_ROUTER]: true },
  emergency_stop: false,
  paused_agents: [],
};

const transferData = (amountHex: string) =>
  `${SELECTORS.transfer}${EXAMPLE_RECIPIENT}${amountHex.padStart(64, "0")}` as `0x${string}`;

const word = (v: bigint | string) => (typeof v === "string" ? v.replace(/^0x/, "").padStart(64, "0") : v.toString(16).padStart(64, "0"));

/** swapExactTokensForTokens(amountIn, amountOutMin, path[token, WETH], to, deadline), fully ABI-encoded. */
const swapData = (amountIn: bigint, amountOutMin: bigint) =>
  `${SELECTORS.swapExactTokensForTokens}${[
    word(amountIn),
    word(amountOutMin),
    word(0xa0n), // offset of the dynamic path array
    word(EXAMPLE_ACCOUNT),
    word(BigInt(SIM_EPOCH + 600)),
    word(2n),
    word(EXAMPLE_TOKEN),
    word("0x6666666666666666666666666666666666666666"),
  ].join("")}` as `0x${string}`;

export interface Scenario {
  id: string;
  label: string;
  summary: string;
  intent: Omit<Intent, "request_id" | "deadline">;
  /** Asset safety: the example's simulated result (the browser has no chain); observed_at is set at evaluation. */
  simulation?: Omit<AssetSimulation, "observed_at">;
}

/** Schema 1.1 asset-safety defaults, as new policies get them. */
export const EXAMPLE_ASSET_SAFETY: AssetSafety = {
  enabled: true,
  max_transfer_tax_bps: 500,
  max_slippage_bps: 300,
  require_sell_simulation: true,
  block_unlimited_approvals: true,
  on_simulation_unavailable: "deny",
  max_simulation_age_seconds: 10,
};

/** The browser stand-in for a simulation: the ETH value leaves the account and nothing else moves. */
export function exampleSimulation(s: Scenario, now: number): AssetSimulation {
  const base = s.simulation ?? {
    block_number: 118_000_000,
    reverted: false,
    outflows: s.intent.value_wei === "0" ? [] : [{ token: NATIVE_TOKEN, amount: s.intent.value_wei }],
    inflows: [],
    approvals: [],
    sell: null,
    tax_bps: null,
    round_trip_loss_bps: null,
  };
  return { ...base, observed_at: now };
}

export const SCENARIOS: Scenario[] = [
  {
    id: "token-transfer",
    label: "Token transfer",
    summary: "transfer() on an allowlisted token, no ETH value.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_TOKEN, value_wei: "0", data: transferData("2540be400") },
  },
  {
    id: "swap",
    label: "Router swap · 0.04 ETH",
    summary: "Allowlisted swap selector carrying 0.04 ETH.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_ROUTER, value_wei: "40000000000000000", data: swapData(128_000_000n, 126_000_000n) },
  },
  {
    id: "large-swap",
    label: "Router swap · 0.08 ETH",
    summary: "Within the value limit, above the human-approval threshold.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_ROUTER, value_wei: "80000000000000000", data: swapData(256_000_000n, 252_000_000n) },
  },
  {
    id: "over-limit",
    label: "Swap · 0.5 ETH",
    summary: "Same swap at ten times the per-transaction limit.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_ROUTER, value_wei: "500000000000000000", data: swapData(1_600_000_000n, 1_580_000_000n) },
  },
  {
    id: "unknown-method",
    label: "approve() on token",
    summary: "A selector the policy does not list.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_TOKEN, value_wei: "0", data: `${SELECTORS.approve}${EXAMPLE_RECIPIENT}${"f".repeat(64)}` },
  },
  {
    id: "unknown-target",
    label: "Unlisted contract",
    summary: "A call to a contract that is not on the allowlist.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_UNKNOWN, value_wei: "10000000000000000", data: "0x" },
  },
  {
    id: "tax-token",
    label: "Buy a token with a 20% sell tax",
    summary: "Router buy of a token whose sell leg loses 20% in simulation.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_ROUTER, value_wei: "20000000000000000", data: swapData(64_000_000n, 63_000_000n) },
    simulation: {
      block_number: 118_000_000,
      reverted: false,
      outflows: [{ token: NATIVE_TOKEN, amount: "20000000000000000" }],
      inflows: [{ token: "0x7777777777777777777777777777777777777777", amount: "64000000000000000000" }],
      approvals: [],
      sell: { reverted: false },
      tax_bps: 2000,
      round_trip_loss_bps: 2160,
    },
  },
  {
    id: "denied-target",
    label: "Denylisted contract",
    summary: "A target named in an explicit deny rule.",
    intent: { agent_id: "agent_rebalancer_01", chain_id: 4663, from: EXAMPLE_ACCOUNT, to: EXAMPLE_DENIED, value_wei: "0", data: transferData("1") },
  },
];
