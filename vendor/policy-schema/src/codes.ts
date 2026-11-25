/**
 * Stable, machine-readable reason codes (spec §5.7).
 * Codes are append-only: never renumber or reuse a code.
 */
export const REASON_CODES = {
  PS_AUTH_001: "Authentication failed",
  PS_POLICY_001: "No valid active policy",
  PS_POLICY_002: "Explicit deny rule matched",
  PS_TARGET_001: "Target contract not allowed",
  PS_METHOD_001: "Function selector not allowed",
  PS_BUDGET_001: "Budget limit exceeded",
  PS_RATE_001: "Rate limit exceeded",
  PS_LOOP_001: "Repeated intent or calldata detected",
  PS_REPLAY_001: "Duplicate or expired authorization",
  PS_ATTEST_001: "Enclave attestation invalid",
  PS_SIM_001: "Simulation failed",
  PS_FEE_001: "Fee estimation unavailable or invalid",
  PS_HUMAN_001: "Human approval required",
  PS_PAUSED_001: "Agent or account is paused",
  PS_STATE_001: "Authoritative state unavailable",
  PS_CHAIN_001: "Chain or bundler unavailable",
  // Extension to the §5.7 table: request schema failures need their own code.
  PS_REQUEST_001: "Request failed schema validation",
  // Asset safety (schema 1.1). PS_SIM_001 above covers an unavailable, stale or reverting simulation.
  PS_ASSET_001: "Sell simulation failed: likely honeypot",
  PS_ASSET_002: "Transfer tax above the policy maximum",
  PS_ASSET_003: "Simulated balance changes do not match the declared intent",
  PS_APPROVAL_001: "Unlimited or oversized approval to a non-allowlisted spender",
  // Upoch recovery (schema 1.2).
  PS_RECOVERY_001: "Agent is not recoverable on Upoch",
  PS_RECOVERY_002: "Upoch checkpoint is too old",
  PS_RECOVERY_003: "Upoch data unavailable",
  // Loss limit (schema 1.3).
  PS_LOSS_001: "Loss limit reached: drawdown percentage",
  PS_LOSS_002: "Loss limit reached: USD loss",
  PS_LOSS_003: "Account value unavailable",
  // Token spend limits (schema 1.5). Limits themselves reuse PS_BUDGET_001 and PS_HUMAN_001.
  PS_PRICE_001: "No reliable price for a token the transaction spends",
  PS_SIM_002: "The transaction's outflows could not be determined",
} as const;

export type ReasonCode = keyof typeof REASON_CODES;

/** Whether a client may retry the same request after the condition clears. */
export const RETRYABLE: Record<ReasonCode, boolean> = {
  PS_AUTH_001: false,
  PS_POLICY_001: false,
  PS_POLICY_002: false,
  PS_TARGET_001: false,
  PS_METHOD_001: false,
  PS_BUDGET_001: true,
  PS_RATE_001: true,
  PS_LOOP_001: false,
  PS_REPLAY_001: false,
  PS_ATTEST_001: true,
  PS_SIM_001: false,
  PS_FEE_001: true,
  PS_HUMAN_001: false,
  PS_PAUSED_001: true,
  PS_STATE_001: true,
  PS_CHAIN_001: true,
  PS_REQUEST_001: false,
  PS_ASSET_001: false,
  PS_ASSET_002: false,
  PS_ASSET_003: false,
  PS_APPROVAL_001: false,
  PS_RECOVERY_001: false,
  PS_RECOVERY_002: false,
  PS_RECOVERY_003: true,
  PS_LOSS_001: false,
  PS_LOSS_002: false,
  PS_LOSS_003: true,
  PS_PRICE_001: true,
  PS_SIM_002: true,
};
