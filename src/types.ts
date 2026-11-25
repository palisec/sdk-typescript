import type { ReasonCode } from "./schema";

export type Hex = `0x${string}`;
export type Address = `0x${string}`;

/**
 * Chains this release of Palisec accepts: Robinhood Chain (4663, real funds, where the deployment enables
 * it) and Robinhood Chain Testnet (46630). A ps_live_ key is a mainnet agent's; a ps_test_ key, testnet's.
 */
export const SUPPORTED_CHAINS = [4663, 46630] as const;
export const MAINNET = 4663;
export const TESTNET = 46630;
export type SupportedChainId = (typeof SUPPORTED_CHAINS)[number];

export interface LogEvent {
  type: "request" | "response" | "retry" | "error";
  method: string;
  path: string;
  attempt: number;
  status?: number;
  requestId?: string | null;
  durationMs?: number;
  code?: string;
}

export interface PalisecConfig {
  /** Agent API key from Console → Agents → Create key. Server-side only; never ship it to a browser. */
  apiKey: string;
  /** Optional: the key already says which network (ps_live_ → 4663, ps_test_ → 46630). A mismatch is refused. */
  chainId?: SupportedChainId;
  /** Defaults to https://palisec.tech/api/v1. */
  baseUrl?: string;
  /** Per-request timeout. Default 15 s. */
  timeoutMs?: number;
  /** Retries for network errors, 429 and 5xx, only on calls that are safe to repeat. Default 2. */
  maxRetries?: number;
  /** Structured events. API keys, bodies and calldata are never included. */
  logger?: (event: LogEvent) => void;
  fetch?: typeof fetch;
}

/** A transaction the agent intends to send, described before it is signed. */
export interface Intent {
  to: Address;
  /** Native value in wei. */
  value?: bigint | number | string;
  /** Calldata. Omit or "0x" for a plain transfer. */
  data?: Hex;
  /**
   * Gas limit you will send with. Palisec bounds the fee as gasLimit × current gas price, so a
   * realistic value keeps budgets accurate. Default: 21000 for a plain transfer, 250000 otherwise.
   */
  gasLimit?: bigint | number;
  /** Unique per intended transaction; also the idempotency key. Default: a random UUID. */
  requestId?: string;
  /** Seconds until the request is stale. Default 120, at most 3600. */
  deadlineSeconds?: number;
}

export type Decision = "ALLOW" | "DENY" | "REQUIRES_HUMAN_SIGNATURE";
export type OperationState =
  | "authorized"
  | "denied"
  | "pending_approval"
  | "approved"
  | "rejected"
  | "cancelled"
  | "expired"
  | "authorization_expired"
  | "not_recorded";

export interface Check {
  id: string;
  label: string;
  status: "pass" | "fail" | "review" | "skipped";
  detail: string;
}

/** A recorded decision. `transactionHash` is always null: Palisec authorizes, it does not broadcast. */
export interface Operation {
  operationId: string | null;
  requestId: string;
  decision: Decision;
  state: OperationState;
  reasonCode: ReasonCode | null;
  message: string;
  retryable: boolean;
  policyId: string | null;
  policyVersion: number | null;
  authorizationId: string | null;
  expiresAt: Date | null;
  checks: Check[];
  dryRun: boolean;
  /** Present when read back from the API: the account, target, value and exposure that were evaluated. */
  details?: Record<string, unknown>;
}

/** Narrowed views so a `switch (op.decision)` gives the right fields. */
export type Allowed = Operation & { decision: "ALLOW"; authorizationId: string; expiresAt: Date };
export type Denied = Operation & { decision: "DENY"; reasonCode: ReasonCode };
export type Held = Operation & { decision: "REQUIRES_HUMAN_SIGNATURE" };
export type AuthorizationResult = Allowed | Denied | Held;

/** The integration an API key belongs to (`whoAmI`). */
export interface Integration {
  agentId: string;
  name: string;
  framework: string | null;
  status: "active" | "paused" | "revoked";
  chainId: number;
  account: Address;
  scopes: string[];
  policy: { policy_key: string; version: number } | null;
  emergencyStop: boolean;
}

/** The exact active policy version an agent is evaluated against. */
export interface BoundPolicy {
  policyKey: string;
  name: string;
  version: number;
  documentHash: string;
  activatedAt: Date;
  document: Record<string, unknown>;
}

export interface AuditEvent {
  seq: string;
  eventId: string;
  type: string;
  detail: Record<string, unknown>;
  createdAt: Date;
}
