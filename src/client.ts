import { RETRYABLE, type ReasonCode } from "./schema";
import { PalisecApprovalError, PalisecConfigError, PalisecDeniedError, PalisecError, PalisecTimeoutError } from "./errors";
import {
  SUPPORTED_CHAINS,
  type Address,
  type AuditEvent,
  type AuthorizationResult,
  type BoundPolicy,
  type Integration,
  type Hex,
  type Intent,
  type LogEvent,
  type Operation,
  type PalisecConfig,
  type SupportedChainId,
} from "./types";
import { safeOpTypedData, type Execution, type PreparedExecution, type PreparedUserOperation, type TypedDataSigner } from "./smart-account";

const KEY = /^ps_(live|test)_[0-9a-f]{48}$/;
const DEFAULT_BASE = "https://palisec.tech/api/v1";
const RETRY_STATUS = new Set([429, 502, 503, 504]);
const USABLE = new Set(["authorized", "approved"]);

/** Masks Palisec API keys anywhere in a string, for logs and error reports. */
export function redact(text: string): string {
  return text.replace(/ps_(?:live|test)_[0-9a-f]{8,}/g, (k) => `${k.slice(0, 12)}…[redacted]`);
}

/** The minimum of a viem WalletClient that `sendTransaction` needs. `fromEthers` adapts an ethers signer to it. */
export interface SendingWallet {
  account?: { address: Address } | null;
  sendTransaction(args: { to: Address; value?: bigint; data?: Hex; gas?: bigint; account?: unknown; chain?: unknown }): Promise<Hex>;
  chain?: { id?: number } | null | unknown;
}

interface RawOperation {
  operation_id: string | null;
  request_id: string;
  decision: Operation["decision"];
  state: Operation["state"];
  reason_code: ReasonCode | null;
  message: string;
  retryable: boolean;
  policy_id: string | null;
  policy_version: number | null;
  authorization_id: string | null;
  expires_at: string | null;
  checks: Operation["checks"];
  dry_run: boolean;
  details?: Record<string, unknown>;
}

function toOperation(r: RawOperation): Operation {
  return {
    operationId: r.operation_id,
    requestId: r.request_id,
    decision: r.decision,
    state: r.state,
    reasonCode: r.reason_code,
    message: r.message,
    retryable: r.retryable,
    policyId: r.policy_id,
    policyVersion: r.policy_version,
    authorizationId: r.authorization_id,
    expiresAt: r.expires_at ? new Date(r.expires_at) : null,
    checks: r.checks ?? [],
    dryRun: r.dry_run,
    ...(r.details ? { details: r.details } : {}),
  };
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new PalisecTimeoutError("Aborted"));
    });
  });

export class PalisecClient {
  readonly chainId: SupportedChainId;
  private readonly base: string;
  private readonly key: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly log: (e: LogEvent) => void;
  private readonly fetchImpl: typeof fetch;

  constructor(config: PalisecConfig) {
    const kind = KEY.exec(config.apiKey ?? "")?.[1];
    if (!kind) throw new PalisecConfigError("apiKey must be a Palisec agent key (ps_live_ or ps_test_ followed by 48 hex characters)");
    // The key decides the network, so a mainnet key can never be pointed at testnet by accident, or the reverse.
    const keyChain: SupportedChainId = kind === "live" ? 4663 : 46630;
    const chainId = config.chainId ?? keyChain;
    if (!(SUPPORTED_CHAINS as readonly number[]).includes(chainId))
      throw new PalisecConfigError(`chainId ${chainId} is not supported; supported: ${SUPPORTED_CHAINS.join(", ")}`);
    if (chainId !== keyChain)
      throw new PalisecConfigError(`This is a ${kind === "live" ? "mainnet (ps_live_)" : "testnet (ps_test_)"} key, so chainId must be ${keyChain}, not ${chainId}`);
    const base = (config.baseUrl ?? DEFAULT_BASE).replace(/\/+$/, "");
    if (!/^https:\/\//.test(base) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(`${base}/`))
      throw new PalisecConfigError("baseUrl must use HTTPS (plain HTTP is allowed only for localhost)");
    this.chainId = chainId;
    this.base = base;
    this.key = config.apiKey;
    this.timeoutMs = config.timeoutMs ?? 15_000;
    this.maxRetries = Math.max(0, Math.min(config.maxRetries ?? 2, 5));
    this.log = config.logger ?? (() => {});
    const f = config.fetch ?? globalThis.fetch;
    if (!f) throw new PalisecConfigError("No fetch implementation available; pass config.fetch (Node 18+ has one built in)");
    this.fetchImpl = f.bind(globalThis);
  }

  /** Converts an intent to the API body. The sender is not sent: it is the agent's registered account. */
  private body(intent: Intent) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(intent.to)) throw new PalisecConfigError("intent.to must be a 20-byte hex address");
    const data = intent.data ?? "0x";
    const deadline = Math.floor(Date.now() / 1000) + Math.min(Math.max(intent.deadlineSeconds ?? 120, 1), 3600);
    const gas = intent.gasLimit ?? (data === "0x" ? 21_000 : 250_000);
    return {
      request_id: intent.requestId ?? crypto.randomUUID(),
      chain_id: this.chainId,
      to: intent.to,
      value_wei: BigInt(intent.value ?? 0).toString(),
      data,
      gas_limit: Number(gas),
      deadline,
    };
  }

  private async request<T>(method: string, path: string, opts: { body?: unknown; idempotencyKey?: string; retry: boolean }): Promise<T> {
    const attempts = opts.retry ? this.maxRetries + 1 : 1;
    let last: unknown;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      const started = Date.now();
      this.log({ type: "request", method, path, attempt });
      try {
        const headers: Record<string, string> = { authorization: `Bearer ${this.key}`, accept: "application/json" };
        if (opts.body !== undefined) headers["content-type"] = "application/json";
        if (opts.idempotencyKey) headers["idempotency-key"] = opts.idempotencyKey;
        const res = await this.fetchImpl(`${this.base}${path}`, {
          method,
          headers,
          body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        const text = await res.text();
        let json: Record<string, unknown> = {};
        try {
          json = text ? JSON.parse(text) : {};
        } catch {
          json = {};
        }
        const err = json.error as { code?: string; message?: string; retryable?: boolean } | undefined;
        const requestId = (json.request_id as string | undefined) ?? null;
        this.log({ type: "response", method, path, attempt, status: res.status, requestId, durationMs: Date.now() - started, ...(err?.code ? { code: err.code } : {}) });
        if (res.ok) return json as T;
        const code = err?.code ?? (res.status === 401 ? "PS_AUTH_001" : "PS_STATE_001");
        const retryable = err?.retryable ?? RETRYABLE[code as ReasonCode] ?? RETRY_STATUS.has(res.status);
        last = new PalisecError(redact(err?.message ?? `HTTP ${res.status}`), code, res.status, requestId, retryable);
        if (!(opts.retry && RETRY_STATUS.has(res.status))) throw last;
      } catch (e) {
        if (e instanceof PalisecError && !(opts.retry && e.status !== null && RETRY_STATUS.has(e.status))) throw e;
        if (!(e instanceof PalisecError)) {
          const timedOut = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
          last = timedOut
            ? new PalisecTimeoutError(`${method} ${path} timed out after ${this.timeoutMs} ms`)
            : new PalisecError(`Network error calling ${method} ${path}`, "PS_SDK_NETWORK", null, null, true);
          if (!opts.retry) throw last;
        }
      }
      if (attempt < attempts) {
        const wait = Math.min(250 * 2 ** (attempt - 1), 4000) + Math.floor(Math.random() * 100);
        this.log({ type: "retry", method, path, attempt, durationMs: wait });
        await sleep(wait);
      }
    }
    this.log({ type: "error", method, path, attempt: attempts, code: last instanceof PalisecError ? last.code : "PS_SDK_NETWORK" });
    throw last;
  }

  /**
   * Asks Palisec whether this transaction may be sent, and records the decision with its budget
   * reservation. Safe to retry: the request ID is the idempotency key, so a retry returns the
   * original decision instead of a second one. Returns ALLOW, DENY or REQUIRES_HUMAN_SIGNATURE;
   * it does not throw on DENY. Use `sendTransaction` to have the SDK enforce the decision.
   */
  async authorize(intent: Intent): Promise<AuthorizationResult> {
    const body = this.body(intent);
    const raw = await this.request<RawOperation>("POST", "/operations", { body, idempotencyKey: body.request_id, retry: true });
    return toOperation(raw) as AuthorizationResult;
  }

  /** Dry run: the same evaluation against live state, reserving nothing and recording nothing. */
  async evaluate(intent: Intent): Promise<Operation> {
    return toOperation(await this.request<RawOperation>("POST", "/authorizations/evaluate", { body: this.body(intent), retry: true }));
  }

  /** Reads one of this agent's operations. */
  async getOperation(operationId: string): Promise<Operation> {
    if (!/^[0-9a-f-]{36}$/i.test(operationId)) throw new PalisecConfigError("operationId must be an operation's id");
    return toOperation(await this.request<RawOperation>("GET", `/operations/${operationId}`, { retry: true }));
  }

  /** The integration this key belongs to: agent, protected account, chain, scopes and bound policy. */
  async whoAmI(): Promise<Integration> {
    const r = await this.request<Record<string, unknown>>("GET", "/integration", { retry: true });
    return {
      agentId: String(r.agent_id),
      name: String(r.name ?? ""),
      framework: (r.framework as string | null) ?? null,
      status: r.status as Integration["status"],
      chainId: Number(r.chain_id),
      account: r.account as Address,
      scopes: (r.scopes as string[]) ?? [],
      policy: (r.policy as Integration["policy"]) ?? null,
      emergencyStop: Boolean(r.emergency_stop),
    };
  }

  /** Policy reads (scope policy:read). */
  readonly policy = {
    /** The exact active policy version this agent is evaluated against. */
    get: async (): Promise<BoundPolicy> => {
      const r = await this.request<Record<string, unknown>>("GET", "/integration/policy", { retry: true });
      return { policyKey: String(r.policy_key), name: String(r.name), version: Number(r.version), documentHash: String(r.document_hash), activatedAt: new Date(String(r.activated_at)), document: r.document as Record<string, unknown> };
    },
  };

  /** Audit reads (scope audit:read). */
  readonly audit = {
    /** Audit events this agent caused, newest first. Pass `before` from the previous page to continue. */
    list: async (opts: { limit?: number; before?: string } = {}): Promise<{ events: AuditEvent[]; nextBefore: string | null }> => {
      const q = new URLSearchParams({ limit: String(opts.limit ?? 50), ...(opts.before ? { before: opts.before } : {}) });
      const r = await this.request<{ events: Record<string, unknown>[]; next_before: string | null }>("GET", `/integration/audit-events?${q}`, { retry: true });
      return { events: r.events.map((e) => ({ seq: String(e.seq), eventId: String(e.event_id), type: String(e.type), detail: (e.detail as Record<string, unknown>) ?? {}, createdAt: new Date(String(e.created_at)) })), nextBefore: r.next_before };
    },
  };

  /** This agent's own operations (scope operations:read). */
  readonly operations = {
    list: async (opts: { limit?: number; before?: string; decision?: Operation["decision"] } = {}): Promise<{ operations: Operation[]; nextBefore: string | null }> => {
      const q = new URLSearchParams({ limit: String(opts.limit ?? 20), ...(opts.before ? { before: opts.before } : {}), ...(opts.decision ? { decision: opts.decision } : {}) });
      const r = await this.request<{ operations: RawOperation[]; next_before: string | null }>("GET", `/integration/operations?${q}`, { retry: true });
      return { operations: r.operations.map(toOperation), nextBefore: r.next_before };
    },
  };

  /**
   * The same methods grouped by the 2.0 naming: `propose` is `authorize` (records a decision),
   * `evaluate` is the dry run. Kept as aliases so existing code keeps working.
   */
  readonly transactions = {
    evaluate: (intent: Intent) => this.evaluate(intent),
    propose: (intent: Intent) => this.authorize(intent),
    get: (operationId: string) => this.getOperation(operationId),
    waitForApproval: (operationId: string, opts?: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal }) => this.waitForApproval(operationId, opts),
    cancel: (operationId: string) => this.cancel(operationId),
  };

  /** Withdraws an operation that is still waiting for approval. Authorized operations keep their budget until they expire. */
  async cancel(operationId: string): Promise<Operation> {
    if (!/^[0-9a-f-]{36}$/i.test(operationId)) throw new PalisecConfigError("operationId must be an operation's id");
    return toOperation(await this.request<RawOperation>("POST", `/operations/${operationId}/cancel`, { retry: false }));
  }

  /**
   * Waits for an approver's decision on a held operation. Resolves with the approved operation
   * (now carrying an authorization) or throws PalisecApprovalError if it is rejected, expires or
   * is withdrawn, and PalisecTimeoutError if `timeoutMs` passes first.
   */
  async waitForApproval(operationId: string, opts: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal } = {}): Promise<Operation> {
    const until = Date.now() + (opts.timeoutMs ?? 15 * 60_000);
    const interval = Math.max(opts.intervalMs ?? 5000, 1000);
    for (;;) {
      const op = await this.getOperation(operationId);
      if (op.state === "approved") return op;
      if (op.state !== "pending_approval") throw new PalisecApprovalError(op);
      if (Date.now() + interval > until) throw new PalisecTimeoutError(`No approval decision for ${operationId} within the timeout`);
      await sleep(interval, opts.signal);
    }
  }

  /**
   * Authorizes, then sends with your viem wallet only if allowed. Throws PalisecDeniedError on
   * DENY (nothing is sent). A held operation is either awaited (`waitForApproval: true`) or
   * returned to you unsent, with `hash: null`, so you can poll it later.
   *
   * The wallet must be the agent's registered account. This enforces the decision in your
   * process only: until the on-chain module ships, a key that skips Palisec can still transact.
   */
  async sendTransaction(
    wallet: SendingWallet,
    intent: Intent,
    opts: { waitForApproval?: boolean; approvalTimeoutMs?: number } = {},
  ): Promise<{ operation: Operation; hash: Hex | null }> {
    const requestId = intent.requestId ?? crypto.randomUUID();
    let op: Operation = await this.authorize({ ...intent, requestId });
    if (op.decision === "DENY") throw new PalisecDeniedError(op);
    if (op.state === "pending_approval") {
      if (!opts.waitForApproval) return { operation: op, hash: null };
      op = await this.waitForApproval(op.operationId!, { ...(opts.approvalTimeoutMs ? { timeoutMs: opts.approvalTimeoutMs } : {}) });
    }
    if (!USABLE.has(op.state) || !op.authorizationId) throw new PalisecDeniedError(op);
    if (op.expiresAt && op.expiresAt.getTime() <= Date.now()) throw new PalisecTimeoutError("The authorization expired before sending");
    const walletChain = (wallet.chain as { id?: unknown } | null | undefined)?.id;
    if (typeof walletChain === "number" && walletChain !== this.chainId)
      throw new PalisecConfigError(`The wallet is on chain ${walletChain}, but this client authorizes chain ${this.chainId}`);
    const account = typeof op.details?.account === "string" ? (op.details.account as string) : null;
    const sender = wallet.account?.address;
    if (account && sender && account.toLowerCase() !== sender.toLowerCase())
      throw new PalisecConfigError(`The wallet ${sender} is not the agent's registered account ${account}`);
    const hash = await wallet.sendTransaction({
      to: intent.to,
      value: BigInt(intent.value ?? 0),
      data: intent.data ?? "0x",
      gas: BigInt(intent.gasLimit ?? ((intent.data ?? "0x") === "0x" ? 21_000 : 250_000)),
      account: wallet.account ?? undefined,
      chain: wallet.chain,
    });
    return { operation: op, hash };
  }

  /* ───────── PALISEC smart accounts: on-chain enforcement ───────── */

  /** Builds the one user operation PALISEC will co-sign for an allowed or approved operation. Nothing is sent. */
  async prepareExecution(operationId: string): Promise<PreparedExecution> {
    if (!/^[0-9a-f-]{36}$/i.test(operationId)) throw new PalisecConfigError("operationId must be an operation's id");
    const r = await this.request<{
      operation_id: string;
      safe_op_hash: Hex;
      user_operation: PreparedUserOperation;
      max_cost_wei: string;
      valid_until: string;
      typed_data: Record<string, unknown>;
    }>("POST", `/operations/${operationId}/user-operation`, { retry: true });
    return {
      operationId: r.operation_id,
      safeOpHash: r.safe_op_hash,
      userOperation: r.user_operation,
      maxCostWei: BigInt(r.max_cost_wei),
      validUntil: new Date(r.valid_until),
      typedDataJson: r.typed_data,
    };
  }

  /** Sends the agent's signature. PALISEC adds its co-signature once and submits through the bundler. */
  async submitExecution(operationId: string, signature: Hex): Promise<Execution> {
    if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) throw new PalisecConfigError("signature must be 65 bytes of hex");
    await this.request<Record<string, unknown>>("POST", `/operations/${operationId}/submit`, { body: { signature }, retry: false });
    return this.getExecution(operationId);
  }

  /** Where a submitted operation is. Asking also records the receipt once the bundler has it. */
  async getExecution(operationId: string): Promise<Execution> {
    return toExecution(await this.request<RawExecution>("GET", `/operations/${operationId}/execution`, { retry: true }));
  }

  /**
   * Authorizes, then executes through the agent's PALISEC smart account: PALISEC prepares the exact
   * operation, `signer` (the agent's key) signs it, PALISEC co-signs and submits, and this waits for the
   * transaction. The account enforces it on chain: without PALISEC's co-signature nothing moves.
   * Throws PalisecDeniedError on DENY. A held operation is awaited when `waitForApproval` is set.
   */
  async executeWithSmartAccount(
    signer: TypedDataSigner,
    intent: Intent,
    opts: { waitForApproval?: boolean; approvalTimeoutMs?: number; receiptTimeoutMs?: number; signal?: AbortSignal } = {},
  ): Promise<{ operation: Operation; execution: Execution }> {
    const requestId = intent.requestId ?? crypto.randomUUID();
    let op: Operation = await this.authorize({ ...intent, requestId });
    if (op.decision === "DENY") throw new PalisecDeniedError(op);
    if (op.state === "pending_approval") {
      if (!opts.waitForApproval) return { operation: op, execution: { operationId: op.operationId!, status: "not_prepared", userOpHash: null, transactionHash: null, submittedAt: null, executedAt: null } };
      op = await this.waitForApproval(op.operationId!, { ...(opts.approvalTimeoutMs ? { timeoutMs: opts.approvalTimeoutMs } : {}) });
    }
    if (!USABLE.has(op.state) || !op.operationId) throw new PalisecDeniedError(op);
    const prepared = await this.prepareExecution(op.operationId);
    const signature = await signer.signTypedData(safeOpTypedData(prepared.userOperation, this.chainId));
    let execution = await this.submitExecution(op.operationId, signature);
    const until = Date.now() + (opts.receiptTimeoutMs ?? 90_000);
    while (execution.status === "submitted" && Date.now() < until) {
      await sleep(3000, opts.signal);
      execution = await this.getExecution(op.operationId);
    }
    return { operation: op, execution };
  }
}

interface RawExecution {
  operation_id: string;
  status: Execution["status"];
  user_op_hash: Hex | null;
  transaction_hash: Hex | null;
  submitted_at: string | null;
  executed_at: string | null;
}

const toExecution = (r: RawExecution): Execution => ({
  operationId: r.operation_id,
  status: r.status,
  userOpHash: r.user_op_hash,
  transactionHash: r.transaction_hash,
  submittedAt: r.submitted_at ? new Date(r.submitted_at) : null,
  executedAt: r.executed_at ? new Date(r.executed_at) : null,
});

/** Creates a client. Keep the API key server-side. */
export function createPalisec(config: PalisecConfig): PalisecClient {
  return new PalisecClient(config);
}
