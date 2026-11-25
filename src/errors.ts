import type { ReasonCode } from "./schema";
import type { Operation } from "./types";

/** Every failure carries a stable code; match on `code`, never on `message`. */
export class PalisecError extends Error {
  override readonly name: string = "PalisecError";
  constructor(
    message: string,
    readonly code: ReasonCode | "PS_SDK_CONFIG" | "PS_SDK_TIMEOUT" | "PS_SDK_NETWORK" | (string & {}),
    readonly status: number | null = null,
    readonly requestId: string | null = null,
    readonly retryable = false,
  ) {
    super(message);
  }
}

/** The client was configured in a way that cannot work (bad key format, unsupported chain). */
export class PalisecConfigError extends PalisecError {
  override readonly name = "PalisecConfigError";
  constructor(message: string) {
    super(message, "PS_SDK_CONFIG");
  }
}

/** The policy denied the operation. Nothing was authorized; do not send the transaction. */
export class PalisecDeniedError extends PalisecError {
  override readonly name = "PalisecDeniedError";
  constructor(readonly operation: Operation) {
    super(operation.message, operation.reasonCode ?? "PS_POLICY_001", 200, operation.requestId, operation.retryable);
  }
}

/** A held operation ended without approval: rejected, expired or withdrawn. */
export class PalisecApprovalError extends PalisecError {
  override readonly name = "PalisecApprovalError";
  constructor(readonly operation: Operation) {
    super(`Approval ended as ${operation.state}`, operation.state === "rejected" ? "PS_HUMAN_001" : "PS_REPLAY_001", 200, operation.requestId, false);
  }
}

/** The request or the wait did not finish in time. For POST /operations a retry with the same key is safe. */
export class PalisecTimeoutError extends PalisecError {
  override readonly name = "PalisecTimeoutError";
  constructor(message: string) {
    super(message, "PS_SDK_TIMEOUT", null, null, true);
  }
}
