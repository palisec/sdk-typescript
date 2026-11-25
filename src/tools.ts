import { REASON_CODES, RETRYABLE, type ReasonCode } from "./schema";
import type { PalisecClient, SendingWallet } from "./client";
import { PalisecDeniedError, PalisecError } from "./errors";
import type { Address, Hex } from "./types";

/**
 * Framework-neutral tools for agent frameworks (OpenAI Agents SDK, Vercel AI SDK, LangGraph, or your
 * own loop). Each is a name, a description, a JSON Schema and an `execute` that returns text for the
 * model. They hold no security logic: every call goes through PALISEC like any other SDK call, and
 * `palisec_send_transaction` sends only on ALLOW. Errors come back as text so the model can react.
 */
export interface PalisecTool {
  name: string;
  description: string;
  parameters: { type: "object"; properties: Record<string, unknown>; required: string[]; additionalProperties: false };
  execute(input: Record<string, unknown>): Promise<string>;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX = /^0x([0-9a-fA-F]{2})*$/;
const UINT = /^(0|[1-9][0-9]{0,77})$/;

const txSchema = {
  type: "object" as const,
  properties: {
    to: { type: "string", description: "Target contract or recipient, 0x-prefixed 20-byte address" },
    value_wei: { type: "string", description: "Native value in wei as a decimal string; \"0\" for none" },
    data: { type: "string", description: "Calldata as 0x-prefixed hex; \"0x\" for a plain transfer" },
    gas_limit: { type: "integer", description: "Gas limit the transaction will use (21000 for a plain transfer)" },
  },
  required: ["to", "value_wei", "data", "gas_limit"],
  additionalProperties: false as const,
};

function intentFrom(input: Record<string, unknown>) {
  const { to, value_wei, data, gas_limit } = input;
  if (typeof to !== "string" || !ADDRESS.test(to)) throw new PalisecError("to must be a 0x-prefixed 20-byte address", "PS_REQUEST_001");
  if (typeof value_wei !== "string" || !UINT.test(value_wei)) throw new PalisecError("value_wei must be a decimal integer string", "PS_REQUEST_001");
  if (typeof data !== "string" || !HEX.test(data)) throw new PalisecError("data must be 0x-prefixed hex", "PS_REQUEST_001");
  if (typeof gas_limit !== "number" || !Number.isInteger(gas_limit) || gas_limit < 21000 || gas_limit > 30_000_000) throw new PalisecError("gas_limit must be an integer between 21000 and 30000000", "PS_REQUEST_001");
  return { to: to as Address, value: BigInt(value_wei), data: data as Hex, gasLimit: gas_limit };
}

const text = (v: unknown) => JSON.stringify(v);
const failure = (e: unknown) =>
  e instanceof PalisecError ? text({ status: "error", code: e.code, message: e.message, retryable: e.retryable }) : text({ status: "error", message: "The request failed" });

/**
 * Creates the tools. Pass `wallet` (the agent's own account, as for `sendTransaction`) to include
 * `palisec_send_transaction`; without it the agent can only evaluate and read.
 */
export function createPalisecTools(palisec: PalisecClient, opts: { wallet?: SendingWallet } = {}): PalisecTool[] {
  const tools: PalisecTool[] = [
    {
      name: "palisec_evaluate_transaction",
      description: "Ask PALISEC what it would decide for this transaction now (dry run). Reserves nothing and never authorizes. Use before proposing.",
      parameters: txSchema,
      async execute(input) {
        try {
          const op = await palisec.evaluate(intentFrom(input));
          return text({ decision: op.decision, reason_code: op.reasonCode, message: op.message });
        } catch (e) {
          return failure(e);
        }
      },
    },
    {
      name: "palisec_get_operation",
      description: "Current state of an operation PALISEC recorded for this agent (for example whether a held operation was approved).",
      parameters: { type: "object", properties: { operation_id: { type: "string", description: "Operation ID returned earlier" } }, required: ["operation_id"], additionalProperties: false },
      async execute(input) {
        try {
          const op = await palisec.getOperation(String(input.operation_id ?? ""));
          return text({ operation_id: op.operationId, decision: op.decision, state: op.state, reason_code: op.reasonCode, expires_at: op.expiresAt });
        } catch (e) {
          return failure(e);
        }
      },
    },
    {
      name: "palisec_explain_reason_code",
      description: "What a PALISEC reason code (PS_…) means and whether retrying later can help.",
      parameters: { type: "object", properties: { code: { type: "string", description: "For example PS_BUDGET_001" } }, required: ["code"], additionalProperties: false },
      async execute(input) {
        const code = String(input.code ?? "") as ReasonCode;
        return code in REASON_CODES ? text({ code, meaning: REASON_CODES[code], retryable: RETRYABLE[code] }) : text({ code, known: false });
      },
    },
  ];
  if (opts.wallet) {
    const wallet = opts.wallet;
    tools.splice(1, 0, {
      name: "palisec_send_transaction",
      description:
        "Send a transaction through PALISEC: it is authorized first and sent only if PALISEC allows it. Returns sent (with hash), held for human approval (with operation_id), or denied (with reason code). Never retry a denied transaction unchanged.",
      parameters: txSchema,
      async execute(input) {
        try {
          const { operation, hash } = await palisec.sendTransaction(wallet, intentFrom(input));
          return hash ? text({ status: "sent", hash, operation_id: operation.operationId }) : text({ status: "held_for_approval", operation_id: operation.operationId });
        } catch (e) {
          if (e instanceof PalisecDeniedError) return text({ status: "denied", code: e.code, message: e.message, retryable: e.retryable });
          return failure(e);
        }
      },
    });
  }
  return tools;
}
