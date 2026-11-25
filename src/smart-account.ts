import type { Address, Hex } from "./types";

/** The unsigned user operation PALISEC prepared (EntryPoint v0.7, Safe 4337 module). Quantities are hex. */
export interface PreparedUserOperation {
  sender: Address;
  nonce: Hex;
  callData: Hex;
  callGasLimit: Hex;
  verificationGasLimit: Hex;
  preVerificationGas: Hex;
  maxFeePerGas: Hex;
  maxPriorityFeePerGas: Hex;
  validAfter: number;
  validUntil: number;
}

export interface PreparedExecution {
  operationId: string;
  safeOpHash: Hex;
  userOperation: PreparedUserOperation;
  /** The most the operation can cost the smart account in gas, in wei. */
  maxCostWei: bigint;
  validUntil: Date;
  /** Typed data with integers as strings, as returned by the API (for eth_signTypedData_v4). */
  typedDataJson: Record<string, unknown>;
}

export type ExecutionState = "not_prepared" | "prepared" | "submitted" | "executed" | "reverted";

export interface Execution {
  operationId: string;
  status: ExecutionState;
  userOpHash: Hex | null;
  transactionHash: Hex | null;
  submittedAt: Date | null;
  executedAt: Date | null;
}

/** Anything that can sign EIP-712 typed data with the agent's key: a viem LocalAccount or WalletClient account. */
export interface TypedDataSigner {
  address?: Address;
  signTypedData(args: {
    domain: { chainId: number; verifyingContract: Address };
    types: typeof SAFE_OP_TYPES;
    primaryType: "SafeOp";
    message: Record<string, unknown>;
  }): Promise<Hex>;
}

const ENTRY_POINT_V07: Address = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const SAFE_4337_MODULE: Address = "0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226";

export const SAFE_OP_TYPES = {
  SafeOp: [
    { name: "safe", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "initCode", type: "bytes" },
    { name: "callData", type: "bytes" },
    { name: "verificationGasLimit", type: "uint128" },
    { name: "callGasLimit", type: "uint128" },
    { name: "preVerificationGas", type: "uint256" },
    { name: "maxPriorityFeePerGas", type: "uint128" },
    { name: "maxFeePerGas", type: "uint128" },
    { name: "paymasterAndData", type: "bytes" },
    { name: "validAfter", type: "uint48" },
    { name: "validUntil", type: "uint48" },
    { name: "entryPoint", type: "address" },
  ],
} as const;

/** The exact EIP-712 data the agent signs: PALISEC co-signs the same hash, and the Safe checks both. */
export function safeOpTypedData(op: PreparedUserOperation, chainId: number) {
  return {
    domain: { chainId, verifyingContract: SAFE_4337_MODULE },
    types: SAFE_OP_TYPES,
    primaryType: "SafeOp" as const,
    message: {
      safe: op.sender,
      nonce: BigInt(op.nonce),
      initCode: "0x" as Hex,
      callData: op.callData,
      verificationGasLimit: BigInt(op.verificationGasLimit),
      callGasLimit: BigInt(op.callGasLimit),
      preVerificationGas: BigInt(op.preVerificationGas),
      maxPriorityFeePerGas: BigInt(op.maxPriorityFeePerGas),
      maxFeePerGas: BigInt(op.maxFeePerGas),
      paymasterAndData: "0x" as Hex,
      validAfter: op.validAfter,
      validUntil: op.validUntil,
      entryPoint: ENTRY_POINT_V07,
    },
  };
}
