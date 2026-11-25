import { PalisecConfigError } from "./errors";
import type { SendingWallet } from "./client";
import { SUPPORTED_CHAINS, type Address, type Hex, type SupportedChainId } from "./types";

/** The parts of an ethers v6 Signer the adapter uses. No ethers import: any compatible signer works. */
export interface EthersSigner {
  getAddress(): Promise<string>;
  sendTransaction(tx: { to: string; value?: bigint; data?: string; gasLimit?: bigint; chainId?: bigint }): Promise<{ hash: string }>;
  provider?: { getNetwork(): Promise<{ chainId: bigint | number }> } | null;
}

/**
 * Adapts an ethers v6 signer for `palisec.sendTransaction`. Checks the signer's network up front
 * when it has a provider, and pins `chainId` on every transaction so ethers refuses a mismatch.
 *
 *   const wallet = await fromEthers(new Wallet(process.env.AGENT_KEY!, provider));
 *   await palisec.sendTransaction(wallet, intent);
 */
export async function fromEthers(signer: EthersSigner, opts: { chainId?: SupportedChainId } = {}): Promise<SendingWallet> {
  const chainId = opts.chainId ?? 46630;
  if (!(SUPPORTED_CHAINS as readonly number[]).includes(chainId)) throw new PalisecConfigError(`chainId ${chainId} is not supported`);
  const address = await signer.getAddress();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new PalisecConfigError("The signer has no valid address");
  if (signer.provider) {
    const network = await signer.provider.getNetwork();
    if (Number(network.chainId) !== chainId)
      throw new PalisecConfigError(`The signer's provider is on chain ${network.chainId}, but Palisec authorizes chain ${chainId}`);
  }
  return {
    account: { address: address as Address },
    chain: { id: chainId },
    async sendTransaction({ to, value, data, gas }) {
      const res = await signer.sendTransaction({
        to,
        value: value ?? 0n,
        data: data ?? "0x",
        ...(gas !== undefined ? { gasLimit: gas } : {}),
        chainId: BigInt(chainId),
      });
      return res.hash as Hex;
    },
  };
}
