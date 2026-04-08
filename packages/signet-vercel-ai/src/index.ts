/**
 * Signet signing callbacks for Vercel AI SDK.
 *
 * Usage:
 *   import { generateText } from "ai";
 *   import { createSignetCallbacks } from "@signet-auth/vercel-ai";
 *   import { generateKeypair } from "@signet-auth/core";
 *
 *   const { secretKey } = generateKeypair();
 *   const callbacks = createSignetCallbacks(secretKey, "my-agent");
 *
 *   const result = await generateText({
 *     model: openai("gpt-4"),
 *     tools: { myTool },
 *     ...callbacks,
 *     prompt: "...",
 *   });
 *
 *   console.log(callbacks.receipts);  // all signed receipts
 */

import { sign, contentHash, type SignetReceipt } from "@signet-auth/core";

/** A signed receipt from a tool call. */
export interface ToolCallReceipt {
  toolName: string;
  toolCallId: string;
  receipt: SignetReceipt;
  durationMs?: number;
}

/** Options for createSignetCallbacks. */
export interface SignetCallbackOptions {
  /** Target URI for receipts (default: "vercel-ai://local"). */
  target?: string;
  /** Whether to include tool args hash in the receipt (default: true). */
  hashArgs?: boolean;
  /** Custom warning logger. Defaults to console.warn. Set to `() => {}` to silence. */
  onWarn?: (message: string, error: unknown) => void;
}

/**
 * Create Vercel AI SDK callbacks that sign every tool call with Signet.
 *
 * Returns an object with:
 * - `experimental_onToolCallStart` — signs tool call before execution
 * - `experimental_onToolCallFinish` — records completion with duration
 * - `receipts` — array of all signed receipts
 */
export function createSignetCallbacks(
  secretKey: string,
  signerName: string,
  options: SignetCallbackOptions & { signerOwner?: string } = {},
) {
  const signerOwner = options.signerOwner ?? "";
  const target = options.target ?? "vercel-ai://local";
  const hashArgs = options.hashArgs ?? true;
  const warn = options.onWarn ?? ((msg: string, err: unknown) => console.warn(msg, err));
  const receipts: ToolCallReceipt[] = [];

  return {
    receipts,

    experimental_onToolCallStart({
      toolCallId,
      toolName,
      args,
    }: {
      toolCallId: string;
      toolName: string;
      args: unknown;
    }) {
      try {
        const action = {
          tool: toolName,
          params: args,
          params_hash: hashArgs && args != null ? contentHash(args) : contentHash({}),
          target,
          transport: "vercel-ai",
        };
        const receipt = sign(secretKey, action, signerName, signerOwner);
        receipts.push({ toolName, toolCallId, receipt });
      } catch (err) {
        // Never block tool execution, but log for debugging
        warn("[signet] Failed to sign tool call:", err);
      }
    },

    experimental_onToolCallFinish({
      toolCallId,
      toolName,
      result,
      durationMs,
    }: {
      toolCallId: string;
      toolName: string;
      result: unknown;
      durationMs?: number;
    }) {
      // Update the matching receipt with duration
      const entry = receipts.find(
        (r) => r.toolCallId === toolCallId && r.toolName === toolName,
      );
      if (entry) {
        entry.durationMs = durationMs;
      }
    },
  };
}
