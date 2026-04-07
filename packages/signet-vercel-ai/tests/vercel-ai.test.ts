import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { generateKeypair, verify } from "@signet-auth/core";
import { createSignetCallbacks } from "../src/index.js";

describe("@signet-auth/vercel-ai", () => {
  it("signs a tool call", () => {
    const { secretKey, publicKey } = generateKeypair();
    const callbacks = createSignetCallbacks(secretKey, "test-agent");

    callbacks.experimental_onToolCallStart({
      toolCallId: "call_1",
      toolName: "search",
      args: { query: "signet" },
    });

    assert.equal(callbacks.receipts.length, 1);
    assert.equal(callbacks.receipts[0].toolName, "search");
    assert.equal(callbacks.receipts[0].toolCallId, "call_1");
    assert.ok(verify(callbacks.receipts[0].receipt, publicKey));
  });

  it("tracks duration on finish", () => {
    const { secretKey } = generateKeypair();
    const callbacks = createSignetCallbacks(secretKey, "test-agent");

    callbacks.experimental_onToolCallStart({
      toolCallId: "call_2",
      toolName: "calc",
      args: { expr: "1+1" },
    });

    callbacks.experimental_onToolCallFinish({
      toolCallId: "call_2",
      toolName: "calc",
      result: { value: 2 },
      durationMs: 42,
    });

    assert.equal(callbacks.receipts[0].durationMs, 42);
  });

  it("signs multiple tool calls", () => {
    const { secretKey } = generateKeypair();
    const callbacks = createSignetCallbacks(secretKey, "bot");

    for (const name of ["a", "b", "c"]) {
      callbacks.experimental_onToolCallStart({
        toolCallId: `call_${name}`,
        toolName: name,
        args: {},
      });
    }

    assert.equal(callbacks.receipts.length, 3);
    assert.deepEqual(
      callbacks.receipts.map((r) => r.toolName),
      ["a", "b", "c"],
    );
  });

  it("uses custom target", () => {
    const { secretKey } = generateKeypair();
    const callbacks = createSignetCallbacks(secretKey, "bot", {
      target: "custom://target",
    });

    callbacks.experimental_onToolCallStart({
      toolCallId: "call_x",
      toolName: "echo",
      args: { msg: "hi" },
    });

    const receipt = callbacks.receipts[0].receipt;
    assert.equal((receipt as any).action.target, "custom://target");
  });

  it("never throws on signing failure", () => {
    // Empty secret key should fail internally but not throw
    const callbacks = createSignetCallbacks("", "bad");

    assert.doesNotThrow(() => {
      callbacks.experimental_onToolCallStart({
        toolCallId: "x",
        toolName: "y",
        args: {},
      });
    });
    assert.equal(callbacks.receipts.length, 0);
  });
});
