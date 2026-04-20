"""LangChain agent with Signet compliance receipts.

Every tool call produces an Ed25519-signed receipt appended to the
hash-chained audit log at ~/.signet/audit/. All signing and audit IO is
local — only the LLM inference itself calls OpenAI.

Prerequisites:
    signet identity generate --name demo-bot --unencrypted
    pip install signet-auth[langchain] langchain langchain-openai
    export OPENAI_API_KEY="sk-..."
"""

from __future__ import annotations

import ast
import operator as _op
import os

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from signet_auth import SigningAgent
from signet_auth.langchain import SignetCallbackHandler


# ─── Tools ───────────────────────────────────────────────────────────────────

@tool
def search(query: str) -> str:
    """Search the web for information."""
    # Stubbed — a real tool would call an external API here
    return f"Results for '{query}': (stubbed)"


# Safe AST-based arithmetic. Avoids eval() so this file is safe to copy as a template.
_BIN_OPS = {ast.Add: _op.add, ast.Sub: _op.sub, ast.Mult: _op.mul, ast.Div: _op.truediv}
_UNARY_OPS = {ast.UAdd: _op.pos, ast.USub: _op.neg}


def _safe_eval(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError(f"disallowed expression node: {type(node).__name__}")


@tool
def calculator(expression: str) -> str:
    """Evaluate a mathematical expression, e.g. '2 + 2 * 3'."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"invalid expression: {expression!r}") from exc
    return str(_safe_eval(tree.body))


# ─── Signet setup ────────────────────────────────────────────────────────────

# Load the agent's signing key (generated via `signet identity generate`).
# The key lives at ~/.signet/keys/demo-bot.key; audit log at ~/.signet/audit/.
signer = SigningAgent("demo-bot")

# Attach the Signet callback handler. Every on_tool_start / on_tool_end /
# on_tool_error LangChain event produces a signed receipt.
signet_handler = SignetCallbackHandler(signer, target="langchain://demo")


# ─── LangChain agent ─────────────────────────────────────────────────────────

def build_agent() -> AgentExecutor:
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    tools = [search, calculator]

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful agent. Use the tools when needed."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)


def main() -> None:
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: set OPENAI_API_KEY before running this example")
        raise SystemExit(1)

    executor = build_agent()

    # The prompt asks for both tools, but tool selection is up to the LLM —
    # the receipt count below reflects what actually ran, not what was requested.
    result = executor.invoke(
        {"input": "What is 142 * 37, and search for the word 'signet'?"},
        config={"callbacks": [signet_handler]},
    )
    print("\n=== Agent result ===")
    print(result["output"])

    # Every tool call produced a receipt. Show the audit trail from this run.
    print(f"\n=== {len(signet_handler.receipts)} receipts produced ===")
    for receipt in signet_handler.receipts:
        print(f"  {receipt.id}  {receipt.action.tool}  {receipt.ts}")

    print("\nAudit log at ~/.signet/audit/  (verify with: signet audit --verify)")


if __name__ == "__main__":
    main()
