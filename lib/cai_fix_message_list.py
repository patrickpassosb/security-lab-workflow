"""cai_fix_message_list — deterministic replacement for CAI's
`cai.util.fix_message_list` (upstream defect, cai-framework 0.5.10).

Why this exists
---------------
CAI's own `fix_message_list` (cai/util.py) has an infinite-loop defect on
multi-tool turns: its second pass moves a tool result to sit right after
its assistant message, but when an assistant message carries TWO OR MORE
tool calls, moving the first result displaces the second result, which is
then moved back — ping-ponging forever. The lab's live runs hit this on
the very first turn (the agent issues 2 parallel `curl` calls), so the
LLM loop spins until the wall-clock budget kills it and NO tool results
ever flow. Verified live 2026-08-07 on xben-037 (run
run-20260807T192444Z-d2e1bf2f: assistant_message with 2 tool_calls, then
nothing).

This module provides a single-pass, deterministic reimplementation with
the same observable contract (see the docstring of the original):

  1. tool-call ids are truncated to 40 chars (provider compatibility)
  2. empty user messages are dropped; empty system messages become ""
  3. every tool result is paired with a preceding assistant message that
     carries the matching tool_call_id (synthesized with
     `unknown_function` when missing)
  4. every assistant tool_call gets a tool result (synthesized
     "Auto-generated response for <name>" when missing)
  5. tool results with empty content get "Tool response for <id>"
  6. non-tool messages never carry None content

Unlike the original it is O(n) and cannot loop: results are placed in a
single forward pass, each tool result is placed at most once, and
duplicate results are dropped (the OpenAI API rejects a tool_call_id
appearing more than once anyway).

How it is loaded
----------------
The lab's adapter (lib/labcai.py) injects this module into the sandboxed
CAI process via a `sitecustomize.py` shim on PYTHONPATH (see
`labcai._cai_shim_dir`). The shim replaces `cai.util.fix_message_list`
with `cai_fix_message_list.fix_message_list` at interpreter startup,
before any CAI module imports it. The venv itself is never modified.
"""

from __future__ import annotations

from typing import Any

# Sentinel for "no pending assistant" lookups.
_MISSING = object()


def _truncate_id(tool_id: str) -> str:
    return tool_id[:40] if len(tool_id) > 40 else tool_id


def _tool_ids(assistant_msg: dict[str, Any]) -> list[str]:
    """The (truncated) tool-call ids carried by an assistant message."""
    ids: list[str] = []
    for tc in assistant_msg.get("tool_calls") or []:
        tid = tc.get("id")
        if tid:
            ids.append(_truncate_id(tid))
    return ids


def _synthetic_assistant(tool_id: str) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": tool_id,
                "type": "function",
                "function": {"name": "unknown_function", "arguments": "{}"},
            }
        ],
    }


def fix_message_list(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sanitize a message list for the OpenAI chat-completions API.

    Deterministic single-pass reimplementation of CAI's
    `cai.util.fix_message_list` that cannot loop (see module docstring).
    Never mutates the input.
    """
    # Pass 0: deep-copy + truncate tool ids (both sides of each pair).
    sanitized: list[dict[str, Any]] = []
    for msg in messages:
        msg_copy = msg.copy()
        if msg_copy.get("role") == "tool" and msg_copy.get("tool_call_id"):
            msg_copy["tool_call_id"] = _truncate_id(str(msg_copy["tool_call_id"]))
        if msg_copy.get("role") == "assistant" and msg_copy.get("tool_calls"):
            tcs = []
            for tc in msg_copy["tool_calls"]:
                tc_copy = tc.copy()
                if tc_copy.get("id"):
                    tc_copy["id"] = _truncate_id(str(tc_copy["id"]))
                tcs.append(tc_copy)
            msg_copy["tool_calls"] = tcs
        sanitized.append(msg_copy)

    # Pass 1: drop empty user messages; empty system messages become "".
    kept: list[dict[str, Any]] = []
    for msg in sanitized:
        role = msg.get("role")
        if role in ("user", "system") and (
            msg.get("content") is None or not str(msg.get("content", "")).strip()
        ):
            if role == "system":
                msg["content"] = ""
                kept.append(msg)
            continue
        kept.append(msg)

    # Pass 2: single forward pass pairing tool results with their
    # assistant messages. `pending` maps tool_call_id -> the assistant
    # message object that issued it (results are placed right after it).
    out: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    placed: set[str] = set()

    def _insert_after(assistant_msg: dict[str, Any], tool_msg: dict[str, Any]) -> None:
        """Insert tool_msg immediately after assistant_msg in `out`."""
        idx = out.index(assistant_msg)
        # Keep results for the same assistant contiguous: insert after
        # any results already placed for it.
        while idx + 1 < len(out) and out[idx + 1].get("role") == "tool":
            idx += 1
        out.insert(idx + 1, tool_msg)

    for msg in kept:
        role = msg.get("role")
        if role == "assistant" and msg.get("tool_calls"):
            out.append(msg)
            for tid in _tool_ids(msg):
                pending.setdefault(tid, msg)
        elif role == "tool" and msg.get("tool_call_id"):
            tid = msg["tool_call_id"]
            if tid in placed:
                # Duplicate result for an already-paired call: drop it
                # (the API rejects repeated tool_call_ids).
                continue
            owner = pending.get(tid, _MISSING)
            if owner is _MISSING:
                # Orphan result: synthesize a matching assistant first.
                synth = _synthetic_assistant(tid)
                out.append(synth)
                out.append(msg)
            else:
                _insert_after(owner, msg)
            placed.add(tid)
        else:
            out.append(msg)

    # Pass 3: every assistant tool_call must have a result.
    for msg in out:
        if msg.get("role") != "assistant" or not msg.get("tool_calls"):
            continue
        for tid in _tool_ids(msg):
            if tid not in placed:
                tool_name = "unknown_function"
                for tc in msg["tool_calls"]:
                    if tc.get("id") == tid and tc.get("function"):
                        tool_name = tc["function"].get("name", "unknown_function")
                        break
                _insert_after(
                    msg,
                    {
                        "role": "tool",
                        "tool_call_id": tid,
                        "content": f"Auto-generated response for {tool_name}",
                    },
                )
                placed.add(tid)

    # Pass 4: content normalization (non-tool messages never None; tool
    # results never empty).
    for msg in out:
        role = msg.get("role")
        if role == "tool":
            if msg.get("content") is None or str(msg.get("content", "")).strip() == "":
                msg["content"] = f"Tool response for {msg.get('tool_call_id', 'unknown')}"
        elif (role != "assistant" or not msg.get("tool_calls")) and msg.get("content") is None:
            msg["content"] = ""
    return out
