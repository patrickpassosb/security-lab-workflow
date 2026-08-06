"""staticreview — source-review scaffold: inventory -> sink grep -> reachability -> report.

A deterministic, no-LLM first pass over a source tree before any manual or
agentic review. Four stages:

  1. inventory   — walk the tree, group files by language, count lines, and
                   find entry points (main(), handlers, route decorators).
  2. sink grep   — scan for dangerous sinks (command execution, SQL, eval,
                   deserialization, path traversal, file writes) per language.
  3. reachability— for each sink hit, decide whether it is reachable from an
                   entry point: same file as an entry point, or the file is
                   imported (directly or transitively) by an entry-point file.
  4. report      — render a markdown report (findings table + per-sink
                   detail) that a reviewer or the lab's finding-evaluation
                   loop consumes.

This is a SCAFFOLD: the sink patterns and entry-point heuristics are
deliberately small and conservative. It performs no network I/O and no
subprocess execution. All inputs are data; output is a ranked worklist, never
a verdict (the lab's verification gates decide verdicts).

The module is pure except for reading the source tree the caller points it at.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# ─── Constants ───────────────────────────────────────────────────────────────

# Language detection by file extension (deterministic, conservative).
_LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
}

# Sink patterns per language: (name, regex). The regex is applied to each
# line; a hit records the line number and the matched text. Patterns are
# deliberately broad (scaffold) — the reviewer triages.
_SINKS: dict[str, list[tuple[str, str]]] = {
    "python": [
        (
            "command-exec",
            r"\b(os\.system|subprocess\.(run|call|Popen|check_output)|os\.popen)\s*\(",
        ),
        ("eval", r"\b(eval|exec|compile)\s*\("),
        ("sql", r"\b(execute|executemany|raw\(|query)\s*\("),
        ("deserialize", r"\b(pickle\.loads|yaml\.load|json\.loads)\s*\("),
        ("path-traversal", r"\b(open|Path|os\.path\.join)\s*\("),
        ("file-write", r"\b(write|writelines|open)\s*\([^)]*['\"]w"),
    ],
    "javascript": [
        ("command-exec", r"\b(child_process\.(exec|execSync|spawn|spawnSync)|exec\(|eval\()"),
        ("eval", r"\beval\s*\("),
        ("sql", r"\b(query|execute|raw)\s*\("),
        ("deserialize", r"\b(JSON\.parse|eval)\s*\("),
        ("path-traversal", r"\b(fs\.(readFile|writeFile|createReadStream)|path\.join)\s*\("),
    ],
    "typescript": [
        ("command-exec", r"\b(child_process\.(exec|execSync|spawn|spawnSync)|exec\(|eval\()"),
        ("eval", r"\beval\s*\("),
        ("sql", r"\b(query|execute|raw)\s*\("),
        ("deserialize", r"\b(JSON\.parse|eval)\s*\("),
        ("path-traversal", r"\b(fs\.(readFile|writeFile|createReadStream)|path\.join)\s*\("),
    ],
    "go": [
        ("command-exec", r"\b(os/exec\.(Command|CommandContext)|exec\.Command)\s*\("),
        ("sql", r"\b(db\.(Query|QueryRow|Exec)|\.Query\()"),
        ("deserialize", r"\b(json\.Unmarshal|yaml\.Unmarshal|gob\.Decode)\s*\("),
        ("path-traversal", r"\b(os\.(Open|Create|ReadFile|WriteFile)|filepath\.Join)\s*\("),
    ],
    "java": [
        ("command-exec", r"\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("),
        ("sql", r"\b(executeQuery|executeUpdate|createStatement|prepareStatement)\s*\("),
        ("deserialize", r"\b(ObjectInputStream|readObject)\s*\("),
        ("path-traversal", r"\b(new File\(|Files\.(read|write|newInputStream))\s*\("),
    ],
    "ruby": [
        ("command-exec", r"\b(system|`|IO\.popen|Open3\.)\s*\("),
        ("eval", r"\b(eval|instance_eval|class_eval)\s*\("),
        ("sql", r"\b(execute|exec_query|find_by_sql)\s*\("),
        ("deserialize", r"\b(Marshal\.load|YAML\.load)\s*\("),
    ],
    "php": [
        ("command-exec", r"\b(system|exec|shell_exec|passthru|popen)\s*\("),
        ("eval", r"\b(eval)\s*\("),
        ("sql", r"\b(mysqli?_query|->query|->exec|PDO::)\s*\("),
        ("deserialize", r"\b(unserialize)\s*\("),
    ],
    "shell": [
        ("command-exec", r"\b(eval|exec)\s+"),
        ("path-traversal", r"\b(cat|rm|cp|mv|>)\s+"),
    ],
    "c": [
        ("command-exec", r"\b(system|popen|execl|execv)\s*\("),
        ("unsafe-memory", r"\b(strcpy|strcat|sprintf|gets|scanf)\s*\("),
        ("path-traversal", r"\b(fopen|open)\s*\("),
    ],
    "cpp": [
        ("command-exec", r"\b(system|popen|execl|execv)\s*\("),
        ("unsafe-memory", r"\b(strcpy|strcat|sprintf|gets|scanf)\s*\("),
        ("path-traversal", r"\b(fopen|open|ifstream|ofstream)\s*\("),
    ],
    "rust": [
        ("command-exec", r"\b(Command::new|std::process::Command)\s*\("),
        ("unsafe", r"\bunsafe\s*\{"),
        ("path-traversal", r"\b(File::open|fs::(read|write|read_to_string))\s*\("),
    ],
}

# Entry-point heuristics per language: (name, regex). A file whose content
# matches any of these is an entry point (a place execution can start).
_ENTRY_POINTS: dict[str, list[tuple[str, str]]] = {
    "python": [
        ("main", r"^\s*(if __name__\s*==\s*['\"]__main__['\"]|def main\s*\()"),
        ("framework", r"^\s*(from|import)\s+(flask|django|fastapi|aiohttp|bottle|tornado)"),
        ("handler", r"^\s*@(app|router)\.(route|get|post|put|delete|patch)\s*\("),
    ],
    "javascript": [
        ("main", r"\b(module\.exports|exports\.|app\.(get|post|put|delete|listen)\s*\()"),
        ("framework", r"\brequire\(['\"](express|fastify|koa|http)['\"]\)"),
    ],
    "typescript": [
        ("main", r"\b(export\s+(default|function|const)|app\.(get|post|put|delete|listen)\s*\()"),
        ("framework", r"\b(from\s+['\"](express|fastify|koa|http)['\"])"),
    ],
    "go": [
        ("main", r"^\s*func\s+main\s*\("),
        ("handler", r"^\s*func\s+.*(Handler|ServeHTTP)\s*\("),
    ],
    "java": [
        ("main", r"^\s*public\s+static\s+void\s+main\s*\("),
        ("handler", r"^\s*@(GetMapping|PostMapping|RequestMapping|PutMapping|DeleteMapping)"),
    ],
    "ruby": [
        ("main", r"^\s*(get|post|put|delete|patch)\s+['\"]/"),
        ("framework", r"^\s*(require|require_relative)\s+['\"](sinatra|rails)"),
    ],
    "php": [
        ("main", r"^\s*<\?php"),
        ("handler", r"^\s*(function|class)\s+.*(Controller|Action)"),
    ],
    "shell": [
        ("main", r"^\s*(#!/|set\s+-e|main\s*\(\))"),
    ],
    "c": [
        ("main", r"^\s*int\s+main\s*\("),
    ],
    "cpp": [
        ("main", r"^\s*int\s+main\s*\("),
    ],
    "rust": [
        ("main", r"^\s*fn\s+main\s*\("),
    ],
}

# Directories always skipped (vendored/third-party noise).
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".venv", "venv", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "target",
    "coverage", ".next", ".nuxt",
})

# ─── Errors ──────────────────────────────────────────────────────────────────


class StaticReviewError(Exception):
    """Base error for the static-review module."""


# ─── Stage 1: inventory ──────────────────────────────────────────────────────


def _lang_for(path: Path) -> str:
    return _LANG_BY_EXT.get(path.suffix.lower(), "")


def inventory(root: Path) -> dict[str, Any]:
    """Walk `root` and produce the inventory.

    Returns a dict:
        {
          "root": str,
          "files": [{"path": str, "lang": str, "lines": int}],
          "by_lang": {lang: {"files": int, "lines": int}},
          "entry_points": [{"path": str, "lang": str, "kind": str, "line": int}],
        }

    Files with an unknown extension are skipped. Symlinked files/dirs are
    skipped (defense-in-depth — never follow links out of the tree).
    """
    root = Path(root)
    if not root.is_dir():
        raise StaticReviewError(f"not a directory: {root}")
    files: list[dict[str, Any]] = []
    entry_points: list[dict[str, Any]] = []
    by_lang: dict[str, dict[str, int]] = {}

    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not (dirpath / d).is_symlink()
        )
        for fname in sorted(filenames):
            fpath = dirpath / fname
            if fpath.is_symlink():
                continue
            lang = _lang_for(fpath)
            if not lang:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            rel = str(fpath.relative_to(root))
            files.append({"path": rel, "lang": lang, "lines": lines})
            agg = by_lang.setdefault(lang, {"files": 0, "lines": 0})
            agg["files"] += 1
            agg["lines"] += lines
            for kind, pattern in _ENTRY_POINTS.get(lang, []):
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if re.search(pattern, line):
                        entry_points.append(
                            {"path": rel, "lang": lang, "kind": kind, "line": lineno}
                        )
                        break

    return {
        "root": str(root),
        "files": files,
        "by_lang": by_lang,
        "entry_points": entry_points,
    }


# ─── Stage 2: sink grep ───────────────────────────────────────────────────────


def _sink_hits_for_file(fpath: Path, lang: str) -> list[dict[str, Any]]:
    """Scan one file for sink patterns. Returns a list of hit dicts:
    {"path", "lang", "sink", "line", "text"}."""
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    hits: list[dict[str, Any]] = []
    for sink_name, pattern in _SINKS.get(lang, []):
        for lineno, line in enumerate(text.splitlines(), start=1):
            if re.search(pattern, line):
                hits.append({
                    "path": str(fpath),
                    "lang": lang,
                    "sink": sink_name,
                    "line": lineno,
                    "text": line.strip()[:200],
                })
    return hits


def sink_grep(root: Path) -> list[dict[str, Any]]:
    """Scan every inventoried file for sink patterns.

    Returns a flat list of hit dicts (see _sink_hits_for_file) with paths
    RELATIVE to `root` (consistent with inventory()). The scan is per-file
    and deterministic; hits are NOT deduplicated here (the report groups
    them).
    """
    root = Path(root)
    hits: list[dict[str, Any]] = []
    for dirpath, dirnames, filenames in root.walk():
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not (dirpath / d).is_symlink()
        )
        for fname in sorted(filenames):
            fpath = dirpath / fname
            if fpath.is_symlink():
                continue
            lang = _lang_for(fpath)
            if not lang:
                continue
            for hit in _sink_hits_for_file(fpath, lang):
                hit["path"] = str(fpath.relative_to(root))
                hits.append(hit)
    return hits


# ─── Stage 3: reachability ────────────────────────────────────────────────────


def _imports_of(fpath: Path, lang: str) -> list[str]:
    """Extract the module names a file imports (best-effort, per language).

    Returns a list of import targets (module names / relative paths). Used
    for the reachability heuristic — a sink file is reachable when an
    entry-point file imports it (directly or transitively).
    """
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    if lang == "python":
        for m in re.finditer(
            r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", text, re.M
        ):
            out.append(m.group(1) or m.group(2))
    elif lang in ("javascript", "typescript"):
        for m in re.finditer(r"(?:require\(['\"]|from\s+['\"])([^'\"]+)['\"]", text):
            out.append(m.group(1))
    elif lang == "go":
        for m in re.finditer(r"^\s*\"([\w./-]+)\"", text, re.M):
            out.append(m.group(1))
    elif lang == "java":
        for m in re.finditer(r"^\s*import\s+([\w.]+)", text, re.M):
            out.append(m.group(1))
    elif lang == "ruby":
        for m in re.finditer(r"^\s*(?:require|require_relative)\s+['\"]([^'\"]+)['\"]", text, re.M):
            out.append(m.group(1))
    elif lang == "php":
        for m in re.finditer(
            r"^\s*(?:require|require_once|include|include_once)\s*\(?['\"]([^'\"]+)['\"]",
            text,
            re.M,
        ):
            out.append(m.group(1))
    return out


def _file_matches_import(rel_path: str, import_target: str) -> bool:
    """Heuristic: does `rel_path` correspond to `import_target`?

    Matches when the import target's last component appears in the path
    (e.g. import "auth" matches "src/auth.py" / "auth/index.js"), or the
    path stem equals the target's last component. Conservative on purpose —
    a miss only downgrades reachability, never upgrades it.
    """
    stem = Path(rel_path).stem
    last = import_target.rstrip("/").split("/")[-1]
    if last in ("", "."):
        return False
    if stem == last:
        return True
    return last in rel_path.replace("\\", "/").split("/")


def reachability(
    inv: dict[str, Any],
    hits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Annotate each sink hit with a reachability verdict.

    A hit is `reachable` when:
      - its file is itself an entry point (same file), OR
      - an entry-point file imports its file (directly or transitively).

    The import graph is built from the inventoried files (imports are
    resolved against the tree; unknown imports are ignored). Returns the
    hits with an added "reachable": bool and "via": str field.
    """
    root = Path(inv["root"])
    entry_files = {e["path"] for e in inv["entry_points"]}

    # Build the import graph: rel_path -> set of rel_paths it imports.
    imports: dict[str, set[str]] = {}
    for f in inv["files"]:
        fpath = root / f["path"]
        targets = _imports_of(fpath, f["lang"])
        resolved: set[str] = set()
        for t in targets:
            for other in inv["files"]:
                if other["path"] != f["path"] and _file_matches_import(other["path"], t):
                    resolved.add(other["path"])
        imports[f["path"]] = resolved

    # Transitive closure from entry points (BFS).
    reachable_files: set[str] = set(entry_files)
    frontier = list(entry_files)
    while frontier:
        cur = frontier.pop()
        for nxt in imports.get(cur, ()):
            if nxt not in reachable_files:
                reachable_files.add(nxt)
                frontier.append(nxt)

    out: list[dict[str, Any]] = []
    for hit in hits:
        rel = hit["path"]
        if rel in reachable_files:
            via = "entry-point file" if rel in entry_files else "imported by entry point"
            out.append({**hit, "reachable": True, "via": via})
        else:
            out.append({**hit, "reachable": False, "via": "not reachable from entry points"})
    return out


# ─── Stage 4: report ──────────────────────────────────────────────────────────


def render_report(
    inv: dict[str, Any],
    hits: list[dict[str, Any]],
) -> str:
    """Render the markdown report from the inventory + annotated sink hits.

    The report is a worklist, not a verdict: reachable sinks are listed
    first (they are the review priority), then unreachable ones. The lab's
    verification gates decide whether any of this is a real finding.
    """
    lines: list[str] = [
        "# Static review (scaffold)",
        "",
        f"- root: `{inv['root']}`",
        f"- files: {len(inv['files'])} | entry points: {len(inv['entry_points'])}",
        "",
        "## Inventory (by language)",
        "",
        "| language | files | lines |",
        "|---|---|---|",
    ]
    for lang in sorted(inv["by_lang"]):
        agg = inv["by_lang"][lang]
        lines.append(f"| {lang} | {agg['files']} | {agg['lines']} |")
    lines.append("")

    lines.append("## Entry points")
    lines.append("")
    if not inv["entry_points"]:
        lines.append("(none found)")
    for e in inv["entry_points"]:
        lines.append(f"- `{e['path']}:{e['line']}` — {e['kind']} ({e['lang']})")
    lines.append("")

    reachable = [h for h in hits if h.get("reachable")]
    unreachable = [h for h in hits if not h.get("reachable")]

    lines.append("## Sink hits (reachable — review priority)")
    lines.append("")
    if not reachable:
        lines.append("(none)")
    for h in reachable:
        lines.append(
            f"- `{h['path']}:{h['line']}` — {h['sink']} ({h['lang']}) — {h['via']}"
        )
        lines.append("  ```")
        lines.append(f"  {h['text']}")
        lines.append("  ```")
    lines.append("")

    lines.append("## Sink hits (not reachable from entry points)")
    lines.append("")
    if not unreachable:
        lines.append("(none)")
    for h in unreachable:
        lines.append(f"- `{h['path']}:{h['line']}` — {h['sink']} ({h['lang']})")
    lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append(
        "- This is a scaffold: sink patterns and entry-point heuristics are "
        "conservative and language-specific."
    )
    lines.append(
        "- Reachability is a heuristic (import-name matching), not a call "
        "graph. Confirm manually before treating a hit as exploitable."
    )
    lines.append(
        "- Sink hits are hypotheses, never verdicts — the lab's verification "
        "gates (lab-verify / lab-verify-findings) decide."
    )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ─── Orchestration ──────────────────────────────────────────────────────────


def run_static_review(root: Path) -> dict[str, Any]:
    """Run the full scaffold: inventory -> sink grep -> reachability.

    Returns {"inventory": ..., "hits": [...], "report": str}. The report is
    also written to <root>/STATIC_REVIEW.md by the CLI.
    """
    inv = inventory(root)
    hits = sink_grep(root)
    annotated = reachability(inv, hits)
    report = render_report(inv, annotated)
    return {"inventory": inv, "hits": annotated, "report": report}


# ─── __all__ ─────────────────────────────────────────────────────────────────

__all__ = [
    "StaticReviewError",
    "inventory",
    "sink_grep",
    "reachability",
    "render_report",
    "run_static_review",
]
