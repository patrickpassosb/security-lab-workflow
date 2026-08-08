"""Tests for lib/staticreview.py + bin/lab-static-review — the source-review
scaffold (inventory -> sink grep -> reachability -> report).

Covers:
  - inventory: language grouping, line counts, entry-point detection,
    skip dirs, symlink refusal
  - sink grep: per-language sink patterns
  - reachability: entry-point files reachable, imported files reachable,
    unrelated files not reachable
  - report rendering: candidates-first ordering, notes
  - CLI: help, missing dir, report written to --out, audit entry

All tests run against synthetic source trees in tmp_path. No network.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labutil  # noqa: E402
import staticreview as SR  # noqa: E402

BIN_DIR = HERE.parent / "bin"


def _import_cli(name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(BIN_DIR / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


lab_static_review = _import_cli("lab-static-review")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A synthetic source tree:
    src/app.py        — entry point (main) with a command-exec sink
    src/helper.py     — imported by app.py, with a subprocess sink
    src/unused.py     — not imported, with a sink
    vendor/third.py   — skipped dir, with a sink
    """
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "vendor").mkdir()
    (root / "src" / "app.py").write_text(
        "import os\n"
        "import helper\n"
        "\n"
        "def main():\n"
        '    os.system("ls")\n'
        "\n"
        'if __name__ == "__main__":\n'
        "    main()\n",
        encoding="utf-8",
    )
    (root / "src" / "helper.py").write_text(
        "import subprocess\n"
        "\n"
        "def run():\n"
        '    subprocess.run("id", shell=True)\n',
        encoding="utf-8",
    )
    (root / "src" / "unused.py").write_text(
        "import os\n"
        "\n"
        "def nope():\n"
        '    os.popen("ls")\n',
        encoding="utf-8",
    )
    (root / "vendor" / "third.py").write_text(
        'import os\nos.system("x")\n',
        encoding="utf-8",
    )
    return root


# ─── Inventory ────────────────────────────────────────────────────────────────


class TestInventory:
    def test_counts_files_and_lines(self, tree):
        inv = SR.inventory(tree)
        assert len(inv["files"]) == 3  # vendor/ skipped
        langs = {f["lang"] for f in inv["files"]}
        assert langs == {"python"}
        by_lang = inv["by_lang"]["python"]
        assert by_lang["files"] == 3

    def test_entry_points_detected(self, tree):
        inv = SR.inventory(tree)
        eps = {e["path"] for e in inv["entry_points"]}
        assert "src/app.py" in eps
        assert "src/helper.py" not in eps

    def test_skip_dirs(self, tree):
        inv = SR.inventory(tree)
        paths = {f["path"] for f in inv["files"]}
        assert not any("vendor" in p for p in paths)

    def test_symlinked_file_skipped(self, tmp_path):
        root = tmp_path / "t"
        root.mkdir()
        real = tmp_path / "real.py"
        real.write_text("import os\n", encoding="utf-8")
        (root / "link.py").symlink_to(real)
        inv = SR.inventory(root)
        assert inv["files"] == []

    def test_missing_dir_raises(self, tmp_path):
        with pytest.raises(SR.StaticReviewError):
            SR.inventory(tmp_path / "nope")


# ─── Sink grep ────────────────────────────────────────────────────────────────


class TestSinkGrep:
    def test_finds_sinks(self, tree):
        hits = SR.sink_grep(tree)
        paths = {h["path"] for h in hits}
        assert "src/app.py" in paths
        assert "src/helper.py" in paths
        assert "src/unused.py" in paths
        assert not any("vendor" in h["path"] for h in hits)

    def test_sink_names(self, tree):
        hits = SR.sink_grep(tree)
        sinks = {h["sink"] for h in hits}
        assert "command-exec" in sinks

    def test_js_sinks(self, tmp_path):
        root = tmp_path / "js"
        root.mkdir()
        (root / "app.js").write_text(
            "const { exec } = require('child_process');\n"
            "exec('ls');\n",
            encoding="utf-8",
        )
        hits = SR.sink_grep(root)
        assert any(h["sink"] == "command-exec" for h in hits)


# ─── Reachability ────────────────────────────────────────────────────────────


class TestReachability:
    def test_entry_point_reachable(self, tree):
        inv = SR.inventory(tree)
        hits = SR.sink_grep(tree)
        annotated = SR.reachability(inv, hits)
        by_path = {h["path"]: h for h in annotated}
        assert by_path["src/app.py"]["reachable"] is True
        assert "entry-point" in by_path["src/app.py"]["via"]

    def test_imported_file_reachable(self, tree):
        inv = SR.inventory(tree)
        hits = SR.sink_grep(tree)
        annotated = SR.reachability(inv, hits)
        by_path = {h["path"]: h for h in annotated}
        assert by_path["src/helper.py"]["reachable"] is True
        assert "imported" in by_path["src/helper.py"]["via"]

    def test_unrelated_file_not_reachable(self, tree):
        inv = SR.inventory(tree)
        hits = SR.sink_grep(tree)
        annotated = SR.reachability(inv, hits)
        by_path = {h["path"]: h for h in annotated}
        assert by_path["src/unused.py"]["reachable"] is False


# ─── Report ──────────────────────────────────────────────────────────────────


class TestReport:
    def test_report_sections(self, tree):
        inv = SR.inventory(tree)
        hits = SR.reachability(inv, SR.sink_grep(tree))
        report = SR.render_report(inv, hits)
        assert "Static review (scaffold)" in report
        assert "## Inventory (by language)" in report
        assert "## Entry points" in report
        assert "## Sink hits (reachable" in report
        assert "## Sink hits (not reachable" in report
        assert "never verdicts" in report

    def test_reachable_listed_first(self, tree):
        inv = SR.inventory(tree)
        hits = SR.reachability(inv, SR.sink_grep(tree))
        report = SR.render_report(inv, hits)
        reachable_idx = report.index("## Sink hits (reachable")
        unreachable_idx = report.index("## Sink hits (not reachable")
        assert reachable_idx < unreachable_idx


# ─── Orchestration ────────────────────────────────────────────────────────────


class TestRunStaticReview:
    def test_full_pipeline(self, tree):
        result = SR.run_static_review(tree)
        assert "inventory" in result
        assert "hits" in result
        assert "report" in result
        assert result["report"].startswith("# Static review")


# ─── CLI ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    log_path = tmp_path / "findings" / ".agent-audit.jsonl"
    monkeypatch.setattr(labutil, "LAB", tmp_path)
    monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
    monkeypatch.setenv("HACKING_LAB", str(tmp_path))
    monkeypatch.setenv("USER", "lab-static-review-test-agent")
    return tmp_path


def _run(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["lab-static-review", *args])
    return lab_static_review.main()


class TestLabStaticReviewCli:
    def test_help(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, "--help")
        out = capsys.readouterr().out
        assert rc == 0
        assert "lab-static-review" in out

    def test_missing_dir_errors(self, capsys, cli_env, monkeypatch):
        # No args -> prints usage/help and exits 0 (help is a valid result,
        # matching the lab-verify CLI convention).
        rc = _run(monkeypatch)
        assert rc == 0

    def test_dir_not_found(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, str(cli_env / "nope"))
        assert rc == 1

    def test_writes_report(self, capsys, cli_env, monkeypatch, tree):
        out_path = cli_env / "STATIC_REVIEW.md"
        rc = _run(monkeypatch, str(tree), "--out", str(out_path))
        assert rc == 0
        assert out_path.is_file()
        assert "Static review (scaffold)" in out_path.read_text(encoding="utf-8")

    def test_audit_entry(self, capsys, cli_env, monkeypatch, tree):
        _run(monkeypatch, str(tree))
        log = cli_env / "findings" / ".agent-audit.jsonl"
        entry = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        assert entry["action"] == "lab-static-review"
        assert entry["exit"] == 0
        assert "sink_hits=" in entry["detail"]


# ─── TypeScript coverage ─────────────────────────────────────────────────────
# The scaffold ships dedicated TS sinks, entry points, and import
# resolution: child_process in CJS+ESM forms, fs sync/promises,
# process.env, Deno APIs, node shebangs / import.meta.main / Deno.serve
# entry points, and bare-specifier import handling.

@pytest.fixture
def ts_tree(tmp_path: Path) -> Path:
    """A synthetic TypeScript tree:
    src/server.ts         — entry point (express + process.argv) with sinks
    src/helpers/util.ts   — imported via './helpers/util', has a sink
    src/unused.ts         — not imported, has a sink
    out/bundle.ts         — build output (skipped)
    """
    root = tmp_path / "ts"
    (root / "src" / "helpers").mkdir(parents=True)
    (root / "out").mkdir()
    (root / "src" / "server.ts").write_text(
        "#!/usr/bin/env node\n"
        "import express from 'express';\n"
        "import { exec } from 'child_process';\n"
        "import { readFileSync } from 'fs';\n"
        "import { util } from './helpers/util';\n"
        "const app = express();\n"
        "const key = process.env.API_KEY;\n"
        "app.get('/run', (req, res) => {\n"
        "  exec(`ls ${req.query.cmd}`);\n"
        "  res.send(readFileSync('/etc/passwd', 'utf8'));\n"
        "  util();\n"
        "});\n",
        encoding="utf-8",
    )
    (root / "src" / "helpers" / "util.ts").write_text(
        "import { spawn } from 'child_process';\n"
        "export function util() { spawn('id'); }\n",
        encoding="utf-8",
    )
    (root / "src" / "unused.ts").write_text(
        "import { writeFileSync } from 'fs';\n"
        "export function nope() { writeFileSync('/tmp/x', 'y'); }\n",
        encoding="utf-8",
    )
    (root / "out" / "bundle.ts").write_text(
        "import { exec } from 'child_process';\nexec('rm -rf /');\n",
        encoding="utf-8",
    )
    return root


class TestTypeScriptInventory:
    def test_counts_ts_files_and_skips_out(self, ts_tree):
        inv = SR.inventory(ts_tree)
        paths = {f["path"] for f in inv["files"]}
        assert paths == {
            "src/server.ts",
            "src/helpers/util.ts",
            "src/unused.ts",
        }
        assert all(f["lang"] == "typescript" for f in inv["files"])

    def test_ts_entry_points_detected(self, ts_tree):
        inv = SR.inventory(ts_tree)
        eps = {e["path"] for e in inv["entry_points"]}
        assert "src/server.ts" in eps  # shebang + process.argv + express
        assert "src/helpers/util.ts" not in eps

    def test_node_shebang_entry_point(self, tmp_path):
        root = tmp_path / "cli"
        root.mkdir()
        (root / "cli.ts").write_text("#!/usr/bin/env node\nconsole.log(1);\n", encoding="utf-8")
        inv = SR.inventory(root)
        assert any(e["path"] == "cli.ts" for e in inv["entry_points"])

    def test_deno_entry_points(self, tmp_path):
        root = tmp_path / "deno"
        root.mkdir()
        (root / "mod.ts").write_text(
            "if (import.meta.main) { Deno.serve({ port: 8000 }, handler); }\n",
            encoding="utf-8",
        )
        inv = SR.inventory(root)
        kinds = {e["kind"] for e in inv["entry_points"] if e["path"] == "mod.ts"}
        assert "main" in kinds


class TestTypeScriptSinks:
    def test_esm_child_process_import_sink(self, ts_tree):
        hits = SR.sink_grep(ts_tree)
        by_path: dict[str, list[dict]] = {}
        for h in hits:
            by_path.setdefault(h["path"], []).append(h)
        sinks = {h["sink"] for h in by_path.get("src/server.ts", [])}
        assert "command-exec" in sinks
        assert "env-read" in sinks
        assert "path-traversal" in sinks

    def test_imported_helper_sink_found(self, ts_tree):
        hits = SR.sink_grep(ts_tree)
        by_path: dict[str, list[dict]] = {}
        for h in hits:
            by_path.setdefault(h["path"], []).append(h)
        assert any(h["sink"] == "command-exec" for h in by_path.get("src/helpers/util.ts", []))

    def test_out_dir_skipped_in_sink_grep(self, ts_tree):
        hits = SR.sink_grep(ts_tree)
        assert not any("out/" in h["path"] for h in hits)

    def test_file_write_sink(self, ts_tree):
        hits = SR.sink_grep(ts_tree)
        by_path: dict[str, list[dict]] = {}
        for h in hits:
            by_path.setdefault(h["path"], []).append(h)
        assert any(
            h["sink"] == "file-write" for h in by_path.get("src/unused.ts", [])
        )

    def test_deno_sink(self, tmp_path):
        root = tmp_path / "deno"
        root.mkdir()
        (root / "mod.ts").write_text(
            "const p = Deno.run({ cmd: ['sh', '-c', 'id'] });\n",
            encoding="utf-8",
        )
        hits = SR.sink_grep(root)
        assert any(h["sink"] == "deno" for h in hits)

    def test_js_sinks_unchanged(self, tmp_path):
        # JS keeps its own table; TS additions must not leak into JS.
        root = tmp_path / "js"
        root.mkdir()
        (root / "a.js").write_text("process.env.KEY;\n", encoding="utf-8")
        hits = SR.sink_grep(root)
        assert not any(h["sink"] == "env-read" for h in hits)


class TestTypeScriptReachability:
    def test_relative_import_resolves(self, ts_tree):
        inv = SR.inventory(ts_tree)
        hits = SR.sink_grep(ts_tree)
        annotated = SR.reachability(inv, hits)
        by_path = {h["path"]: h for h in annotated}
        assert by_path["src/server.ts"]["reachable"] is True
        assert by_path["src/helpers/util.ts"]["reachable"] is True
        assert by_path["src/unused.ts"]["reachable"] is False

    def test_bare_specifier_never_matches_tree_file(self, tmp_path):
        # 'child_process' is a bare package specifier; a file named
        # child_process.ts in the tree must NOT be considered imported.
        root = tmp_path / "tree"
        root.mkdir()
        (root / "main.ts").write_text(
            "#!/usr/bin/env node\n"
            "import { exec } from 'child_process';\n"
            "exec('x');\n",
            encoding="utf-8",
        )
        (root / "child_process.ts").write_text(
            "import { spawn } from 'child_process';\n"
            "export const x = spawn('id');\n",
            encoding="utf-8",
        )
        inv = SR.inventory(root)
        hits = SR.sink_grep(root)
        annotated = SR.reachability(inv, hits)
        cp = [h for h in annotated if h["path"] == "child_process.ts"]
        # The decoy file has sink hits but is NOT reachable: the bare
        # specifier resolves to node_modules, never to a tree file.
        assert cp and cp[0]["reachable"] is False

    def test_node_prefix_specifier_never_matches(self, tmp_path):
        root = tmp_path / "tree"
        root.mkdir()
        (root / "main.ts").write_text(
            "#!/usr/bin/env node\n"
            "import { readFileSync } from 'node:fs';\n"
            "readFileSync('/etc/x');\n",
            encoding="utf-8",
        )
        (root / "fs.ts").write_text(
            "import { writeFileSync } from 'fs';\n"
            "export const x = writeFileSync('/tmp/a', 'b');\n",
            encoding="utf-8",
        )
        inv = SR.inventory(root)
        hits = SR.sink_grep(root)
        annotated = SR.reachability(inv, hits)
        fs_hit = [h for h in annotated if h["path"] == "fs.ts"]
        assert fs_hit and fs_hit[0]["reachable"] is False

    def test_extension_import_matches_stem(self, tmp_path):
        root = tmp_path / "tree"
        root.mkdir()
        (root / "main.ts").write_text(
            "#!/usr/bin/env node\n"
            "import { h } from './helpers/util.ts';\n"
            "h();\n",
            encoding="utf-8",
        )
        (root / "helpers").mkdir()
        (root / "helpers" / "util.ts").write_text(
            "import { spawn } from 'child_process';\n"
            "export function h() { spawn('x'); }\n",
            encoding="utf-8",
        )
        inv = SR.inventory(root)
        hits = SR.sink_grep(root)
        annotated = SR.reachability(inv, hits)
        util = [h for h in annotated if h["path"] == "helpers/util.ts"]
        assert util and util[0]["reachable"] is True


class TestReportByClass:
    def test_by_class_section_present(self, tree):
        inv = SR.inventory(tree)
        hits = SR.reachability(inv, SR.sink_grep(tree))
        report = SR.render_report(inv, hits)
        assert "## Sink hits by class (all files)" in report
        assert "command-exec:" in report

    def test_ts_caveats_note_present(self, tree):
        inv = SR.inventory(tree)
        hits = SR.reachability(inv, SR.sink_grep(tree))
        report = SR.render_report(inv, hits)
        assert "bare package specifiers" in report
