"""Query connections preserve selected SQLite inputs, including recovery state."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "scripts"))
import naos_graph_context_query as graph  # noqa: E402
import naos_local_context_index as index  # noqa: E402
import naos_local_context_query as local  # noqa: E402

TIME = "2026-10-22T00:00:00Z"
MAGIC = bytes.fromhex("d9d505f920a163d7")


class SQLiteQueryReadSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="naos-query-read-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.path = self.inputs / "index ü #%.sqlite"
        self.artifact = {"artifact_id": "A1", "path": "src/example.py",
            "artifact_type": "source_code", "source_hash": "a" * 64,
            "profile_scope": ["quickstart"], "limitations": [],
            "authority_level": "source", "provenance": "synthetic test"}
        self.chunk = {"chunk_id": "C1", "artifact_id": "A1", "path": "src/example.py",
            "bounded_excerpt": "baselineword", "text_summary": "baselineword", "limitations": []}
        self.report = {"schema": "naos.local_context_index.v1", "generated_at": TIME,
            "profile": "quickstart", "status": "ready", "indexed_artifacts": [self.artifact],
            "artifact_chunks": [self.chunk], "artifact_links": [], "summary": {}}
        self.fts, _ = index.populate_sqlite_database(self.path, self.report,
            [self.artifact], [self.chunk], [])
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                connection.execute("CREATE TABLE spill(value BLOB)")
                connection.executemany("INSERT INTO spill VALUES (?)", [(bytes(4096),)] * 100)
        finally:
            connection.close()
        self.loaded = local.load_index_from_sqlite(self.path)
        self.baseline_bytes = self.path.read_bytes()

    def reset_database(self):
        for path in self.inputs.iterdir():
            path.unlink()
        self.path.write_bytes(self.baseline_bytes)

    def snapshot(self):
        result = {}
        for path in sorted(self.inputs.iterdir()):
            info = path.stat()
            result[path.name] = (hashlib.sha256(path.read_bytes()).hexdigest(), info.st_size,
                info.st_mode, info.st_mtime_ns, info.st_ino, info.st_nlink)
        return result

    def read(self, kind, *, path=None, word="baselineword"):
        path = self.path if path is None else path
        if kind == "graph":
            return graph.load_index_from_sqlite(path)
        if kind == "local":
            return local.load_index_from_sqlite(path)
        if not self.fts:
            self.skipTest("SQLite FTS5 unavailable")
        return local.query_index(args=local.build_parser().parse_args(["--query", word]),
            index_data=copy.deepcopy(self.loaded), index_report=self.report,
            sqlite_path=path, limit=5)

    def assert_word(self, kind, result, word):
        if kind == "fts":
            rows, modes, findings = result
            self.assertIn("fts_keyword_search", modes)
            self.assertNotIn("local_context_query.fts_fallback", {f["id"] for f in findings})
            self.assertEqual([row["bounded_excerpt"] for row in rows], [word])
        else:
            self.assertEqual([row["bounded_excerpt"] for row in result["chunks"]], [word])

    def crash_state(self, state):
        if state == "hot":
            script = """import os,sqlite3,sys
c=sqlite3.connect(sys.argv[1]);c.execute('PRAGMA cache_size=5');c.execute('BEGIN IMMEDIATE')
c.execute(\"UPDATE artifact_chunks SET bounded_excerpt='uncommittedword',text_summary='uncommittedword'\")
if c.execute(\"SELECT 1 FROM sqlite_master WHERE name='artifact_chunks_fts'\").fetchone():
 c.execute(\"UPDATE artifact_chunks_fts SET bounded_excerpt='uncommittedword',text_summary='uncommittedword'\")
c.execute('UPDATE spill SET value=randomblob(8192)');os._exit(0)
"""
        else:
            script = """import os,sqlite3,sys
c=sqlite3.connect(sys.argv[1]);c.execute('PRAGMA journal_mode=WAL')
c.execute(\"UPDATE artifact_chunks SET bounded_excerpt='committedword',text_summary='committedword'\")
if c.execute(\"SELECT 1 FROM sqlite_master WHERE name='artifact_chunks_fts'\").fetchone():
 c.execute(\"UPDATE artifact_chunks_fts SET bounded_excerpt='committedword',text_summary='committedword'\")
c.commit();os._exit(0)
"""
        result = subprocess.run([sys.executable, "-B", "-c", script, str(self.path)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        suffix = "-journal" if state == "hot" else "-wal"
        self.assertTrue(Path(str(self.path) + suffix).is_file())

    def test_normal_queries_preserve_input_bytes_modes_and_names(self):
        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                before = self.snapshot()
                self.assert_word(kind, self.read(kind), "baselineword")
                self.assertEqual(self.snapshot(), before)

    def test_missing_input_is_not_created_by_any_query_api(self):
        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                self.path.unlink(missing_ok=True)
                before = self.snapshot()
                if kind == "fts":
                    _, modes, findings = self.read(kind)
                    self.assertIn("metadata_text_fallback", modes)
                    self.assertIn("local_context_query.fts_fallback", {f["id"] for f in findings})
                else:
                    with self.assertRaises((OSError, ValueError, sqlite3.Error)):
                        self.read(kind)
                self.assertEqual(self.snapshot(), before)
                self.assertFalse(self.path.exists())

    def test_hot_single_database_recovery_preserves_source_and_committed_results(self):
        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                self.reset_database()
                self.crash_state("hot")
                before = self.snapshot()
                self.assert_word(kind, self.read(kind), "baselineword")
                self.assertEqual(self.snapshot(), before)

    def test_committed_wal_is_read_without_checkpointing_source(self):
        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                self.reset_database()
                self.crash_state("wal")
                before = self.snapshot()
                self.assert_word(kind, self.read(kind, word="committedword"), "committedword")
                self.assertEqual(self.snapshot(), before)

    def test_missing_shared_memory_is_not_created_beside_source(self):
        for shared_memory in ("missing", "zeroed"):
            for kind in ("graph", "local", "fts"):
                with self.subTest(kind=kind, shared_memory=shared_memory):
                    self.reset_database()
                    self.crash_state("wal")
                    shared = Path(str(self.path) + "-shm")
                    if shared_memory == "missing":
                        shared.unlink()
                    else:
                        shared.write_bytes(bytes(shared.stat().st_size))
                    before = self.snapshot()
                    self.assert_word(kind, self.read(kind, word="committedword"), "committedword")
                    self.assertEqual(self.snapshot(), before)

    def test_external_super_journal_reference_never_reaches_sqlite(self):
        victim = self.root / "external-keeper.txt"
        name = str(victim).encode("utf-8")
        checksum = sum(value if value < 128 else value - 256 for value in name) & 0xffffffff
        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                self.reset_database()
                self.crash_state("hot")
                victim.write_bytes(b"keep this synthetic file\n")
                journal = Path(str(self.path) + "-journal")
                with journal.open("ab") as stream:
                    stream.write(name + struct.pack(">II", len(name), checksum) + MAGIC)
                before = self.snapshot()
                if kind == "fts":
                    _, modes, findings = self.read(kind)
                    self.assertIn("metadata_text_fallback", modes)
                    self.assertTrue(any("super-journal" in f.get("message", "") for f in findings))
                else:
                    error = None
                    try:
                        self.read(kind)
                    except (OSError, ValueError, sqlite3.Error) as exc:
                        error = exc
                    self.assertTrue(victim.exists(), "query deleted the external synthetic keeper")
                    self.assertIsInstance(error, ValueError)
                    self.assertIn("super-journal", str(error))
                self.assertTrue(victim.exists())
                self.assertEqual(victim.read_bytes(), b"keep this synthetic file\n")
                self.assertEqual(self.snapshot(), before)

    @unittest.skipUnless(os.name == "posix", "POSIX readable input with owner-read-masking umask")
    def test_readable_read_only_input_and_umask_are_preserved(self):
        self.path.chmod(0o444)
        for mask in (0o400, 0o600, 0o577):
            for kind in ("graph", "local", "fts"):
                with self.subTest(mask=oct(mask), kind=kind):
                    before = self.snapshot()
                    previous = os.umask(mask)
                    try:
                        self.assert_word(kind, self.read(kind), "baselineword")
                        self.assertEqual(os.umask(mask), mask)
                    finally:
                        os.umask(previous)
                    self.assertEqual(self.snapshot(), before)

    def test_hardlinked_read_input_remains_supported(self):
        alias = self.inputs / "linked.sqlite"
        os.link(self.path, alias)
        before = self.snapshot()
        for kind in ("graph", "local", "fts"):
            self.assert_word(kind, self.read(kind, path=alias), "baselineword")
            self.assertEqual(self.snapshot(), before)

    @unittest.skipUnless(os.name == "posix", "POSIX recovery-file permissions")
    def test_unreadable_empty_recovery_files_remain_usable(self):
        for suffix in ("-journal", "-wal"):
            sidecar = Path(str(self.path) + suffix)
            sidecar.write_bytes(b"")
            sidecar.chmod(0)
            try:
                before = sidecar.stat()
                database = self.path.read_bytes()
                for kind in ("graph", "local", "fts"):
                    with self.subTest(suffix=suffix, kind=kind):
                        self.assert_word(kind, self.read(kind), "baselineword")
                        self.assertEqual(sidecar.stat(), before)
                        self.assertEqual(self.path.read_bytes(), database)
            finally:
                sidecar.chmod(0o600)
                sidecar.unlink()

    @unittest.skipUnless(os.name == "posix", "POSIX recovery-file permissions")
    def test_unreadable_nonempty_recovery_files_are_not_discarded(self):
        for state, suffix in (("hot", "-journal"), ("wal", "-wal")):
            self.reset_database()
            self.crash_state(state)
            sidecar = Path(str(self.path) + suffix)
            content = sidecar.read_bytes()
            sidecar.chmod(0)
            try:
                before = sidecar.stat()
                for kind in ("graph", "local", "fts"):
                    with self.subTest(state=state, kind=kind):
                        if kind == "fts":
                            _, modes, findings = self.read(kind)
                            self.assertIn("metadata_text_fallback", modes)
                            self.assertIn("local_context_query.fts_fallback", {f["id"] for f in findings})
                        else:
                            with self.assertRaises(PermissionError):
                                self.read(kind)
                        self.assertEqual(sidecar.stat(), before)
            finally:
                sidecar.chmod(0o600)
            self.assertEqual(sidecar.read_bytes(), content)

    @unittest.skipUnless(os.name == "posix", "POSIX writable/searchable temporary ancestor")
    def test_private_snapshot_accepts_search_only_temporary_ancestors(self):
        parent = self.root / "search-only-temp"
        parent.mkdir()
        parent.chmod(0o311)
        try:
            before = self.snapshot()
            with patch.object(local.tempfile, "tempdir", str(parent)):
                for kind in ("graph", "local", "fts"):
                    with self.subTest(kind=kind):
                        self.assert_word(kind, self.read(kind), "baselineword")
                        self.assertEqual(self.snapshot(), before)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o311)
        finally:
            parent.chmod(0o700)
        self.assertEqual(list(parent.iterdir()), [])

    def test_leaf_symlink_uses_the_selected_database_recovery_files(self):
        self.crash_state("wal")
        alias = self.root / "alias.sqlite"
        try:
            alias.symlink_to(self.path)
        except OSError as exc:
            self.skipTest(f"File symlink unavailable: {exc}")
        before = self.snapshot()
        for kind in ("graph", "local", "fts"):
            self.assert_word(kind, self.read(kind, path=alias, word="committedword"), "committedword")
            self.assertTrue(alias.is_symlink())
            self.assertEqual(self.snapshot(), before)

    def test_empty_or_malformed_database_keeps_existing_error_fallback(self):
        for raw in (b"", b"not a SQLite database"):
            for kind in ("graph", "local", "fts"):
                with self.subTest(kind=kind, raw=raw):
                    self.path.write_bytes(raw)
                    before = self.snapshot()
                    if kind == "fts":
                        _, modes, findings = self.read(kind)
                        self.assertIn("metadata_text_fallback", modes)
                        self.assertIn("local_context_query.fts_fallback", {f["id"] for f in findings})
                    else:
                        with self.assertRaises(sqlite3.Error):
                            self.read(kind)
                    self.assertEqual(self.snapshot(), before)

    def test_failed_snapshot_preserves_inputs_and_removes_private_workspace(self):
        created = []
        temporary_directory = tempfile.TemporaryDirectory
        copy_input = local._copy_sqlite_input

        def tracked(*args, **kwargs):
            workspace = temporary_directory(*args, **kwargs)
            created.append(Path(workspace.name))
            return workspace

        def fail_after_copy(*args, **kwargs):
            copy_input(*args, **kwargs)
            raise OSError("synthetic snapshot failure")

        before = self.snapshot()
        with patch.object(local.tempfile, "TemporaryDirectory", side_effect=tracked), \
                patch.object(local, "_copy_sqlite_input", side_effect=fail_after_copy):
            for kind in ("graph", "local", "fts"):
                with self.subTest(kind=kind):
                    if kind == "fts":
                        _, _, findings = self.read(kind)
                        self.assertTrue(any("synthetic snapshot failure" in f.get("message", "") for f in findings))
                    else:
                        with self.assertRaisesRegex(OSError, "synthetic snapshot failure"):
                            self.read(kind)
                    self.assertEqual(self.snapshot(), before)
        self.assertTrue(created)
        self.assertTrue(all(not path.exists() for path in created))

    def test_foreign_input_change_is_preserved_and_not_queried(self):
        copy_input = local._copy_sqlite_input

        def changed(source, target, expected):
            copy_input(source, target, expected)
            if source == self.path:
                self.path.write_bytes(self.path.read_bytes() + b"foreign edit")

        for kind in ("graph", "local", "fts"):
            with self.subTest(kind=kind):
                self.reset_database()
                with patch.object(local, "_copy_sqlite_input", side_effect=changed):
                    if kind == "fts":
                        _, modes, findings = self.read(kind)
                        self.assertIn("metadata_text_fallback", modes)
                        self.assertTrue(any("changed" in f.get("message", "") for f in findings))
                    else:
                        with self.assertRaisesRegex(ValueError, "changed"):
                            self.read(kind)
                self.assertTrue(self.path.read_bytes().endswith(b"foreign edit"))

    def test_directory_alias_is_readable_or_structurally_refused_on_windows(self):
        alias = self.root / "alias"
        try:
            alias.symlink_to(self.inputs, target_is_directory=True)
        except OSError as exc:
            if os.name != "nt" or getattr(exc, "winerror", None) != 1314:
                self.skipTest(f"Directory alias unavailable: {exc}")
            result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(alias), str(self.inputs)],
                capture_output=True, text=True)
            if result.returncode != 0:
                self.skipTest(f"Directory junction unavailable: {result.stderr}")
        before = self.snapshot()
        selected = alias / self.path.name
        try:
            graph.load_index_from_sqlite(selected)
        except (OSError, sqlite3.Error):
            if os.name != "nt":
                raise
            # Native Windows baseline also refuses this untrusted junction.
            # Check the public advisory contract rather than skipping the case.
            self.run_query_clis(selected, available=False)
            self.assertEqual(self.snapshot(), before)
            return
        for kind in ("graph", "local", "fts"):
            self.assert_word(kind, self.read(kind, path=selected), "baselineword")
            self.assertEqual(self.snapshot(), before)

    @unittest.skipIf(os.name == "nt", "Question mark is not a Windows filename character")
    def test_literal_uri_characters_are_not_interpreted_as_connection_options(self):
        alias = self.inputs / "input ?#% ü.sqlite"
        self.path.rename(alias)
        before = self.snapshot()
        for kind in ("graph", "local", "fts"):
            self.assert_word(kind, self.read(kind, path=alias), "baselineword")
            self.assertEqual(self.snapshot(), before)

    def run_query_clis(self, selected, *, available, word="baselineword"):
        project = self.root / "project"
        (project / "naos/reports").mkdir(parents=True, exist_ok=True)
        report_path = self.root / "index-report.json"
        report_path.write_text(json.dumps(self.report), encoding="utf-8")
        for script, query in (("naos_graph_context_query.py", ["--path", "src/example.py"]),
                              ("naos_local_context_query.py", ["--query", word])):
            with self.subTest(script=script):
                before = self.snapshot()
                result = subprocess.run([sys.executable, "-B", str(KIT / "scripts" / script),
                    "--profile", "quickstart", "--index-report", str(report_path),
                    "--sqlite", str(selected), "--output", str(self.root / (script + ".json")),
                    "--json", *query], cwd=project, capture_output=True, text=True,
                    timeout=30, env={**os.environ, "NAOS_FIXED_TIME": TIME, "PYTHONDONTWRITEBYTECODE": "1"})
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report["sqlite_artifact"]["available"], available)
                self.assertNotIn("Traceback", result.stdout + result.stderr)
                if not available:
                    expected = script.removeprefix("naos_").removesuffix(".py") + ".sqlite_unavailable"
                    self.assertIn(expected, {finding["id"] for finding in report["findings"]})
                self.assertEqual(self.snapshot(), before)

    def test_actual_query_clis_preserve_recoverable_inputs(self):
        self.crash_state("wal")
        self.run_query_clis(self.path, available=True, word="committedword")

    def test_input_metadata_failure_uses_existing_structured_fallback(self):
        project = self.root / "project"
        (project / "naos/reports").mkdir(parents=True)
        report_path = self.root / "index-report.json"
        report_path.write_text(json.dumps(self.report), encoding="utf-8")
        exists = Path.exists

        def unreadable(path):
            if path == self.path:
                raise OSError("synthetic input metadata unavailable")
            return exists(path)

        before = self.snapshot()
        for module, query in ((graph, ["--path", "src/example.py"]),
                              (local, ["--query", "baselineword"])):
            with self.subTest(module=module.__name__):
                args = module.build_parser().parse_args([
                    "--index-report", str(report_path), "--sqlite", str(self.path), *query])
                with patch.object(Path, "exists", new=unreadable):
                    report = module.build_report(project, "naos", "quickstart", {}, args)
                self.assertFalse(report["sqlite_artifact"]["available"])
                expected = module.__name__.removeprefix("naos_") + ".sqlite_unavailable"
                self.assertIn(expected, {finding["id"] for finding in report["findings"]})
                self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
