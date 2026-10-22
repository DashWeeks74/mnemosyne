#!/usr/bin/env python3
"""Regression suite for Mnemosyne captures + connectors (captures spec, 2026-09-26).

A capture is a small markdown file with `kind: capture` frontmatter and authored, typed links
(`applies_to`) to other memories. This suite pins the parser grammar, the invalid-capture contract
(degrade VISIBLY, never lose the prose), duplicate-id ownership, link resolution, forget, secret
redaction of every stored capture field, and the three --json surfaces.

MUTATION CONTROL (standing acceptance criterion, same discipline as test_redaction.py): section [8]
re-runs its secret assertions with the capture-field redaction neutered and REQUIRES them to fail. If
that control ever passes, section [8] has stopped testing the thing it exists to test.

Runs against a THROWAWAY database - MNEMOSYNE_DB / MNEMOSYNE_LOG_DIR are redirected before import.

Run with the install's own venv, from the Mnemosyne folder (it needs hooks\\secret-rules.txt beside
mnemosyne.py):
    .venv\\Scripts\\python.exe test_captures.py        (Windows)
    .venv/bin/python test_captures.py                   (Mac/Linux - Windows-only sections need Windows)
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time

_TMP = tempfile.mkdtemp(prefix="mnemo-cap-test-")
os.environ["MNEMOSYNE_DB"] = os.path.join(_TMP, "test.db")        # MUST precede the import
os.environ["MNEMOSYNE_LOG_DIR"] = os.path.join(_TMP, "logs")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mnemosyne as M                                             # noqa: E402

FAILS = []


def check(cond, label):
    print("  %s  %s" % ("PASS" if cond else "FAIL", label))
    if not cond:
        FAILS.append(label)
    return cond


def _secret(seed="s", n=40):
    """Deterministic credential-shaped token, built at runtime (never a literal in this file)."""
    import hashlib
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    out, h = [], hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        for b in h:
            out.append(alphabet[b % len(alphabet)])
            if len(out) >= n:
                break
        h = hashlib.sha256(h).digest()
    return "".join(out)


def _write(path, body, newline="\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline=newline) as fh:
        fh.write(body)
    return path


class _Args(object):
    def __init__(self, **kw):
        self.path = None
        self.project = None
        self.allow_governed = False
        self.watch = False
        self.json = False
        self.lexical = True
        self.k = 6
        self.n = 10
        self.open_only = False
        self.expect_chunks = None
        self.__dict__.update(kw)


def _ingest(path, project):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = M.cmd_ingest(_Args(path=path, project=project))
    return rc, buf.getvalue()


def _run_json(fn, **kw):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(_Args(json=True, **kw))
    out = buf.getvalue()
    try:
        doc = json.loads(out)
    except ValueError:
        doc = None
    return rc, out, doc


def _q(sql, args=()):
    con = M.connect()
    try:
        return list(con.execute(sql, args))
    finally:
        con.close()


def _cap(cid, what="a thing we did", extra=""):
    return "---\nkind: capture\nid: %s\nwhat: %s\n%s---\nBody prose for %s.\n" % (cid, what, extra, cid)


# --------------------------------------------------------------------------------------------
# 1. Parser - valid, sparse, YAML-trap values, quotes, unknown keys
# --------------------------------------------------------------------------------------------
def test_parser():
    print("\n[1] parser")
    d = os.path.join(_TMP, "p")
    full = ("---\nkind: capture\nid: ups-alert-routing\ndate: 2026-09-26\n"
            "what: \"Route UPS alerts via Telegram\"\noutcome: no\nstatus: open\nsource: /home/x/notes.md\n"
            "flavor: ignored\napplies_to:\n  - voice-assistant-intake: like\n  - telegram-routing: depends-on\n"
            "  - lab-subnet-migration\n---\nprose\n")
    cap, err = M.parse_capture(full, d, time.time())
    check(err is None and cap is not None, "full capture parses (err=%r)" % (err,))
    if cap:
        check(cap["what"] == "Route UPS alerts via Telegram", "surrounding quotes stripped")
        check(cap["outcome"] == "no", "`outcome: no` stays the STRING 'no' (YAML would make it False)")
        check(cap["status"] == "open" and cap["date"] == "2026-09-26", "status/date kept")
        check(cap["links"] == [("voice-assistant-intake", "like"), ("telegram-routing", "depends-on"),
                               ("lab-subnet-migration", "applies-to")], "links + default relation")
    sparse, err = M.parse_capture("---\nkind: capture\nid: tiny\nwhat: x\n---\n", d, 0)
    check(err is None and sparse and sparse["outcome"] is None and sparse["links"] == []
          and sparse["status"] == "filed", "sparse capture is fully valid (outcome None, no links, filed)")
    nul, err = M.parse_capture("---\nkind: capture\nid: n1\nwhat: x\noutcome: null\n---\n", d, 0)
    check(err is None and nul["outcome"] is None, "`outcome: null` is legal and means None")
    crlf, err = M.parse_capture(full.replace("\n", "\r\n"), d, 0)
    check(err is None and crlf and len(crlf["links"]) == 3, "CRLF capture parses identically")
    bom, err = M.parse_capture("\ufeff" + full, d, 0)
    check(err is None and bom is not None, "leading BOM tolerated")


# --------------------------------------------------------------------------------------------
# 2. Invalid captures + 3. not-a-capture
# --------------------------------------------------------------------------------------------
def test_invalid_and_not_capture():
    print("\n[2] invalid captures  /  [3] not-a-capture")
    d = os.path.join(_TMP, "p")
    bad = {
        "missing id":        "---\nkind: capture\nwhat: x\n---\n",
        "bad id chars":      "---\nkind: capture\nid: Bad_ID\nwhat: x\n---\n",
        "missing what":      "---\nkind: capture\nid: a1\n---\n",
        "unknown relation":  "---\nkind: capture\nid: a2\nwhat: x\napplies_to:\n  - b1: resembles\n---\n",
        "unknown status":    "---\nkind: capture\nid: a3\nwhat: x\nstatus: maybe\n---\n",
        "duplicate key":     "---\nkind: capture\nid: a4\nwhat: x\nwhat: y\n---\n",
        "bad date":          "---\nkind: capture\nid: a5\nwhat: x\ndate: 2026-13-45\n---\n",
        "inline list":       "---\nkind: capture\nid: a6\nwhat: x\napplies_to: [b1, b2]\n---\n",
        "secret-shaped id":  "---\nkind: capture\nid: %s\nwhat: x\n---\n" % "-".join(
            "ups alert telegram routing decision for lab server power".split()),
    }
    for label, text in bad.items():
        cap, err = M.parse_capture(text, d, 0)
        check(cap is None and bool(err), "invalid: %s -> %r" % (label, err))
    cap, err = M.parse_capture("---\nkind: capture\nid: a7\nwhat: x\napplies_to:\n  - C:\\x\\y.md#A: B\n---\n", d, 0)
    check(cap is None and err and "applies-to" in err,
          "a heading containing ': ' without a relation errors and TELLS you to add ': applies-to'")
    for label, text in {"no kind":        "---\nid: a8\nwhat: x\n---\n",
                        "other kind":     "---\nkind: note\nid: a9\nwhat: x\n---\n",
                        "unclosed":       "---\nkind: capture\nid: b0\nwhat: x\n" + "line\n" * 70,
                        "no frontmatter": "# Heading\nkind: capture\n"}.items():
        cap, err = M.parse_capture(text, d, 0)
        check(cap is None and err is None, "not a capture, not an error: %s" % label)

    # end to end: an invalid capture is STILL stored as prose, flagged, with no capture row
    root = os.path.join(_TMP, "inv")
    _write(os.path.join(root, "broken.md"),
           "---\nkind: capture\nid: broken-one\nwhat: keep this prose zanzibar\nstatus: maybe\n---\nbody\n")
    rc, out = _ingest(root, "inv")
    check(rc == 0, "ingest of an invalid capture still exits 0")
    check("CAPTURE-INVALID" in out, "ingest prints a CAPTURE-INVALID warning")
    check(any("zanzibar" in (r[0] or "") for r in _q("SELECT text FROM chunks WHERE project='inv'")),
          "invalid capture's content is STILL stored as prose (nothing lost)")
    check(not _q("SELECT id FROM captures WHERE id='broken-one'"), "no capture row for an invalid capture")
    notes = _q("SELECT note FROM files WHERE project='inv'")
    check(notes and (notes[0][0] or "").startswith("CAPTURE-INVALID"), "files.note records CAPTURE-INVALID")


# --------------------------------------------------------------------------------------------
# 4. Item grammar + target normalization
# --------------------------------------------------------------------------------------------
def test_item_grammar():
    print("\n[4] item grammar + target normalization")
    base = os.path.join(_TMP, "caps")
    nc = lambda p: os.path.normcase(os.path.abspath(p))  # noqa: E731
    cases = [
        ("C:\\a\\b.md#H: supersedes", (nc("C:\\a\\b.md") + "#H", "supersedes")),
        ("C:\\a\\b.md",               (nc("C:\\a\\b.md"), "applies-to")),
        ("C:\\x#A: B: like",          (nc("C:\\x") + "#A: B", "like")),
        ("notes.md#Alerting: like",   (nc(os.path.join(base, "notes.md")) + "#Alerting", "like")),
        ("../other/n.md",             (nc(os.path.join(base, "..", "other", "n.md")), "applies-to")),
        ("/mnt/c/Project/x.md: depends-on", (nc("C:\\Project\\x.md"), "depends-on")),
        ("voice-assistant-intake: blocked-by",     ("voice-assistant-intake", "blocked-by")),
    ]
    for item, want in cases:
        got = M._parse_link_item(item, base)
        check(got == want, "item %r -> %r (got %r)" % (item, want, got))
    check(M._parse_link_item("x: resembles", base)[0] is None, "unknown relation -> error tuple")


# --------------------------------------------------------------------------------------------
# 5. Duplicate id  6. resolution  7. re-ingest + forget
# --------------------------------------------------------------------------------------------
def test_ids_links_forget():
    print("\n[5] duplicate id  /  [6] resolution  /  [7] re-ingest + forget")
    root = os.path.join(_TMP, "g")
    a = _write(os.path.join(root, "a.md"), _cap("dup-id", "first owner"))
    _write(os.path.join(root, "b.md"), _cap("dup-id", "second claimant"))
    rc, out = _ingest(root, "g")
    rows = _q("SELECT source_path FROM captures WHERE id='dup-id'")
    check(len(rows) == 1 and os.path.normcase(rows[0][0]) == os.path.normcase(a),
          "same-run duplicate: first by SORTED path wins (a.md)")
    check("duplicate id" in out, "the loser is reported as a duplicate")
    os.remove(a)
    b = os.path.join(root, "b.md")
    _write(b, _cap("dup-id", "second claimant, edited"))
    _ingest(root, "g")
    rows = _q("SELECT source_path, what FROM captures WHERE id='dup-id'")
    check(len(rows) == 1 and os.path.normcase(rows[0][0]) == os.path.normcase(b),
          "owner file gone -> the claimant takes the id over")

    # resolution
    r2 = os.path.join(_TMP, "r")
    _write(os.path.join(r2, "doc.md"), "# Top\n\n## Alerting\n\nAlerting prose long enough to be a chunk here.\n")
    _write(os.path.join(r2, "hub.md"), _cap("hub", "the hub", "applies_to:\n  - spoke-one: like\n"
                                              "  - doc.md#Alerting: supersedes\n  - ghost-target\n"))
    _ingest(r2, "r")
    con = M.connect()
    try:
        res = {t: M._resolve_target(con, t)[0] for (t,) in con.execute("SELECT target FROM links WHERE src_id='hub'")}
    finally:
        con.close()
    check(sum(res.values()) == 1, "path#anchor resolves on breadcrumb suffix; slugs dangle (%r)" % res)
    _write(os.path.join(r2, "spoke.md"), _cap("spoke-one", "the spoke"))
    _ingest(r2, "r")
    con = M.connect()
    try:
        ok = M._resolve_target(con, "spoke-one")[0]
    finally:
        con.close()
    check(ok, "a later-ingested capture resolves an earlier dangling link WITHOUT re-ingesting the source")
    rc, out, doc = _run_json(M.cmd_status)
    check(doc is not None and any(x["target"] == "ghost-target" for x in doc.get("dangling", [])),
          "status --json lists the dangling link")

    # re-ingest replaces links
    _write(os.path.join(r2, "hub.md"), _cap("hub", "the hub v2", "applies_to:\n  - spoke-one: like\n"))
    _ingest(r2, "r")
    check(len(_q("SELECT * FROM links WHERE src_id='hub'")) == 1, "re-ingest after edit REPLACES links")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_forget(_Args(path=os.path.join(r2, "hub.md"), project=None))
    check(not _q("SELECT * FROM captures WHERE id='hub'") and not _q("SELECT * FROM links WHERE src_id='hub'"),
          "forget --path removes the capture and its links")
    with contextlib.redirect_stdout(buf):
        M.cmd_forget(_Args(project="r", path=None, expect_chunks=_nchunks("r")))
    check(not _q("SELECT * FROM captures WHERE project='r'"), "forget --project removes that project's captures")


def test_forget_both_flags():
    """forget --project X --path P used to IGNORE --path and delete ALL of project X at rc=0 (it wiped a
    2,311-chunk project live, 2026-10-02). Both flags together must now be refused before anything is
    touched; each flag alone must keep its exact meaning."""
    print("\n[7b] forget refuses --project and --path together")
    root = os.path.join(_TMP, "fb-both")    # NOT "fb": section [12] ingests the parent _TMP\fb
    keep = _write(os.path.join(root, "keep.md"), "# Keep\n\nThis document must survive a refused forget, intact.\n")
    gone = _write(os.path.join(root, "gone.md"), "# Gone\n\nThis document is the one a path-only forget removes.\n")
    _ingest(root, "fb")
    n0 = len(_q("SELECT id FROM chunks WHERE project='fb'"))
    check(n0 >= 2, "setup: both documents indexed in project fb (%d chunks)" % n0)
    for label, proj in (("--project fb", "fb"), ('--project ""', "")):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = M.cmd_forget(_Args(project=proj, path=gone))
        check(rc == 2 and "Nothing forgotten" in buf.getvalue(), "%s --path P is REFUSED at rc=2 (rc=%r)" % (label, rc))
        check(len(_q("SELECT id FROM chunks WHERE project='fb'")) == n0, "%s --path P deletes NOTHING" % label)
    # the real command line, so argparse -> main() -> sys.exit carries the refusal as the process exit code
    import subprocess
    p = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "mnemosyne.py"),
                        "forget", "--project", "fb", "--path", gone], capture_output=True, text=True,
                       encoding="utf-8", env=dict(os.environ))
    check(p.returncode == 2, "CLI: forget --project fb --path P exits 2 (got %r)" % p.returncode)
    check(len(_q("SELECT id FROM chunks WHERE project='fb'")) == n0, "CLI: the refused forget deleted nothing")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = M.cmd_forget(_Args(project=None, path=gone))
    left = {os.path.normcase(r[0]) for r in _q("SELECT DISTINCT source_path FROM chunks WHERE project='fb'")}
    check(rc == 0 and os.path.normcase(gone) not in left and os.path.normcase(keep) in left,
          "--path alone removes exactly that file and keeps the other")
    with contextlib.redirect_stdout(buf):
        rc = M.cmd_forget(_Args(project="fb", path=None, expect_chunks=_nchunks("fb")))
    check(rc == 0 and not _q("SELECT id FROM chunks WHERE project='fb'"),
          "--project with a matching --expect-chunks still removes the whole project")


def _nchunks(proj):
    return _q("SELECT COUNT(*) FROM chunks WHERE project=?", (proj,))[0][0]


def _footprint(proj, root):
    """(chunks, fts rows, files, captures, links) held by a project - what a project forget deletes.
    FTS rows are counted by their OWN source_path column under the project's root, not by joining to
    chunks: a join empties when the chunks go, so it read 0 even with the FTS delete removed (round-1
    code-auditor, proven by mutation)."""
    return (_nchunks(proj),
            _q("SELECT COUNT(*) FROM chunks_fts WHERE instr(source_path, ?) = 1", (root + os.sep,))[0][0],
            _q("SELECT COUNT(*) FROM files WHERE project=?", (proj,))[0][0],
            _q("SELECT COUNT(*) FROM captures WHERE project=?", (proj,))[0][0],
            _q("SELECT COUNT(*) FROM links WHERE src_id IN (SELECT id FROM captures WHERE project=?)", (proj,))[0][0])


def test_forget_project_confirm():
    """`forget --project X` ALONE used to delete the whole project at rc=0 with no preview (the hazard
    left open after the both-flags fix, 2026-10-02). It must now only PREVIEW, at rc=5, with exact
    counts of everything it would delete; deleting needs --expect-chunks equal to the live count."""
    print("\n[7c] forget --project previews unless --expect-chunks matches")
    root = os.path.join(_TMP, "fc")
    _write(os.path.join(root, "doc.md"), "# Doc\n\nAn ordinary document that a project forget would remove.\n")
    _write(os.path.join(root, "c1.md"), _cap("fc-open", "an open capture", "status: open\n"
                                              "applies_to:\n  - fc-filed: like\n  - doc.md: depends-on\n"))
    _write(os.path.join(root, "c2.md"), _cap("fc-filed", "a filed capture"))
    _ingest(root, "fc")
    other = os.path.join(_TMP, "fc-other")
    _write(os.path.join(other, "o.md"), "# Other\n\nA bystander project that must never be touched.\n")
    _ingest(other, "fc-other")
    fp0, other0 = _footprint("fc", root), _footprint("fc-other", other)
    check(fp0[0] >= 3 and fp0[1] == fp0[0] and fp0[2] == 3 and fp0[3] == 2 and fp0[4] == 2,
          "setup: project fc has chunks, fts rows, 3 files, 2 captures, 2 links (%r)" % (fp0,))

    def run(**kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = M.cmd_forget(_Args(**kw))
        return rc, buf.getvalue()

    rc, out = run(project="fc")
    check(rc == 5, "bare --project returns the preview code 5, not 0 (rc=%r)" % rc)
    check(out.startswith("[PREVIEW - NOTHING DELETED]"), "the preview says so on its first line")
    check(_footprint("fc", root) == fp0, "the preview deletes NOTHING in any table")
    want = "%d chunks, %d files, 2 captures (1 open), 2 links" % (fp0[0], fp0[2])
    check(want in out, "the preview reports exact counts incl. captures and links (%r)" % want)
    check("--path" in out, "the preview points a one-entry intent at --path")
    check(("--expect-chunks %d" % fp0[0]) not in out, "the preview prints no ready-made confirming command")

    for bad in (fp0[0] - 1, fp0[0] + 1, 0):
        rc, out = run(project="fc", expect_chunks=bad)
        check(rc == 2 and "Nothing forgotten" in out and _footprint("fc", root) == fp0,
              "--expect-chunks %d (live %d) is REFUSED at rc=2 and deletes nothing (rc=%r)" % (bad, fp0[0], rc))
    rc, out = run(path=os.path.join(root, "doc.md"), expect_chunks=1)
    check(rc == 2 and _footprint("fc", root) == fp0, "--expect-chunks with --path alone is refused, nothing deleted")
    for bad in (str(fp0[0]), float(fp0[0])):
        rc, out = run(project="fc", expect_chunks=bad)
        check(rc == 2 and _footprint("fc", root) == fp0,
              "an importing caller's non-int echo %r is refused at rc=2, nothing deleted (rc=%r)" % (bad, rc))
    # True == 1 in Python, so the bool case needs a ONE-chunk project: against fc the mismatch branch
    # refused it anyway and the bool guard could be deleted with the suite green (round-2 code-auditor).
    one = os.path.join(_TMP, "fc-one")
    _write(os.path.join(one, "one.md"), "# One\n\nA single document that becomes exactly one chunk.\n")
    _ingest(one, "fc-one")
    check(_nchunks("fc-one") == 1, "setup: project fc-one holds exactly one chunk")
    rc, out = run(project="fc-one", expect_chunks=True)
    check(rc == 2 and _nchunks("fc-one") == 1,
          "a bool echo (True == 1) is refused at rc=2 on a ONE-chunk project, chunk kept (rc=%r)" % rc)
    rc, out = run(project="")
    check(rc == 2 and "needs a project name" in out, '--project "" is refused at rc=2 with a clear message')
    fresh = os.path.join(_TMP, "never-created.db")
    saved_db = M.DB_PATH
    try:
        M.DB_PATH = fresh
        rc, out = run()
    finally:
        M.DB_PATH = saved_db
    check(rc == 1 and not os.path.exists(fresh), "a forget with neither flag is rc=1 and creates NO database file")

    # the count and the delete share ONE write transaction: while cmd_forget counts, a second writer
    # must already be locked out. Probed from inside the count query, so removing BEGIN IMMEDIATE fails it.
    import sqlite3
    probe = {}

    class _Probe(object):
        def __init__(self, con):
            self._con = con

        def __getattr__(self, name):
            return getattr(self._con, name)

        def execute(self, sql, *a):
            if sql.startswith("SELECT COUNT(*) FROM chunks WHERE project") and "locked" not in probe:
                other_con = sqlite3.connect(M.DB_PATH, timeout=0)
                try:
                    other_con.execute("BEGIN IMMEDIATE")
                    probe["locked"] = False
                    other_con.rollback()
                except sqlite3.OperationalError:
                    probe["locked"] = True
                finally:
                    other_con.close()
            return self._con.execute(sql, *a)
    real_connect = M.connect
    try:
        M.connect = lambda: _Probe(real_connect())
        rc, out = run(project="fc")
    finally:
        M.connect = real_connect
    check(rc == 5 and probe.get("locked") is True,
          "a second writer is LOCKED OUT while forget counts (count and delete in one transaction; %r)" % probe)

    # another writer holding the index: a clear refusal, not a traceback, and nothing deleted
    def _short_connect():
        con = real_connect()
        con.execute("PRAGMA busy_timeout=200")
        return con
    holder = sqlite3.connect(M.DB_PATH)
    try:
        holder.execute("BEGIN IMMEDIATE")
        M.connect = _short_connect
        rc, out = run(project="fc", expect_chunks=fp0[0])
    finally:
        M.connect = real_connect
        holder.rollback()
        holder.close()
    check(rc == 1 and "busy" in out and _footprint("fc", root) == fp0,
          "a locked index is reported as busy at rc=1, nothing deleted (rc=%r)" % rc)

    # a chunk-less project: the echo would be the guessable 0, so it cannot confirm the delete
    con = M.connect()
    try:
        con.execute("INSERT INTO files(source_path,project,mtime,content_hash,ingested_at,chunk_count,note,norm_path)"
                    " VALUES(?,?,?,?,?,?,?,?)", ("C:\\zc\\f.md", "fc-zero", 0, "h", "t", 0, None, "c:\\zc\\f.md"))
        con.execute("INSERT INTO captures(id,source_path,project,what,status) VALUES(?,?,?,?,?)",
                    ("fc-zero-cap", "C:\\zc\\f.md", "fc-zero", "x", "open"))
        con.commit()
    finally:
        con.close()
    rc, out = run(project="fc-zero")
    check(rc == 5 and "0 chunks, 1 files, 1 captures (1 open)" in out, "a chunk-less project still previews its rows")
    rc, out = run(project="fc-zero", expect_chunks=0)
    check(rc == 2 and _q("SELECT COUNT(*) FROM captures WHERE project='fc-zero'")[0][0] == 1,
          "--expect-chunks 0 cannot confirm deleting a chunk-less project's captures (refused, kept)")

    # the snapshot writer must never break a command that already committed (it now runs after forget).
    # The failure is INJECTED, not provoked by bad data: section [13]'s fixes removed the known data
    # triggers, so a data-driven probe here went green with the broad except narrowed (mutation M6).
    con = M.connect()
    real_signal = M.upgrade_signal

    def _boom(_con):
        raise RuntimeError("injected snapshot failure")
    try:
        M.upgrade_signal = _boom
        M._write_status_snapshot(con)
        ok = True
    except Exception:
        ok = False
    finally:
        M.upgrade_signal = real_signal
        con.close()
    check(ok, "a non-OS, non-SQLite failure inside the status snapshot does not escape it")
    rc, out = run(project="fc-no-such-project")
    check(rc == 1 and "nothing forgotten" in out, "an unknown project is rc=1 'nothing forgotten', not a preview")
    rc, out = run(project="fc-no-such-project", expect_chunks=0)
    check(rc == 1, "an unknown project with --expect-chunks 0 is rc=1 too, not a 'successful' forget")

    # the count is read at DELETE time: content added after a preview makes the old count a mismatch
    _write(os.path.join(root, "late.md"), "# Late\n\nA document ingested between the preview and the delete.\n")
    _ingest(root, "fc")
    fp1 = _footprint("fc", root)
    check(fp1[0] > fp0[0], "setup: a later ingest grew project fc (%d -> %d chunks)" % (fp0[0], fp1[0]))
    rc, out = run(project="fc", expect_chunks=fp0[0])
    check(rc == 2 and _footprint("fc", root) == fp1, "a STALE count from an earlier preview is refused, nothing deleted")

    # end to end through the real command line, so argparse -> main() -> sys.exit carries the code
    import subprocess
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mnemosyne.py")

    def cli(*a):
        return subprocess.run([sys.executable, script, "forget"] + list(a), capture_output=True, text=True,
                              encoding="utf-8", env=dict(os.environ)).returncode
    check(cli("--project", "fc") == 5 and _footprint("fc", root) == fp1, "CLI: bare --project exits 5, nothing deleted")
    check(cli("--project", "fc", "--expect-chunks", str(fp1[0] + 1)) == 2 and _footprint("fc", root) == fp1,
          "CLI: a wrong --expect-chunks exits 2, nothing deleted")
    check(cli("--project", "fc", "--expect-chunks", "many") == 2 and _footprint("fc", root) == fp1,
          "CLI: a non-integer --expect-chunks is a usage error (2), nothing deleted")
    wrapper = os.path.join(M.HERE, "mnemosyne.cmd")
    wrapper_py = os.path.join(M.HERE, ".venv", "Scripts", "python.exe")
    if os.name != "nt" or not os.path.isfile(wrapper) or not os.path.isfile(wrapper_py):
        # The launcher needs Windows and the install's own .venv (setup.ps1). A copy without them
        # cannot test it. SKIP is printed, not silent.
        print("  SKIP  WRAPPER: no %s (or no .venv beside it) in this copy" % wrapper)
    else:
        wrc = subprocess.run([wrapper, "forget", "--project", "fc"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=dict(os.environ)).returncode
        check(wrc == 5 and _footprint("fc", root) == fp1, "WRAPPER: mnemosyne.cmd passes the preview's 5 through (got %r)" % wrc)
    check(cli("--project", "fc", "--expect-chunks", str(fp1[0])) == 0, "CLI: the matching count exits 0")
    check(_footprint("fc", root) == (0, 0, 0, 0, 0), "the confirmed forget removed chunks, fts rows, files, captures and links")
    check(_footprint("fc-other", other) == other0, "the bystander project is untouched")
    check(_q("SELECT COUNT(*) FROM chunks_fts")[0][0] == _q("SELECT COUNT(*) FROM chunks")[0][0],
          "no orphan FTS rows anywhere in the index after the forget")
    names = _snapshot_projects()
    check(names is not None and "fc" not in names and "fc-other" in names,
          "the dashboard snapshot is refreshed by the forget (fc gone, fc-other kept: %r)" % (names,))
    # the --path branch refreshes it too: delete the snapshot, forget one file, the snapshot is back
    snap = os.path.join(M.LOG_DIR, M.STATUS_SNAPSHOT)
    os.remove(snap)
    rc, out = run(path=os.path.join(one, "one.md"))
    names = _snapshot_projects()
    check(rc == 0 and names is not None and "fc-one" not in names,
          "a --path forget also rewrites the snapshot (fc-one gone: %r)" % (names,))


def _snapshot_projects():
    snap = os.path.join(M.LOG_DIR, M.STATUS_SNAPSHOT)
    if not os.path.exists(snap):
        return None
    with open(snap, encoding="utf-8") as fh:
        return [p["name"] for p in json.load(fh)["projects"]]


# --------------------------------------------------------------------------------------------
# 8. Secrets in capture fields - with a MUTATION CONTROL
# --------------------------------------------------------------------------------------------
def _secret_round(tag):
    root = os.path.join(_TMP, "sec-" + tag)
    s = _secret("cap-" + tag)
    _write(os.path.join(root, "s.md"),
           "---\nkind: capture\nid: sec-%s\nwhat: token %s here\noutcome: used %s\nsource: from %s\n---\n"
           % (tag, s, s, s))
    _ingest(root, "sec-" + tag)
    blob = json.dumps(_q("SELECT * FROM captures WHERE id=?", ("sec-" + tag,)))
    return s, blob


def test_secrets():
    print("\n[8] secret redaction of capture fields (+ mutation control)")
    s, blob = _secret_round("real")
    check(blob != "[]", "the capture row exists")
    # `blob != "[]"` is folded in (whole-file audit 2026-09-27, Minor): alone, this row read PASS when
    # capture storage was disabled outright, because an empty result contains no token.
    check(blob != "[]" and s not in blob, "the token is in NO stored capture field")
    check(M.REDACT_MARK in blob, "the redaction marker is present in the stored fields")
    orig = M._redact_field
    M._redact_field = lambda v: v                 # neuter the capture-field redaction
    try:
        s2, blob2 = _secret_round("mutant")
    finally:
        M._redact_field = orig
    check(s2 in blob2, "MUTATION CONTROL: with field redaction neutered the token DOES reach the table "
                       "(proves section [8] can fail)")


# --------------------------------------------------------------------------------------------
# 9. Slugs + relation names survive the redactor
# --------------------------------------------------------------------------------------------
def test_slugs_survive():
    print("\n[9] slugs and relation names survive redact_secrets")
    for s in ["ups-alert-routing", "2026-09-26-ups-alert-telegram-routing", "voice-assistant-intake",
              "cap-7f3a9c", "applies_to:\n  - ups-alert-routing: like\n  - voice-assistant-intake: blocked-by"] \
            + list(M.RELATIONS) + list(M.CAPTURE_STATUSES):
        check(M.redact_secrets(s)[0] == s, "unchanged: %r" % s)


# --------------------------------------------------------------------------------------------
# 3b. The .mnemo-captures marker keeps a parent walk from re-owning captures
# --------------------------------------------------------------------------------------------
def test_marker_prune():
    print("\n[3b] .mnemo-captures marker prune")
    parent = os.path.join(_TMP, "ws")
    caps = os.path.join(parent, "captures")
    _write(os.path.join(caps, M.CAPTURE_MARKER), "")
    _write(os.path.join(caps, "m.md"), _cap("marked", "marked capture"))
    _write(os.path.join(parent, "other.md"), "# Other\n\nSome ordinary prose that is long enough.\n")
    _ingest(parent, "sandbox-like")
    check(not _q("SELECT * FROM chunks WHERE project='sandbox-like' AND source_path LIKE '%captures%'"),
          "walking the PARENT skips the marked captures dir")
    _ingest(caps, "captures")
    check(_q("SELECT project FROM captures WHERE id='marked'") == [("captures",)],
          "ingesting the marked dir itself registers the capture")


# --------------------------------------------------------------------------------------------
# 10. JSON surfaces
# --------------------------------------------------------------------------------------------
def test_json():
    print("\n[10] --json surfaces")
    root = os.path.join(_TMP, "j")
    _write(os.path.join(root, "one.md"), _cap("quokka-one", "quokka decision alpha",
                                              "status: open\napplies_to:\n  - quokka-two: like\n"))
    _write(os.path.join(root, "two.md"), _cap("quokka-two", "quokka idea beta"))
    _write(os.path.join(root, "three.md"), _cap("quokka-three", "quokka follow-up",
                                                "applies_to:\n  - quokka-one: depends-on\n"))
    _ingest(root, "j")

    rc, out, doc = _run_json(M.cmd_query, query="quokka decision alpha", project="j")
    check(rc == 0 and doc is not None, "query --json: stdout is ONE parseable JSON document")
    check(all(ord(c) < 128 for c in out), "query --json output is pure ASCII")
    check(doc and "content_trust" in doc, "query --json carries content_trust framing")
    hits = {r.get("id"): r for r in (doc or {}).get("results", [])}
    one = hits.get("quokka-one")
    check(one is not None, "the capture is returned with its id")
    if one:
        check(one["kind"] == "capture" and one["status"] == "open", "kind/status on a capture hit")
        check([(l["target"], l["relation"], l["resolved"]) for l in one["links_out"]]
              == [("quokka-two", "like", True)], "links_out resolved with relation")
        check([(l["source"], l["relation"]) for l in one["links_in"]] == [("quokka-three", "depends-on")],
              "links_in found from the other capture")
        check(all(k in one for k in ("stale", "missing", "source_path")), "citation fields present")

    rc, out, doc = _run_json(M.cmd_recent, project="j")
    check(rc == 0 and doc is not None and all(ord(c) < 128 for c in out), "recent --json parses, ASCII")
    if doc:
        check([x["id"] for x in doc["open"]] == ["quokka-one"], "recent: open list = the open capture only")
        check(len(doc["recent"]) == 3, "recent: all three in the recent list")
        check("content_trust" in doc, "recent --json carries content_trust framing")

    rc, out, doc = _run_json(M.cmd_status)
    check(rc == 0 and doc is not None and "captures" in doc, "status --json parses and reports captures")

    rc, out, doc = _run_json(M.cmd_query, query="!!!", project="j")
    check(doc is not None and doc.get("results") == [], "no-terms query still emits valid JSON")


# --------------------------------------------------------------------------------------------
# 11. Audit round 1 (2026-09-26): red-team + code-auditor findings, each pinned
# --------------------------------------------------------------------------------------------
def test_audit_round1():
    print("\n[11] audit round 1 regressions")
    d = os.path.join(_TMP, "a1")
    os.makedirs(d, exist_ok=True)

    # F1 (Fatal/Serious, both auditors): a secret written as a PATH-shaped link target was stored raw.
    labeled = "AKIA" + _secret("akia", 16).upper().replace("0", "Q")[:16]
    entropy = _secret("pathsecret", 40)
    for label, tok in (("denylist-shaped", labeled), ("entropy-shaped", entropy)):
        cap, err = M.parse_capture("---\nkind: capture\nid: f1-%s\nwhat: x\napplies_to:\n  - %s: like\n---\n"
                                   % (label, tok), d, 0)
        check(cap is None and err and "secret" in err,
              "F1: a %s bare link target is REJECTED, not stored (err=%r)" % (label, err))
        cap, err = M.parse_capture("---\nkind: capture\nid: f1b-%s\nwhat: x\napplies_to:\n  - notes\\%s.md\n---\n"
                                   % (label, tok), d, 0)
        check(cap is None and err, "F1: a %s inside a NON-EXISTENT relative path is rejected" % label)
    # Round 2 (Fatal): round 1 exempted paths that EXIST, and was defeated by creating a directory named
    # after the secret. The rule is now a bright line with no existence exemption.
    laundered = os.path.join(_TMP, "landing", labeled, "real.md")
    _write(laundered, "# Real\n\nA real file inside a directory named after a credential.\n")
    cap, err = M.parse_capture("---\nkind: capture\nid: f1-launder\nwhat: x\napplies_to:\n  - %s: like\n---\n"
                               % laundered, d, 0)
    check(cap is None and err and "secret" in err,
          "F1 round 2: a credential used as an EXISTING directory name is still rejected (err=%r)" % (err,))
    # Control: the check covers only what the AUTHOR wrote, so a random-looking CAPTURE directory
    # (tempfile names, like this suite's own _TMP) never rejects a relative link.
    rnd_base = os.path.join(_TMP, "zq8Xk2mP9vLr4Tn7Wb3Yc6")
    check(M.redact_secrets(rnd_base)[0] != rnd_base, "F1 control precondition: the base dir IS secret-shaped")
    cap, err = M.parse_capture("---\nkind: capture\nid: f1-rel\nwhat: x\napplies_to:\n  - notes.md#Alerting: like\n---\n",
                               rnd_base, 0)
    check(cap is not None, "F1 control: a relative link from a random-looking capture dir is accepted (err=%r)" % (err,))

    # F2 (auditor Serious): resolution must fold case like Windows does, not ASCII-only like SQLite.
    uni = os.path.join(_TMP, "Caf\u00c9", "doc.md")
    _write(uni, "# Top\n\n## Alerting\n\nAlerting prose long enough to be stored as a chunk.\n")
    _write(os.path.join(_TMP, "uni-caps", "u.md"),
           _cap("uni-link", "links to a non-ASCII path",
                "applies_to:\n  - ..\\caf\u00e9\\doc.md#Alerting: like\n"))   # relative: see F1 bright line
    _ingest(os.path.dirname(uni), "uni")
    _ingest(os.path.join(_TMP, "uni-caps"), "uni")
    con = M.connect()
    try:
        tgt = con.execute("SELECT target FROM links WHERE src_id='uni-link'").fetchone()
        ok = bool(tgt) and M._resolve_target(con, tgt[0])[0]
    finally:
        con.close()
    check(ok, "F2: a link to a non-ASCII-cased path resolves (Unicode case folding)")

    # F3 (red-team Serious): the marker must not silently hide a subtree, and never a governed one.
    parent = os.path.join(_TMP, "mk")
    _write(os.path.join(parent, "hidden", M.CAPTURE_MARKER), "")
    _write(os.path.join(parent, "hidden", "h.md"), "# H\n\nHidden prose long enough to be a chunk.\n")
    _write(os.path.join(parent, "gov", M.CAPTURE_MARKER), "")
    _write(os.path.join(parent, "gov", "canary.md"), "# C\n\nGoverned canary prose, long enough.\n")
    saved = M.GOVERNED_ROOTS
    try:
        M.GOVERNED_ROOTS = [M._canonical(os.path.join(parent, "gov"))]
        rc, out = _ingest(parent, "mk")
    finally:
        M.GOVERNED_ROOTS = saved
    check("capture-marked" in out and "hidden" in out, "F3: ingest output NAMES the marker-pruned directory")
    check("skipped governed  : 1" in out, "F3: a marker inside a GOVERNED dir does not suppress the governed count")
    check(not _q("SELECT * FROM files WHERE source_path LIKE '%canary%'"), "F3: the governed canary is still not indexed")

    # F4 (red-team Serious): control characters / ANSI escapes never reach stored fields or text output.
    esc = "\x1b[2J\x1b[H"
    root = os.path.join(_TMP, "ctl")
    _write(os.path.join(root, "c.md"), _cap("ctl-cap", "hello %s FAKE-SYSTEM-MESSAGE" % esc,
                                            "outcome: ok \x07 \u202e reversed\nstatus: open\n"))
    _ingest(root, "ctl")
    row = _q("SELECT what, outcome FROM captures WHERE id='ctl-cap'")
    check(row and "\x1b" not in row[0][0] and "\x07" not in (row[0][1] or "") and "\u202e" not in (row[0][1] or ""),
          "F4: ESC/BEL/bidi-override are stripped from stored capture fields")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_recent(_Args(project="ctl"))
        M.cmd_query(_Args(query="FAKE SYSTEM MESSAGE hello", project="ctl"))
    check("\x1b" not in buf.getvalue(), "F4: no ESC byte in text-mode recent/query output")
    rawchunk = os.path.join(_TMP, "ctl2", "p.md")
    _write(rawchunk, "# Plain\n\nplain prose with an escape %s zorblax inside it, long enough\n" % esc)
    _ingest(os.path.dirname(rawchunk), "ctl2")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_query(_Args(query="zorblax", project="ctl2"))
    check("\x1b" not in buf.getvalue(), "F4: text-mode query also sanitizes ordinary chunk snippets")
    # Round 2 (Serious): ingest's OWN output quoted raw author text in CAPTURE-INVALID messages.
    root3 = os.path.join(_TMP, "ctl3")
    _write(os.path.join(root3, "c.md"), "---\nkind: capture\nid: BadID%sspoof\nwhat: hello\n---\nbody\n" % esc)
    rc, out = _ingest(root3, "ctl3")
    check("CAPTURE-INVALID" in out and "\x1b" not in out, "F4 round 2: no ESC byte in ingest's CAPTURE-INVALID warning")
    check(all("\x1b" not in (n or "") for (n,) in _q("SELECT note FROM files WHERE project='ctl3'")),
          "F4 round 2: files.note is stored clean")
    for ch in ("\u200f", "\u200e", "\u061c", "\u200b", "\u2066", "\ufeff", "\u2028"):
        check(M._clean("a" + ch + "b") == "a?b", "F4 round 2: U+%04X is stripped" % ord(ch))

    # Round 3 (Serious): a project name derived from a directory basename printed raw in ingest + status.
    evil_dir = os.path.join(_TMP, "proj_" + chr(0x202E) + "evil")
    _write(os.path.join(evil_dir, "e.md"), "# E\n\nProse long enough to become one stored chunk.\n")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_ingest(_Args(path=evil_dir, project=None))
        M.cmd_status(_Args())
    check(chr(0x202E) not in buf.getvalue(), "F4 round 3: no bidi override in ingest/status text output via a project name")

    # F5 (auditor Serious): status must not be O(links x files). Budget is generous; the bug was ~6s.
    con = M.connect()
    try:
        for i in range(3000):
            con.execute("INSERT INTO files(source_path,project,mtime,content_hash,ingested_at,chunk_count,note,norm_path)"
                        " VALUES(?,?,?,?,?,?,?,?)", ("C:\\perf\\f%d.md" % i, "perf", 0, "h", "t", 0, None,
                                                   os.path.normcase("C:\\perf\\f%d.md" % i)))
        for i in range(2000):
            con.execute("INSERT INTO links(src_id,target,relation,source_path,ord) VALUES(?,?,?,?,?)",
                        ("perf-src", os.path.normcase("C:\\perf\\f%d.md" % (i * 7)), "like", "C:\\perf\\s.md", i))
        con.commit()
        t0 = time.time()
        M._capture_health(con)
        dt = time.time() - t0
    finally:
        con.close()
    check(dt < 1.0, "F5: _capture_health over 2000 path links x 3000 files in %.2fs (< 1.0s)" % dt)
    # Round 2 (Minor): the fixture above has 2000 DISTINCT targets, so it never exercised the memo.
    # Count resolver calls over repeated targets instead - removing the memo makes this go red.
    con = M.connect()
    calls = [0]
    orig = M._resolve_target

    def counting(c, t):
        calls[0] += 1
        return orig(c, t)
    try:
        con.execute("DELETE FROM links")
        for i in range(600):
            con.execute("INSERT INTO links(src_id,target,relation,source_path,ord) VALUES(?,?,?,?,?)",
                        ("memo-src-%d" % i, "shared-target-%d" % (i % 3), "like", "C:\\perf\\m.md", 0))
        con.commit()
        M._resolve_target = counting
        M._capture_health(con)
    finally:
        M._resolve_target = orig
        con.close()
    check(calls[0] == 3, "F5 round 2: 600 links over 3 distinct targets resolve 3 times, not 600 (got %d)" % calls[0])


# --------------------------------------------------------------------------------------------
# 12. Whole-file audit 2026-09-27 (isolated code-auditor): three guards no assertion could fail on.
#     Each was proven by mutation to stay 106/106 green with the guarded line removed.
# --------------------------------------------------------------------------------------------
def test_audit_2026_09_27():
    print("\n[12] whole-file audit 2026-09-27: forbidden marker, sorted ownership, insert-time link redaction")

    # A1 (Serious): the marker must never hide a FORBIDDEN dir, the half of F3 that had no test.
    # '.claude' cannot be the fixture: SKIP_DIRS prunes it BEFORE the marker check runs, so the
    # `not is_forbidden_tree(full_d)` clause could be deleted and a '.claude' case would still pass.
    # A forbidden component SKIP_DIRS does not hold leaves that clause as the only barrier.
    parent = os.path.join(_TMP, "fb")
    comp = "forbidfixture"
    check(comp not in M.SKIP_DIRS, "A1 precondition: the fixture component is not pruned by SKIP_DIRS")
    _write(os.path.join(parent, comp, M.CAPTURE_MARKER), "")
    _write(os.path.join(parent, comp, "f.md"), "# F\n\nForbidden canary prose, long enough to index.\n")
    saved = M.FORBIDDEN_COMPONENTS
    try:
        M.FORBIDDEN_COMPONENTS = set(saved) | {comp}
        rc, out = _ingest(parent, "fb")
    finally:
        M.FORBIDDEN_COMPONENTS = saved
    check("skipped sensitive : 1" in out,
          "A1: a marker inside a FORBIDDEN dir does not suppress its refusal count")
    check(not any(comp in ln for ln in out.splitlines() if "capture-marked" in ln),
          "A1: the forbidden dir is not reported as capture-marked (it was walked, not pruned)")
    check(not _q("SELECT * FROM files WHERE source_path LIKE ?", ("%" + comp + "%",)),
          "A1 control: the forbidden canary is still not indexed")

    # A2 (Serious): 'first by SORTED path wins' passed with targets.sort() removed, because os.walk on
    # NTFS already yields names alphabetically. Reverse the walk's file order so enumeration order and
    # sorted order disagree; only the explicit sort can then make a.md win.
    root = os.path.join(_TMP, "srt")
    a = _write(os.path.join(root, "a.md"), _cap("sort-id", "sorted owner"))
    _write(os.path.join(root, "b.md"), _cap("sort-id", "enumerated-first claimant"))
    real_walk = os.walk

    def reversed_walk(*w_args, **w_kw):
        for dp, dn, fn in real_walk(*w_args, **w_kw):
            fn[:] = sorted(fn, reverse=True)
            yield dp, dn, fn
    try:
        M.os.walk = reversed_walk
        _ingest(root, "srt")
    finally:
        M.os.walk = real_walk
    rows = _q("SELECT source_path FROM captures WHERE id='sort-id'")
    check(len(rows) == 1 and os.path.normcase(rows[0][0]) == os.path.normcase(a),
          "A2: with the walk yielding b.md FIRST, the sorted owner a.md still wins")

    # A3 (Manageable): the insert-time _redact_target() is a second layer behind parse_capture's
    # rejection of secret-shaped targets, so no ordinary input ever reached it. Inject a secret-bearing
    # target AFTER parsing to drive that line, with a mutation control proving the assertion can fail.
    def _inject_round(tag):
        s = _secret("link-" + tag)
        real_parse = M.parse_capture

        def injecting(text, base_dir, mtime):
            cap, err = real_parse(text, base_dir, mtime)
            if cap is not None:
                cap["links"] = list(cap["links"]) + [("doc.md#" + s, "like")]
            return cap, err
        r = os.path.join(_TMP, "lnk-" + tag)
        _write(os.path.join(r, "l.md"), _cap("lnk-" + tag, "link carrier"))
        try:
            M.parse_capture = injecting
            _ingest(r, "lnk-" + tag)
        finally:
            M.parse_capture = real_parse
        return s, json.dumps(_q("SELECT target FROM links WHERE src_id=?", ("lnk-" + tag,)))
    s, blob = _inject_round("real")
    check(blob != "[]" and s not in blob and M.REDACT_MARK in blob,
          "A3: a secret in a link target is redacted at INSERT time (the second layer)")
    orig = M._redact_target
    M._redact_target = lambda t: t
    try:
        s2, blob2 = _inject_round("mutant")
    finally:
        M._redact_target = orig
    check(s2 in blob2, "A3 MUTATION CONTROL: with _redact_target neutered the token DOES reach links.target")


# --------------------------------------------------------------------------------------------
# 13. Whole-file audit 2026-10-02: unreadable files fail the run, malformed telemetry never crashes
# --------------------------------------------------------------------------------------------
def test_audit_2026_10_02():
    print("\n[13] whole-file audit 2026-10-02: unreadable files -> rc 4, malformed telemetry lines")
    root = os.path.join(_TMP, "unread")
    paths = [_write(os.path.join(root, "u%d.md" % i), "# U\n\nA readable-looking document, number %d.\n" % i)
             for i in range(7)]
    _write(os.path.join(root, "ok.md"), "# OK\n\nThis one is readable and must still be indexed.\n")
    blocked = {os.path.normcase(p) for p in paths}
    real_open = open

    def locked_open(p, *a, **kw):           # stands in for a file another process holds open exclusively
        if os.path.normcase(os.path.abspath(p)) in blocked:
            raise PermissionError(13, "Permission denied", p)
        return real_open(p, *a, **kw)
    M.open = locked_open                    # module global shadows the builtin inside ingest_file only
    try:
        rc, out = _ingest(root, "unread")
    finally:
        del M.open
    check(rc == 4, "an unreadable file makes ingest exit 4, not 0 (rc=%r)" % rc)
    check("7 file(s) could not be read" in out, "the [ERROR] line counts all 7 unreadable files")
    check("... and 2 more" in out, "warnings past the first five are counted, not silently dropped")
    check(len(_q("SELECT * FROM files WHERE project='unread'")) == 1,
          "only the readable file is recorded as ingested (no files row for an unreadable one)")

    os.makedirs(M.LOG_DIR, exist_ok=True)
    logs = [os.path.join(M.LOG_DIR, n) for n in (M.QUERY_LOG, M.FLAG_LOG)]
    saved = {p: (real_open(p, encoding="utf-8").read() if os.path.exists(p) else None) for p in logs}
    try:
        for p in logs:
            with real_open(p, "a", encoding="utf-8") as fh:
                fh.write('null\n42\n["x"]\n{"ts": 7}\n{"ts": "2026-10-02T00:00:00"}\n')
                # LAST line, dated now: flag-last reads the newest query event, so its wrong-typed
                # `query` field is what cmd_flag hands to redact_secrets (round-2 code-auditor)
                fh.write(json.dumps({"ts": M.now_iso(), "query": 5, "top": 5}) + "\n")
        crashed = []
        # flag-last BEFORE query: query appends a fresh well-formed event, which would hide the corrupt
        # last line from flag-last (mutation M17 stayed green in that order)
        for name, fn, kw in (("status", M.cmd_status, {}), ("status --json", M.cmd_status, {"json": True}),
                             ("flag-last", M.cmd_flag, {"reason": "test"}),
                             ("query", M.cmd_query, {"query": "readable document"})):
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    fn(_Args(**kw))
            except Exception as exc:
                crashed.append("%s: %s: %s" % (name, type(exc).__name__, exc))
        check(not crashed, "null / number / list / non-string and naive ts log lines crash nothing (%r)" % crashed)
    finally:
        for p, body in saved.items():
            if body is None:
                if os.path.exists(p):
                    os.remove(p)
            else:
                with real_open(p, "w", encoding="utf-8") as fh:
                    fh.write(body)


# --------------------------------------------------------------------------------------------
# 14. Ingest fixes 2026-10-04: CA-2 embed retry,
#     CA-4 storage spelling, CA-11 single-file allowlist, R2-6 walk errors, CA-10 project reporting,
#     CA-7 fences, CA-8 Unicode terms, CA-U1 real '~<digit>' names
# --------------------------------------------------------------------------------------------
class _FakeEmb(object):
    """Stands in for mnemo_embed: deterministic 4-dim vectors, no model. `fail_if(texts)` -> raise."""
    MAX_TOKENS = 512
    MODEL_NAME = "fake"

    def __init__(self, fail_if=None, short=False):
        self.EMBED_AVAILABLE = True
        self.fail_if = fail_if
        self.short = short
        self.calls = 0

    def embed_passages(self, texts):
        self.calls += 1
        texts = list(texts)
        if self.fail_if and self.fail_if(texts):
            raise RuntimeError("fake embed failure")
        out = [[float(len(t) % 7), 1.0, 0.0, 0.0] for t in texts]
        return out[:-1] if (self.short and len(out) > 1) else out

    def count_tokens(self, text):
        return len(text) // 4

    def to_blob(self, vec):
        import struct
        return struct.pack("4f", *vec)


def _nulls(project):
    return _q("SELECT COUNT(*) FROM chunks WHERE project=? AND embedding IS NULL", (project,))[0][0]


def _multi_chunk_doc(tag, n=3, poison_at=None):
    parts = []
    for i in range(n):
        body = "Section %d of %s holds enough ordinary prose to be a chunk of its own." % (i, tag)
        if i == poison_at:
            body += " POISON_CHUNK"
        parts.append("# H%d\n\n%s\n" % (i, body))
    return "\n".join(parts)


def test_ingest_fixes_2026_10_04():
    print("\n[14] ingest fixes 2026-10-04")
    real_emb = M.emb
    base = os.path.join(_TMP, "if14")

    # -- CA-2: a failed embed exits 4 with its own message, keeps the chunks, and the next ingest heals.
    root = os.path.dirname(_write(os.path.join(base, "emb", "a.md"), _multi_chunk_doc("emb")))
    try:
        M.emb = _FakeEmb(fail_if=lambda t: True)
        rc, out = _ingest(root, "if14_emb")
        check(rc == 4, "CA-2: an embed failure makes ingest exit 4, not 0 (rc=%r)" % rc)
        check("NOT fully embedded" in out and "were NOT indexed" not in out,
              "CA-2: it gets its OWN message, not the unreadable-file 'NOT indexed' one")
        n_chunks = len(_q("SELECT id FROM chunks WHERE project='if14_emb'"))
        check(n_chunks == 3 and _nulls("if14_emb") == 3,
              "CA-2: the chunks stay indexed (lexical) with no vector (%d chunks, %d null)"
              % (n_chunks, _nulls("if14_emb")))
        M.emb = _FakeEmb()
        rc, out = _ingest(root, "if14_emb")
        check(rc == 0 and _nulls("if14_emb") == 0 and "re-embedded       : 3" in out,
              "CA-2: the next ingest of the UNCHANGED file embeds them (rc=%r, null=%d)" % (rc, _nulls("if14_emb")))
        rc, out = _ingest(root, "if14_emb")
        check(rc == 0 and "re-embedded" not in out, "CA-2: a healed file is not re-embedded again")

        # one poisoned chunk: the batch fails, the per-chunk fallback embeds the others
        r2 = os.path.dirname(_write(os.path.join(base, "poison", "p.md"), _multi_chunk_doc("poison", 4, 2)))
        M.emb = _FakeEmb(fail_if=lambda t: any("POISON_CHUNK" in x for x in t))
        rc, out = _ingest(r2, "if14_poison")
        check(rc == 4 and _nulls("if14_poison") == 1,
              "CA-2: one bad chunk leaves ONLY itself unembedded (rc=%r, null=%d of 4)" % (rc, _nulls("if14_poison")))
        check("1 of 4 chunk(s) NOT embedded" in out, "CA-2: the warning counts the missing chunks")

        # a short vector result is a failure, never a silent zip() truncation
        r3 = os.path.dirname(_write(os.path.join(base, "short", "s.md"), _multi_chunk_doc("short")))
        fake = _FakeEmb(short=True)
        M.emb = fake
        rc, out = _ingest(r3, "if14_short")
        check(rc == 0 and _nulls("if14_short") == 0 and fake.calls == 4,
              "CA-2: a short batch result falls back per chunk (1 batch + 3 singles = %d calls; null=%d)"
              % (fake.calls, _nulls("if14_short")))

        # a broken layer stops the fallback after 3 straight failures
        r4 = os.path.dirname(_write(os.path.join(base, "broken", "b.md"), _multi_chunk_doc("broken", 8)))
        fake = _FakeEmb(fail_if=lambda t: True)
        M.emb = fake
        rc, _ = _ingest(r4, "if14_broken")
        check(rc == 4 and fake.calls == 4, "CA-2: a broken layer is tried 1 batch + 3 singles, not once per "
              "chunk (%d calls)" % fake.calls)

        # embed layer OFF: lexical-only is not a failure, and turning it on heals
        r5 = os.path.dirname(_write(os.path.join(base, "off", "o.md"), _multi_chunk_doc("off")))
        M.emb = _FakeEmb()
        M.emb.EMBED_AVAILABLE = False
        rc, _ = _ingest(r5, "if14_off")
        check(rc == 0 and _nulls("if14_off") == 3, "CA-2: ingest with the embed layer OFF exits 0 (rc=%r)" % rc)
        rc, _ = _ingest(r5, "if14_off")
        check(rc == 0 and M.emb.calls == 0 and _nulls("if14_off") == 3,
              "CA-2: re-ingest with the layer still OFF neither embeds nor fails (rc=%r, calls=%d)"
              % (rc, M.emb.calls))
        buf = io.StringIO()
        M.emb.EMBED_AVAILABLE = True
        with contextlib.redirect_stdout(buf):
            M.cmd_status(_Args())
        check("have no embedding" in buf.getvalue() and "if14_off 3" in buf.getvalue(),
              "CA-2: status names the un-embedded chunks per project")
        rc, _ = _ingest(r5, "if14_off")
        check(rc == 0 and _nulls("if14_off") == 0, "CA-2: with the layer back ON, re-ingest embeds them")
    finally:
        M.emb = real_emb

    # -- CA-4: the same tree under another case is ONE set of rows, stored in the on-disk case;
    #    old-spelling rows migrate lazily and a capture survives the migration.
    real = os.path.join(base, "CaseTree")
    _write(os.path.join(real, "Note.md"), "# N\n\nA note that must be indexed exactly once.\n")
    _write(os.path.join(real, "cap.md"), _cap("if14-case-cap"))
    lower = real.lower()
    if lower == real:
        print("  NOTE  temp path has no upper-case letters; CA-4 checks SKIPPED")
    else:
        rc, _ = _ingest(lower, "if14_case")
        first = [r[0] for r in _q("SELECT source_path FROM files WHERE project='if14_case'")]
        # Checked BEFORE a second ingest: the alias cleanup would otherwise repair a lower-case store and
        # hide a broken _storage_spelling (mutation M7 survived the first battery that way).
        check(len(first) == 2 and all("CaseTree" in r for r in first),
              "CA-4: an ingest TYPED in lower case stores the on-disk case (%r)" % first)
        rc2, _ = _ingest(real, "if14_case")
        rows = [r[0] for r in _q("SELECT source_path FROM files WHERE project='if14_case'")]
        check(rc == 0 and rc2 == 0 and len(rows) == 2,
              "CA-4: the tree typed in two cases is indexed ONCE (%d files rows)" % len(rows))
        check(all(os.path.basename(os.path.dirname(r)) == "CaseTree" for r in rows),
              "CA-4: stored in the ON-DISK case, not the typed one (%r)" % rows)
        # Migration: rows written the OLD way (typed lowercase) are replaced on the next ingest.
        mig = os.path.join(base, "MigTree")
        _write(os.path.join(mig, "m.md"), "# M\n\nA migrating note with enough prose to be a chunk.\n")
        _write(os.path.join(mig, "mcap.md"), _cap("if14-mig-cap"))
        real_sp = M._storage_spelling
        M._storage_spelling = os.path.abspath            # the pre-fix behavior
        try:
            _ingest(mig.lower(), "if14_mig")
        finally:
            M._storage_spelling = real_sp
        before = [r[0] for r in _q("SELECT source_path FROM files WHERE project='if14_mig'")]
        rc, out = _ingest(mig, "if14_mig")
        after = sorted(r[0] for r in _q("SELECT source_path FROM files WHERE project='if14_mig'"))
        caps = _q("SELECT source_path FROM captures WHERE id='if14-mig-cap'")
        check(all(p == p.lower() for p in before) and len(after) == 2
              and all("MigTree" in p for p in after),
              "CA-4: old lower-case rows are REPLACED by the on-disk spelling (%r -> %r)" % (before, after))
        check(rc == 0 and "CAPTURE-INVALID" not in out and len(caps) == 1 and "MigTree" in caps[0][0],
              "CA-4: the capture survives the migration, owned by the new spelling (%r)" % caps)
        check("old spellings     : 2" in out, "CA-4: the replaced spellings are reported")

    # A zero file ID (FAT, some network or placeholder volumes) is UNKNOWN, never equal to another zero.
    class _St(object):
        st_dev, st_ino, st_size, st_mtime_ns = 1, 0, 10, 5
    real_stat = M.os.stat
    M.os.stat = lambda p, *a, **kw: _St()
    try:
        zero_key = M._same_file_key("anything")
    finally:
        M.os.stat = real_stat
    check(zero_key is None, "CA-4: a zero file ID gives NO identity, so it can never match an alias")

    # Different files that only collide by case are BOTH kept (per-directory case-sensitive folder).
    import subprocess
    cs = os.path.join(base, "cs")
    os.makedirs(cs, exist_ok=True)
    r = subprocess.run(["fsutil.exe", "file", "setCaseSensitiveInfo", cs, "enable"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  NOTE  case-sensitive directory unavailable (fsutil rc=%s); collision check SKIPPED" % r.returncode)
    else:
        _write(os.path.join(cs, "Doc.md"), "# U\n\nUPPER_DOC_MARK prose long enough to be a chunk.\n")
        _write(os.path.join(cs, "doc.md"), "# L\n\nLOWER_DOC_MARK prose long enough to be a chunk.\n")
        _ingest(cs, "if14_cs")
        rc, out = _ingest(cs, "if14_cs")
        n = len(_q("SELECT * FROM files WHERE project='if14_cs'"))
        check(rc == 0 and n == 2 and "old spellings" not in out,
              "CA-4: two DIFFERENT files that collide by case are both kept (%d rows)" % n)

    # -- CA-11: a single-file root must pass the allowlist; a link single-file root is refused
    py = _write(os.path.join(base, "single", "script.py"), "# not a doc\nprint('SINGLE_PY_MARK')\n")
    rc, out = _ingest(py, "if14_single")
    check(rc == 2 and "not an ingestible file type" in out and not _q(
        "SELECT * FROM files WHERE project='if14_single'"),
        "CA-11: a single .py root is REFUSED at rc=2 and nothing is stored (rc=%r)" % rc)
    md = _write(os.path.join(base, "single", "ok.md"), "# OK\n\nA single markdown file is still fine to ingest.\n")
    rc, _ = _ingest(md, "if14_single")
    check(rc == 0 and len(_q("SELECT * FROM files WHERE project='if14_single'")) == 1,
          "CA-11 CONTROL: a single .md root still ingests")
    real_rp = M._is_reparse
    M._is_reparse = lambda p: os.path.normcase(p) == os.path.normcase(md) or real_rp(p)
    try:
        rc, out = _ingest(md, "if14_single")
    finally:
        M._is_reparse = real_rp
    check(rc == 2 and "is a link" in out, "CA-11: a single-file root that is a link is REFUSED (rc=%r)" % rc)

    # -- R2-6: a directory that cannot be listed fails the run; a governed one does not
    wr = os.path.dirname(_write(os.path.join(base, "walkerr", "w.md"), "# W\n\nA readable note beside a locked dir.\n"))
    locked = os.path.join(wr, "locked")
    real_walk = os.walk

    def walk_with_error(top, topdown=True, onerror=None, followlinks=False):
        if onerror:
            onerror(PermissionError(13, "Access is denied", locked))
        return real_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks)
    M.os.walk = walk_with_error
    try:
        rc, out = _ingest(wr, "if14_walk")
        real_roots = M.GOVERNED_ROOTS
        M.GOVERNED_ROOTS = list(real_roots) + [M._canonical(locked)]   # `locked` is a governed root
        try:
            rc_g, out_g = _ingest(wr, "if14_walk")
        finally:
            M.GOVERNED_ROOTS = real_roots
    finally:
        M.os.walk = real_walk
    check(rc == 4 and "could not be listed" in out,
          "R2-6: an unlistable directory makes ingest exit 4 and is named (rc=%r)" % rc)
    check(rc_g == 0 and "skipped governed  : 1" in out_g,
          "R2-6: an unlistable GOVERNED directory counts as skipped-governed, not a failure (rc=%r)" % rc_g)

    # -- CA-10: unchanged files keep their owner (reported); changed files move (warned)
    pr = os.path.join(base, "proj")
    f = _write(os.path.join(pr, "p.md"), "# P\n\nOwned first by project A, with enough prose.\n")
    _ingest(pr, "if14_A")
    rc, out = _ingest(pr, "if14_B")
    owner = _q("SELECT project FROM files WHERE source_path LIKE ?", ("%" + os.sep + "proj" + os.sep + "p.md",))
    check(rc == 0 and owner == [("if14_A",)] and "NOT moved into 'if14_B'" in out and "(was 'if14_A')" in out,
          "CA-10: an unchanged file under another --project is REPORTED and keeps its owner (%r)" % owner)
    _write(f, "# P\n\nChanged now, so last writer wins - but visibly, with enough prose.\n")
    rc, out = _ingest(pr, "if14_B")
    owner = _q("SELECT project FROM files WHERE source_path LIKE ?", ("%" + os.sep + "proj" + os.sep + "p.md",))
    check(rc == 0 and owner == [("if14_B",)] and "CHANGED file(s) moved into project 'if14_B'" in out,
          "CA-10: a CHANGED file moves and the move is WARNED (%r)" % owner)

    # -- CA-7: fenced '#' lines are not headings; an unclosed fence does not swallow later headings
    doc = ("# Real\n\nIntro prose for the real section, long enough.\n\n```bash\n# just a comment\necho hi\n```\n"
           "\nAfter the fence, still the Real section.\n\n~~~~\n# tilde comment\n~~~\n# still inside\n~~~~\n"
           "\nTail prose of Real.\n")
    anchors = {a for a, _, _ in M.chunk_markdown(doc)}
    blob = "\n".join(t for _, _, t in M.chunk_markdown(doc))
    check(anchors == {"Real"} and "# just a comment" in blob and "# still inside" in blob,
          "CA-7: '#' lines inside ``` and ~~~ fences stay body text (anchors %r)" % sorted(anchors))
    doc2 = "# One\n\nFirst section prose, long enough to keep.\n\n```\nunclosed fence\n\n# Two\n\nSecond section prose, long enough.\n"
    anchors2 = [a for a, _, _ in M.chunk_markdown(doc2)]
    check("Two" in anchors2, "CA-7: an UNCLOSED fence does not swallow the headings after it (%r)" % anchors2)
    doc3 = "# A\n\nProse long enough for a chunk here.\n\n``` x`y\n# B\n\nProse long enough for B here.\n```\n"
    check("B" in [a for a, _, _ in M.chunk_markdown(doc3)],
          "CA-7: a backtick line whose info string holds a backtick is not a fence (CommonMark)")
    t0 = time.time()
    M.chunk_markdown("```x\n" * 20000 + "# H\n\nbody text that is long enough\n")
    check(time.time() - t0 < 5.0, "CA-7: 20,000 unclosed openers chunk in under 5s (%.2fs)" % (time.time() - t0))

    # -- CA-8: non-ASCII lexical terms
    _write(os.path.join(base, "uni", "u.md"), "# Uni\n\nThe candidate's r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE} lists na\N{LATIN SMALL LETTER I WITH DIAERESIS}ve Bayes and Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich.\n")
    _ingest(os.path.join(base, "uni"), "if14_uni")
    for q in ("r\N{LATIN SMALL LETTER E WITH ACUTE}sum\N{LATIN SMALL LETTER E WITH ACUTE}", "Zu\N{COMBINING DIAERESIS}rich", "na\N{LATIN SMALL LETTER I WITH DIAERESIS}ve"):
        rc, _, d = _run_json(M.cmd_query, query=q, project="if14_uni")
        check(d and len(d.get("results", [])) == 1, "CA-8: query %a finds the non-ASCII word" % q)

    # -- CA-U1: a real '~<digit>' directory name ingests; an unlistable '~<digit>' component is refused
    tdir = os.path.join(base, "notes" + chr(126) + "2")
    _write(os.path.join(tdir, "t.md"), "# T\n\nA note inside a directory whose real name has a tilde-digit.\n")
    rc, out = _ingest(tdir, "if14_tilde")
    check(rc == 0 and "8.3" not in out, "CA-U1: a REAL long name containing '~<digit>' is not refused (rc=%r)" % rc)
    ghost = os.path.join(base, "no-such-dir", "PROGRA" + chr(126) + "9")
    check(M._has_unresolved_short_name(ghost), "CA-U1: a '~<digit>' component that is not listed is still refused")


def _short_path(p):
    """The 8.3 short spelling of an existing path, or None when the volume makes none."""
    import ctypes
    buf = ctypes.create_unicode_buffer(32768)
    n = ctypes.windll.kernel32.GetShortPathNameW(p, buf, 32768)
    s = buf.value if n and n < 32768 else ""
    return s if s and os.path.normcase(s) != os.path.normcase(p) else None


def test_ingest_fixes_round1():
    print("\n[15] ingest fixes 2026-10-04, audit round 1")
    base = os.path.join(_TMP, "if15")

    # -- RT1-1 / RT1-2: a TYPED 8.3 short name is refused, so every name-based check sees long names
    ssh = os.path.join(base, "sens", ".ssh")
    _write(os.path.join(ssh, "config_notes.txt"), "Host notes behind a short alias, long enough to be a chunk.\n")
    sec = _write(os.path.join(base, "sens", "my_secrets.md"), "# S\n\nSecret-named notes, long enough to be a chunk.\n")
    old = _write(os.path.join(base, "sens", "backup_notes.txtold"), "Not an allowlisted type, long enough text.\n")
    cases = [(ssh, "the short alias of a .ssh DIRECTORY"), (sec, "the short alias of my_secrets.md"),
             (old, "the short alias of a .txtold file (CA-11 allowlist)")]
    for target, what in cases:
        sp = _short_path(target)
        if not sp:
            print("  NOTE  no 8.3 name for %s on this volume; check SKIPPED" % os.path.basename(target))
            continue
        # LONG parent + SHORT final component only (round-2 code-auditor, T2): the temp parent has its
        # own short name, so a fully short spelling was refused on the PARENT and never tested the leaf.
        sp = os.path.join(os.path.dirname(target), os.path.basename(sp))
        if sp == target:
            print("  NOTE  %s has no distinct short leaf; check SKIPPED" % os.path.basename(target))
            continue
        rc, out = _ingest(sp, "if15_short")
        check(rc == 2 and "8.3" in out and not _q("SELECT * FROM files WHERE project='if15_short'"),
              "RT1-1/2: ingesting %s is REFUSED, nothing stored (rc=%r)" % (what, rc))

    # -- RT1-1: a sensitive component visible only in the CANONICAL spelling (a junction ancestor) is skipped
    jdir = os.path.join(base, "viajunction")
    jf = _write(os.path.join(jdir, "notes.md"), "# J\n\nContent that really lives under a .ssh directory.\n")
    real_canon = M._canonical
    fake_target = os.path.normcase(os.path.join(base, "realhome", ".ssh", "notes.md"))
    M._canonical = lambda p: fake_target if os.path.normcase(os.path.abspath(p)) == os.path.normcase(jf) else real_canon(p)
    try:
        rc, out = _ingest(jdir, "if15_junction")
    finally:
        M._canonical = real_canon
    check(rc == 0 and "skipped sensitive : 1" in out and not _q("SELECT * FROM files WHERE project='if15_junction'"),
          "RT1-1: a file whose CANONICAL path is under .ssh is skipped as sensitive (rc=%r)" % rc)

    # -- RT1-3: migrating an UNCHANGED file's old spelling keeps its owner; a CHANGED one moves (warned)
    mig = os.path.join(base, "OwnMig")
    keep = _write(os.path.join(mig, "keep.md"), "# K\n\nUnchanged through the migration, enough prose.\n")
    move = _write(os.path.join(mig, "move.md"), "# M\n\nWill change before the migration, enough prose.\n")
    real_sp = M._storage_spelling
    M._storage_spelling = os.path.abspath
    try:
        _ingest(mig.lower(), "if15_x")
    finally:
        M._storage_spelling = real_sp
    _write(move, "# M\n\nChanged now, so it moves to the new project, enough prose.\n")
    rc, out = _ingest(mig, "if15_y")
    owners = dict((os.path.basename(p), prj) for p, prj in _q(
        "SELECT source_path, project FROM files WHERE project IN ('if15_x','if15_y')"))
    check(rc == 0 and owners.get("keep.md") == "if15_x",
          "RT1-3: an UNCHANGED file keeps its owner through the spelling migration (%r)" % owners)
    check(owners.get("move.md") == "if15_y" and "1 CHANGED file(s) moved" in out
          and "1 unchanged file(s) are owned by another project" in out,
          "RT1-3: only the CHANGED file moves, and each is reported under its own heading")

    # -- RT1-4: a walk error on a directory whose stat ALSO fails is a failure, not skipped-governed
    wr = os.path.dirname(_write(os.path.join(base, "walkerr", "w.md"), "# W\n\nReadable note beside a dead dir.\n"))
    dead = os.path.join(wr, "dead")
    real_walk, real_stat, real_ids = os.walk, os.stat, M._governed_ids

    def walk_with_error(top, topdown=True, onerror=None, followlinks=False):
        if onerror:
            onerror(OSError(362, "The cloud file provider is not running", dead))
        return real_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks)

    def stat_dead(p, *a, **kw):
        if os.path.normcase(str(p)) == os.path.normcase(dead):
            raise OSError(362, "The cloud file provider is not running", p)
        return real_stat(p, *a, **kw)
    M.os.walk, M.os.stat = walk_with_error, stat_dead
    M._governed_ids = lambda: {(1, 1)}       # a governed identity exists, so is_governed's fail-closed branch is live
    try:
        rc, out = _ingest(wr, "if15_walk")
    finally:
        M.os.walk, M.os.stat, M._governed_ids = real_walk, real_stat, real_ids
    check(rc == 4 and "could not be listed" in out and "skipped governed  : 0" in out,
          "RT1-4: an unlistable, un-stat-able directory fails the run (rc=%r)" % rc)

    # -- CA1-1: BOTH spellings already stored (the old bug's state); the old one owns the capture
    both = os.path.join(base, "BothSp")
    _write(os.path.join(both, "c.md"), _cap("if15-both-cap"))
    real_sp, real_drop = M._storage_spelling, M._drop_alias_rows
    M._drop_alias_rows = lambda *a, **kw: None
    try:
        M._storage_spelling = os.path.abspath
        _ingest(both.lower(), "if15_both")                  # old spelling registers the capture
        M._storage_spelling = real_sp
        _ingest(both, "if15_both")                          # on-disk row: CAPTURE-INVALID duplicate id
    finally:
        M._storage_spelling, M._drop_alias_rows = real_sp, real_drop
    pre = _q("SELECT source_path, note FROM files WHERE project='if15_both'")
    check(len(pre) == 2 and any((n or "").startswith("CAPTURE-INVALID") for _, n in pre),
          "PRECONDITION CA1-1: both spellings stored, the on-disk one CAPTURE-INVALID (%d rows)" % len(pre))
    rc, out = _ingest(both, "if15_both")
    rows = _q("SELECT source_path, note FROM files WHERE project='if15_both'")
    caps = _q("SELECT source_path FROM captures WHERE id='if15-both-cap'")
    check(rc == 0 and len(rows) == 1 and rows[0][1] is None and len(caps) == 1 and "BothSp" in caps[0][0],
          "CA1-1: the capture is RE-REGISTERED under the on-disk spelling, not lost (%r, %r)" % (rows, caps))

    # -- CA1-3: a file that rolls back reports none of the work it undid
    rb = os.path.join(base, "RollBk")
    _write(os.path.join(rb, "r.md"), "# R\n\nA file whose re-ingest raises after its alias was dropped.\n")
    M._storage_spelling = os.path.abspath
    try:
        _ingest(rb.lower(), "if15_rb")
    finally:
        M._storage_spelling = real_sp
    real_parse = M.parse_capture

    def boom(*a, **kw):
        raise RuntimeError("injected failure after the alias drop")
    M.parse_capture = boom
    try:
        rc, out = _ingest(rb, "if15_rb")
    finally:
        M.parse_capture = real_parse
    rows = _q("SELECT source_path FROM files WHERE project='if15_rb'")
    check(rc == 4 and "removed:" not in out and "old spellings" not in out and len(rows) == 1
          and rows[0][0] == rows[0][0].lower(),
          "CA1-3: a rolled-back file does not claim an alias removal that was undone (rc=%r, rows=%r)" % (rc, rows))

    # -- tests the round-1 auditor's mutations showed were missing
    ghost = os.path.join(base, "GHOST" + chr(126) + "7")         # parent EXISTS; the name is not listed
    check(os.path.isdir(base) and M._has_unresolved_short_name(ghost),
          "CA-U1: an unlisted '~<digit>' name under an EXISTING parent is refused")
    a1 = [a for a, _, _ in M.chunk_markdown("# Top\n\nTop prose, long enough here.\n\n```\n# In\n\nIn prose, long enough here.\n``` x\n")]
    check("In" in a1, "CA-7: a closer with trailing text does not close a fence (%r)" % a1)
    a2 = [a for a, _, _ in M.chunk_markdown("# Top\n\nTop prose, long enough here.\n\n    ```\n# In\n\nIn prose, long enough here.\n    ```\n")]
    check("In" in a2, "CA-7: a fence indented 4 spaces is not a fence (%r)" % a2)
    real_rp = M.os.path.realpath
    probe = os.path.join(base, "spell", "x.md")
    try:
        M.os.path.realpath = lambda p, *a, **kw: "Z:\\elsewhere\\x.md"
        far = M._storage_spelling(probe)
        M.os.path.realpath = lambda p, *a, **kw: os.path.abspath(p).upper()
        case_only = M._storage_spelling(probe)
    finally:
        M.os.path.realpath = real_rp
    check(far == os.path.abspath(probe) and case_only == os.path.abspath(probe).upper(),
          "CA-4: storage uses realpath ONLY for a case-only difference (link target kept out: %r)" % far)

    class _S(object):
        def __init__(self, size):
            self.st_dev, self.st_ino, self.st_size, self.st_mtime_ns = 9, 9, size, 1
    real_stat = M.os.stat
    M.os.stat = lambda p, *a, **kw: _S(1 if p == "one" else 2)
    try:
        differ = M._same_file_key("one") != M._same_file_key("two")
    finally:
        M.os.stat = real_stat
    check(differ, "CA-4: equal file IDs with different sizes are NOT the same file (weak-ID volumes)")


def test_ingest_fixes_round2():
    print("\n[16] ingest fixes 2026-10-04, audit round 2: UTF-16/32 files, control chars, PEM headers")
    base = os.path.join(_TMP, "if16")
    upper = "".join(c for c in _secret("akia16", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AKIA" + upper                                     # built at runtime, never a literal
    assert len(akia) == 20
    body = "# Notes\n\nThe deploy key is %s and nothing else here is secret, just prose from Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich.\n" % akia
    encs = [("utf-16", None), ("utf-16-le", None), ("utf-16-be", None), ("utf-32", None), ("utf-32-le", None)]
    for enc, _ in encs:
        d = os.path.join(base, "enc-" + enc)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "k.txt"), "wb") as fh:
            fh.write(body.encode(enc))
        rc, _ = _ingest(d, "if16_enc")
        stored = "\n".join((t or "") + (a or "") for t, a in _q(
            "SELECT text, anchor FROM chunks WHERE source_path LIKE ?", ("%enc-" + enc + "%",)))
        fts = "\n".join(t or "" for (t,) in _q(
            "SELECT text FROM chunks_fts WHERE source_path LIKE ?", ("%enc-" + enc + "%",)))
        note = _q("SELECT note FROM files WHERE source_path LIKE ?", ("%%enc-%s%s%%" % (enc, os.sep),))
        # Every one of these is UTF-16/32 or NUL-bearing, so a held secret DROPS it whole (bright line,
        # 2026-10-05; extended to any NUL-bearing file after round 8, which covers BOM-less UTF-32).
        dropped = note == [("SKIPPED-secret:non-utf8-secret",)]
        want_drop = True
        check(rc == 0 and dropped == want_drop and (dropped or stored)
              and akia not in stored.replace("\x00", "") and akia not in fts.replace("\x00", ""),
              "RT2-1: a %s file's key is never stored (%s; rc=%r)" % (enc, "dropped" if dropped else "redacted", rc))
    # DECODING is checked on files with NO secret (a file with one is now dropped whole).
    clean = "# Notes\n\nNothing secret here, just prose from Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich.\n"
    for enc in ("utf-16", "utf-32"):
        d = os.path.join(base, "dec-" + enc)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "c.txt"), "wb") as fh:
            fh.write(clean.encode(enc))
        _ingest(d, "if16_dec")
        got = _q("SELECT text FROM chunks WHERE source_path LIKE ?", ("%%dec-%s%s%%" % (enc, os.sep),))
        check(got and "Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich" in got[0][0],
              "RT2-1: a BOM'd %s file is DECODED, so non-ASCII prose survives (not just NUL-stripped)" % enc)

    pem_lines = [_secret("pem%d" % i, 64) for i in range(6)]
    for label, header in (("plain", "PRIVATE KEY"), ("encrypted", "ENCRYPTED PRIVATE KEY"),
                          ("pgp", "PGP PRIVATE KEY BLOCK")):
        for enc in ("utf-8", "utf-16"):
            pem = "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (header, "\n".join(pem_lines), header)
            d = os.path.join(base, "pem-%s-%s" % (label, enc))
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "id.txt"), "wb") as fh:
                fh.write(("Key material below.\n\n" + pem).encode(enc))
            _ingest(d, "if16_pem")
            note = _q("SELECT note FROM files WHERE source_path LIKE ?", ("%%pem-%s-%s%%" % (label, enc),))
            check(note and note[0][0] == "SKIPPED-secret:private-key",
                  "RT2-1/RT2-3: a %s PEM in %s is dropped whole (%r)" % (label, enc, note))

    # control chars inside a secret in a QUERY never reach the query log
    split_key = "\x00".join(akia)
    rc, _, _ = _run_json(M.cmd_query, query="deploy key prose " + split_key, project="if16_enc")
    with open(os.path.join(M.LOG_DIR, M.QUERY_LOG), encoding="utf-8") as fh:
        logged = fh.read()
    check(akia not in logged.replace("\\u0000", "").replace("\x00", ""),
          "RT2-1: a NUL-split key in a QUERY is redacted before it is logged")


def _seed_both_spellings(root, alias_project, disk_project):
    """Store `root` under its lower-case spelling (project alias_project) AND its on-disk spelling (project
    disk_project) - the state the old CA-4 bug produced - with the alias cleanup disabled."""
    real_sp, real_drop = M._storage_spelling, M._drop_alias_rows
    M._drop_alias_rows = lambda *a, **kw: None
    try:
        M._storage_spelling = os.path.abspath
        _ingest(root.lower(), alias_project)
        M._storage_spelling = real_sp
        _ingest(root, disk_project)
    finally:
        M._storage_spelling, M._drop_alias_rows = real_sp, real_drop


def test_ingest_fixes_round2_ca():
    print("\n[17] ingest fixes 2026-10-04, audit round 2 (code-auditor)")
    base = os.path.join(_TMP, "if17")

    # -- CA2-1: namespace spellings of one local tree are ONE set of rows
    ns = os.path.join(base, "NsTree")
    _write(os.path.join(ns, "n.md"), "# N\n\nOne file reached through several namespace spellings.\n")
    drive, rest = os.path.splitdrive(ns)
    for spelled in (ns, "\\\\?\\" + ns, "\\\\localhost\\%s$%s" % (drive[0], rest)):
        rc, _ = _ingest(spelled, "if17_ns")
    rows = _q("SELECT source_path FROM files WHERE project='if17_ns'")
    check(len(rows) == 1 and rows[0][0] == os.path.join(ns, "n.md"),
          "CA2-1: plain, \\\\?\\ and \\\\localhost\\C$ spellings store ONE row, in the plain form (%r)" % rows)

    # -- CA2-2: a single file named explicitly but skipped is a refusal; CA2-3: an empty path is refused
    sec = _write(os.path.join(base, "single", "team_secrets.md"), "# S\n\nSecret-named, skipped by name.\n")
    rc, out = _ingest(sec, "if17_single")
    check(rc == 2 and "skipped sensitive : 1" in out and not _q("SELECT * FROM files WHERE project='if17_single'"),
          "CA2-2: a single sensitive-named file root exits 2, not 0 (rc=%r)" % rc)
    okf =_write(os.path.join(base, "single", "ok.md"), "# OK\n\nA plain single file ingests and re-ingests at 0.\n")
    rc1, _ = _ingest(okf, "if17_single")
    rc2, _ = _ingest(okf, "if17_single")
    check(rc1 == 0 and rc2 == 0, "CA2-2 CONTROL: a single file ingests, and an unchanged re-ingest is still 0 (%r, %r)"
          % (rc1, rc2))
    # From an EMPTY temp CWD: if the refusal ever breaks, "" means the CWD, and this keeps it tiny.
    emptycwd = os.path.join(base, "emptycwd")
    os.makedirs(emptycwd, exist_ok=True)
    old_cwd = os.getcwd()
    os.chdir(emptycwd)
    try:
        for empty in ("", "   "):
            rc, out = _ingest(empty, "if17_empty")
            check(rc == 2 and "needs a path" in out, "CA2-3: an empty ingest path %r is refused (rc=%r)" % (empty, rc))
    finally:
        os.chdir(old_cwd)

    # -- T1: a full (not shallow) stats snapshot - two migrating files, the SECOND rolls back
    t1 = os.path.join(base, "TwoMig")
    _write(os.path.join(t1, "a.md"), "# A\n\nFirst migrating file, ingests fine after the case change.\n")
    _write(os.path.join(t1, "b.md"), "# B\n\nSecond migrating file, raises after its alias drop.\n")
    real_sp = M._storage_spelling
    M._storage_spelling = os.path.abspath
    try:
        _ingest(t1.lower(), "if17_t1")
    finally:
        M._storage_spelling = real_sp
    real_parse = M.parse_capture

    def boom_b(text, base_dir, mtime):
        if "Second migrating" in text:
            raise RuntimeError("injected failure for b.md")
        return real_parse(text, base_dir, mtime)
    M.parse_capture = boom_b
    try:
        rc, out = _ingest(t1, "if17_t1")
    finally:
        M.parse_capture = real_parse
    removed = [ln.strip() for ln in out.splitlines() if "removed:" in ln]
    check(rc == 4 and len(removed) == 1 and removed[0].lower().endswith("a.md"),
          "T1: only the file that COMMITTED is reported as an old spelling removed (%r)" % removed)

    # -- T3: with --allow-governed, an unlistable governed directory is a FAILURE (it would have been indexed)
    wr = os.path.dirname(_write(os.path.join(base, "walkgov", "w.md"), "# W\n\nReadable note beside a locked dir.\n"))
    locked = os.path.join(wr, "locked")
    real_walk, real_roots = os.walk, M.GOVERNED_ROOTS

    def walk_with_error(top, topdown=True, onerror=None, followlinks=False):
        if onerror:
            onerror(PermissionError(13, "Access is denied", locked))
        return real_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks)
    M.os.walk = walk_with_error
    M.GOVERNED_ROOTS = list(real_roots) + [M._canonical(locked)]
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = M.cmd_ingest(_Args(path=wr, project="if17_t3", allow_governed=True))
    finally:
        M.os.walk, M.GOVERNED_ROOTS = real_walk, real_roots
    check(rc == 4 and "could not be listed" in buf.getvalue(),
          "T3: with --allow-governed, an unlistable governed dir fails the run (rc=%r)" % rc)

    # -- T4: prev (on-disk row) wins over a dropped alias for the old owner
    t4 = os.path.join(base, "PrevWins")
    _write(os.path.join(t4, "p.md"), "# P\n\nOwned by P on disk, by Q under the old spelling.\n")
    _seed_both_spellings(t4, "if17_Q", "if17_P")
    rc, out = _ingest(t4, "if17_R")
    owner = _q("SELECT project FROM files WHERE source_path LIKE ?", ("%PrevWins%",))
    check(owner == [("if17_P",)] and "(was 'if17_P')" in out,
          "T4: the on-disk row's project wins over the alias's (%r)" % owner)

    # -- T5: a target whose identity cannot be read drops NO alias (None must never equal None)
    t5 = os.path.join(base, "NoIdent")
    _write(os.path.join(t5, "x.md"), "# X\n\nBoth spellings stored; the target cannot be stat'ed.\n")
    _seed_both_spellings(t5, "if17_t5", "if17_t5")
    real_key = M._same_file_key
    M._same_file_key = lambda p: None
    con = M.connect()
    try:
        disk = os.path.join(t5, "x.md")
        dropped = M._drop_alias_rows(con, disk, {"errors": []})
        con.commit()
    finally:
        con.close()
        M._same_file_key = real_key
    n = len(_q("SELECT * FROM files WHERE project='if17_t5'"))
    check(dropped is None and n == 2, "T5: with no readable identity, no alias row is dropped (%d rows)" % n)

    # -- T6: a tilde line does not close a backtick fence
    # A real ``` closer comes AFTER the ~~~ line, so the fence runs to it: neither '#' line is a heading.
    # (Without that later closer the fence is unclosed and a mutation ignoring the closer char survives.)
    a6 = [a for a, _, _ in M.chunk_markdown("# Top\n\nTop prose, long enough here.\n\n```\n# In\n~~~\n# Mid\n"
                                            "\nMid prose, long enough here too.\n```\n")]
    check(a6 == ["Top"], "T6: a ~~~ line does not close a ``` fence (%r)" % a6)

    # -- T2: a real '~<digit>' directory followed by a SHORT leaf is still refused
    real_t = os.path.join(base, "keep" + chr(126) + "3")
    leaf = _write(os.path.join(real_t, "a_long_note_name.md"), "# L\n\nA file with a long name and an 8.3 alias.\n")
    sl = _short_path(leaf)
    if not sl:
        print("  NOTE  no 8.3 name on this volume; T2 SKIPPED")
    else:
        spelled = os.path.join(real_t, os.path.basename(sl))
        rc, _ = _ingest(spelled, "if17_t2")
        check(rc == 2, "T2: <real ~digit dir>\\<short leaf> is refused - the scan does not stop at the first "
              "real ~digit component (rc=%r)" % rc)


def test_ingest_fixes_round3():
    print("\n[18] ingest fixes 2026-10-04, audit round 3")
    base = os.path.join(_TMP, "if18")
    upper = "".join(c for c in _secret("akia18", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AKIA" + upper
    import hashlib

    # -- R3-1: CRLF / BOM+CRLF / lone-CR files hash exactly as the old text-mode reader did, and an unchanged
    #    CRLF file under another project is KEPT, not moved
    cr = os.path.join(base, "crlf")
    raws = {"crlf.md": b"# C\r\n\r\nWindows line endings, long enough to be a chunk.\r\n",
            "bom.md": b"\xef\xbb\xbf# B\r\n\r\nA BOM and CRLF, long enough to be a chunk here.\r\n",
            "cr.md": b"# R\r\rOld Mac line endings, long enough to be a chunk.\r"}
    os.makedirs(cr, exist_ok=True)
    for n, b in raws.items():
        with open(os.path.join(cr, n), "wb") as fh:
            fh.write(b)
    _ingest(cr, "if18_narrow")
    bad = []
    for n in raws:
        p = os.path.join(cr, n)
        with open(p, encoding="utf-8-sig", errors="replace") as fh:
            want = hashlib.sha256(fh.read().encode("utf-8", "replace")).hexdigest()
        got = _q("SELECT content_hash FROM files WHERE source_path=?", (p,))
        if not got or got[0][0] != want:
            bad.append(n)
    check(not bad, "R3-1: CRLF, BOM+CRLF and lone-CR files hash as the old text-mode reader did (bad: %r)" % bad)
    rc, out = _ingest(cr, "if18_broad")
    check(rc == 0 and "unchanged (skip)  : 3" in out and "CHANGED" not in out,
          "R3-1: re-ingesting them under a broad project leaves them unchanged and owned")

    # -- RT3-1: a row an OLDER secret scan stored is re-scanned (and keeps its owner)
    sd = os.path.join(base, "rescan")
    _write(os.path.join(sd, "k.md"), "# K\n\nThe old key was %s in this note, long enough.\n" % "\x00".join(akia))
    real_strip = M._strip_invisible
    M._strip_invisible = M._strip_format_chars              # the pre-round-2 pipeline
    try:
        _ingest(sd, "if18_owner")
    finally:
        M._strip_invisible = real_strip
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if18_owner'")   # written by old code
        con.commit()
    finally:
        con.close()
    leaked = lambda: any(akia in (t or "").replace("\x00", "") for (t,) in _q(
        "SELECT text FROM chunks WHERE project='if18_owner'"))
    check(leaked(), "PRECONDITION RT3-1: the old pipeline stored the NUL-split key")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_status(_Args())
    check("OLDER secret scan" in buf.getvalue() and "if18_owner 1" in buf.getvalue(),
          "RT3-1: status names the project holding rows from an older scan")
    rc, out = _ingest(sd, "if18_other")
    owner = _q("SELECT project, scan_tag FROM files WHERE source_path LIKE ?", ("%" + os.sep + "rescan" + os.sep + "%",))
    check(rc == 0 and "re-scanned        : 1" in out and not leaked() and owner and owner[0][0] == "if18_owner"
          and owner[0][1] == M._scan_tag(),
          "RT3-1: an unchanged file with a stale scan is RE-SCANNED, the key is gone, the owner kept (%r)" % owner)
    real_rules = M.SECRET_RULES
    M.SECRET_RULES = list(real_rules) + [("if18-extra", __import__("re").compile("zz-if18-zz"))]
    try:
        rc, out = _ingest(sd, "if18_owner")
    finally:
        M.SECRET_RULES = real_rules
    check("re-scanned        : 1" in out, "RT3-1: a change to the loaded secret rules re-scans unchanged files")

    # -- RT3-2: C1 controls and U+FFFD inside a key are stripped (file text and query log)
    for i, ch in enumerate(("\x85", "\x9f", "\x80", "\N{REPLACEMENT CHARACTER}")):
        d = os.path.join(base, "c1-%d" % i)
        _write(os.path.join(d, "c.md"), "# C\n\nKey %s%s%s in prose, long enough here.\n" % (akia[:9], ch, akia[9:]))
        _ingest(d, "if18_c1")
        stored = "\n".join(t for (t,) in _q("SELECT text FROM chunks WHERE source_path LIKE ?", ("%c1-" + str(i) + "%",)))
        check(stored and akia not in stored.replace(ch, ""),
              "RT3-2: a key split by U+%04X is masked, not stored" % ord(ch))
    _run_json(M.cmd_query, query="prose key " + akia[:9] + "\x85" + akia[9:], project="if18_c1")
    with open(os.path.join(M.LOG_DIR, M.QUERY_LOG), encoding="utf-8") as fh:
        logged = fh.read()
    check(akia not in logged.replace("\\u0085", ""), "RT3-2: a C1-split key in a QUERY is not logged")

    # -- flag-last: a NUL-split key in the REASON is not logged; a failed write is rc 4
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_flag(_Args(reason="wrong because " + "\x00".join(akia)))
    with open(os.path.join(M.LOG_DIR, M.FLAG_LOG), encoding="utf-8") as fh:
        flog = fh.read()
    check(akia not in flog.replace("\\u0000", ""), "flag-last: a NUL-split key in the REASON is not logged")
    flag_path = os.path.join(M.LOG_DIR, M.FLAG_LOG)
    os.replace(flag_path, flag_path + ".bak")
    os.makedirs(flag_path)                                    # the log path is now a directory: writes fail
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = M.cmd_flag(_Args(reason="test"))
    finally:
        os.rmdir(flag_path)
        os.replace(flag_path + ".bak", flag_path)
    check(rc == 4 and "flagged:" not in buf.getvalue() and "NOT be written" in buf.getvalue(),
          "RT3-3: flag-last exits 4 and claims nothing when the flag cannot be written (rc=%r)" % rc)

    # -- RT3-4: a capture-id takeover is WARNED
    owner_dir = os.path.join(base, "capA")
    _write(os.path.join(owner_dir, "a.md"), _cap("if18-take"))
    _ingest(owner_dir, "if18_cap")
    os.replace(owner_dir, owner_dir + "-offline")             # the owner now looks gone
    try:
        rc, out = _ingest(os.path.dirname(_write(os.path.join(base, "capB", "b.md"), _cap("if18-take"))), "if18_cap")
    finally:
        os.replace(owner_dir + "-offline", owner_dir)
    check(rc == 0 and "TAKEN OVER" in out and "if18-take" in out, "RT3-4: a capture-id takeover is warned, not silent")

    # -- RT3-5 + lower case: general private-key headers are dropped whole
    body = "\n".join(_secret("p18-%d" % i, 64) for i in range(4)) + "\nAbC\n"
    for i, (pre, word, post) in enumerate((("-----", "SSH2 ENCRYPTED PRIVATE KEY", "-----"),
                                           ("---- ", "SSH2 ENCRYPTED PRIVATE KEY", " ----"),
                                           ("-----", "private key", "-----"))):
        d = os.path.join(base, "pk-%d" % i)
        _write(os.path.join(d, "k.txt"), "Key below.\n\n%sBEGIN %s%s\n%s\n%sEND %s%s\n" % (pre, word, post, body, pre, word, post))
        _ingest(d, "if18_pk")
        note = _q("SELECT note FROM files WHERE source_path LIKE ?", ("%pk-" + str(i) + "%",))
        check(note and note[0][0] == "SKIPPED-secret:private-key", "RT3-5: private-key header form %d is dropped whole" % i)
    # A FRESH single file (an already-indexed one takes the unchanged skip): a copy of the runtime-built
    # pk-0 fixture above.
    pk_single = os.path.join(base, "pk-single", "k.txt")
    os.makedirs(os.path.dirname(pk_single), exist_ok=True)
    shutil.copyfile(os.path.join(base, "pk-0", "k.txt"), pk_single)
    rc, out = _ingest(pk_single, "if18_pk_single")
    check(rc == 2 and "private key" in out, "R3-3: a single private-key file's refusal names the private-key drop")

    # -- RT3-7 / CA2-3 cousin: drive-relative paths are refused (from an empty temp CWD, in case it breaks)
    emptycwd = os.path.join(base, "emptycwd")
    os.makedirs(emptycwd, exist_ok=True)
    old_cwd = os.getcwd()
    os.chdir(emptycwd)
    try:
        drv = os.path.splitdrive(emptycwd)[0]
        for spelled in (drv, "\\\\?\\" + drv, drv + "sub"):
            rc, out = _ingest(spelled, "if18_drv")
            check(rc == 2 and "drive-relative" in out, "RT3-7: drive-relative %r is refused (rc=%r)" % (spelled, rc))
    finally:
        os.chdir(old_cwd)

    # -- R3-2: an invisible-only project is refused; query/forget strip --project the same way
    pd = os.path.dirname(_write(os.path.join(base, "proj", "p.md"), "# P\n\nProject-name stripping prose, long enough.\n"))
    rc, out = _ingest(pd, "\N{ZERO WIDTH SPACE}")
    check(rc == 2 and not _q("SELECT * FROM files WHERE project=''"), "R3-2: an invisible-only --project is refused")
    _ingest(pd, "foo\N{ZERO WIDTH SPACE}bar")
    rc, _, d = _run_json(M.cmd_query, query="stripping prose", project="foo\N{ZERO WIDTH SPACE}bar")
    check(d and len(d.get("results", [])) == 1 and d["results"][0]["project"] == "foobar",
          "R3-2: query --project strips invisible chars the way ingest stored the name")

    _ingest(os.path.dirname(_write(os.path.join(base, "recentp", "r.md"), _cap("if18-recent"))), "cap\N{ZERO WIDTH SPACE}proj")
    rc, _, d = _run_json(M.cmd_recent, project="cap\N{ZERO WIDTH SPACE}proj")
    check(d and [it["id"] for it in d.get("recent", [])] == ["if18-recent"],
          "R3-2: recent --project strips invisible chars the way ingest stored the name")

    class F(object):
        project = "\N{ZERO WIDTH SPACE}"
        path = None
        expect_chunks = None
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = M.cmd_forget(F())
    check(rc == 2, "R3-2: forget --project of an invisible-only name is refused (rc=%r)" % rc)

    # -- decode ORDER and BE BOMs: a non-BMP character only a correct decode can produce
    astral = "\U0001F600"
    for enc, bom in (("utf-16-be", b"\xfe\xff"), ("utf-32-be", b"\x00\x00\xfe\xff"), ("utf-32-le", b"\xff\xfe\x00\x00")):
        d = os.path.join(base, "bom-" + enc)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "b.txt"), "wb") as fh:
            fh.write(bom + ("# B\n\nAstral %s here, prose long enough for a chunk.\n" % astral).encode(enc))
        _ingest(d, "if18_bom")
        got = _q("SELECT text FROM chunks WHERE source_path LIKE ?", ("%bom-" + enc + os.sep + "%",))
        check(got and astral in got[0][0], "decode: a %s BOM file is decoded as %s (non-BMP char intact)" % (enc, enc))


def test_ingest_fixes_round4():
    print("\n[19] ingest fixes 2026-10-04, audit round 4")
    base = os.path.join(_TMP, "if19")
    upper = "".join(c for c in _secret("akia19", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AKIA" + upper

    # -- RT4-1: rules that do not load are recorded, and ingest REFUSES while any problem is recorded
    hk = os.path.join(base, "hooks")
    os.makedirs(hk, exist_ok=True)
    real_hooks = M.HOOKS
    M.HOOKS = hk
    try:
        probs = []
        M.load_secret_rules(probs)
        missing = list(probs)
        with open(os.path.join(hk, "secret-rules.txt"), "w", encoding="utf-8") as fh:
            fh.write("# synthetic\ngood@@zz-good-zz\nbad@@(?<n>zz)\n")      # .NET named group: Python rejects it
        probs = []
        rules = M.load_secret_rules(probs)
    finally:
        M.HOOKS = real_hooks
    check(any("missing" in p for p in missing), "RT4-1: a missing rules file is RECORDED (%r)" % missing)
    check([n for n, _ in rules] == ["good"] and any("'bad' does not compile" in p for p in probs),
          "RT4-1: a rule Python cannot compile is RECORDED, not skipped silently (%r)" % probs)
    real_probs = M.SECRET_RULES_PROBLEMS
    M.SECRET_RULES_PROBLEMS = ["rule 'bad' does not compile in Python (test)"]
    try:
        d = os.path.dirname(_write(os.path.join(base, "rules", "r.md"), "# R\n\nAny note at all, long enough here.\n"))
        rc, out = _ingest(d, "if19_rules")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.cmd_status(_Args())
    finally:
        M.SECRET_RULES_PROBLEMS = real_probs
    check(rc == 2 and "did not load cleanly" in out and not _q("SELECT * FROM files WHERE project='if19_rules'"),
          "RT4-1: ingest is REFUSED while a secret rule did not load (rc=%r)" % rc)
    check("ingest is REFUSED" in buf.getvalue(), "RT4-1: status names the rule problem")

    # -- CA4-2: an invisible-only --project is refused by query and recent (not widened to every project)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rq = M.cmd_query(_Args(query="anything", project="\N{ZERO WIDTH SPACE}"))
        rr = M.cmd_recent(_Args(project="\N{ZERO WIDTH SPACE}"))
    check(rq == 2 and rr == 2, "CA4-2: query and recent refuse an invisible-only --project (rc=%r, %r)" % (rq, rr))

    # -- CA4-3: a torn last line in the flag log does not swallow the next flag
    _ingest(os.path.dirname(_write(os.path.join(base, "fl", "f.md"), "# F\n\nFlag target prose, long enough.\n")), "if19_fl")
    _run_json(M.cmd_query, query="flag target prose", project="if19_fl")
    flag_path = os.path.join(M.LOG_DIR, M.FLAG_LOG)
    saved = open(flag_path, encoding="utf-8").read() if os.path.exists(flag_path) else None
    try:
        with open(flag_path, "w", encoding="utf-8") as fh:
            fh.write('{"query": "torn')                       # a crashed append: no newline
        with contextlib.redirect_stdout(io.StringIO()):
            rc = M.cmd_flag(_Args(reason="after a torn line"))
        events = M._read_jsonl(M.FLAG_LOG)
    finally:
        with open(flag_path, "w", encoding="utf-8") as fh:
            fh.write(saved or "")
    check(rc == 0 and len(events) == 1 and events[0].get("reason") == "after a torn line",
          "CA4-3: the flag after a torn line is recorded (%d events)" % len(events))

    # -- CA4-4: a pre-round-2 query line holding a NUL-split key is stripped before flag-last copies it
    qpath = os.path.join(M.LOG_DIR, M.QUERY_LOG)
    with open(qpath, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": M.now_iso(), "query": "legacy " + "\x00".join(akia), "top": []}) + "\n")
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_flag(_Args(reason="legacy line"))
    with open(flag_path, encoding="utf-8") as fh:
        flog = fh.read()
    check(akia not in flog.replace("\\u0000", ""), "CA4-4: flag-last does not copy a NUL-split key from an old query line")

    # -- CA4-5 / RT4-3: a single private-key file is refused on EVERY run (copy of the [18] runtime fixture)
    pk = os.path.join(base, "pk", "k.txt")
    os.makedirs(os.path.dirname(pk), exist_ok=True)
    shutil.copyfile(os.path.join(_TMP, "if18", "pk-0", "k.txt"), pk)
    rc1, _ = _ingest(pk, "if19_pk")
    rc2, out2 = _ingest(pk, "if19_pk")
    check(rc1 == 2 and rc2 == 2, "CA4-5: a single private-key file is refused on the repeat run too (%r, %r)" % (rc1, rc2))
    rc3, out3 = _ingest(os.path.dirname(pk), "if19_pk")
    con = M.connect()
    try:
        pk_stale = "if19_pk" in M._stale_report(con)["projects"]
    finally:
        con.close()
    check(rc3 == 0 and "re-scanned" not in out3 and not pk_stale,
          "M-a: a private-key row carries the current scan tag (no re-scan, not stale)")

    # -- CA4-6: BOM-less UTF-16 CRLF does not double the newlines
    d = os.path.join(base, "u16crlf")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "u.txt"), "wb") as fh:
        fh.write("# T\r\n\r\nline one of text\r\nline two of text\r\n".encode("utf-16-le"))
    _ingest(d, "if19_u16")
    got = _q("SELECT text FROM chunks WHERE project='if19_u16'")
    check(got and "line one of text\nline two of text" in got[0][0],
          "CA4-6: a BOM-less UTF-16 CRLF file keeps single newlines (%r)" % (got[0][0] if got else None))

    # -- CA4-7: an invisible Lo char glued onto a query word does not hide the word
    # ONE word only: terms are ORed, so a second word matched on its own and hid this (M75 survived that way).
    rc, _, dq = _run_json(M.cmd_query, query="target\N{HANGUL FILLER}", project="if19_fl")
    check(dq and len(dq.get("results", [])) == 1, "CA4-7: query terms come from the stripped query")

    # -- CA4-1: a stale row whose file is GONE is reported for forget --path, not re-ingest
    gone_dir = os.path.join(base, "gone")
    g = _write(os.path.join(gone_dir, "g.md"), "# G\n\nThis file will be deleted after ingest.\n")
    _ingest(gone_dir, "if19_gone")
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if19_gone'")
        con.commit()
    finally:
        con.close()
    os.remove(g)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_status(_Args())
    s = buf.getvalue()
    # Paths print in (project, path) order, at most 5 per kind: fc-zero, if19_gone, then the 3,000 'perf' rows.
    check("GONE from disk" in s and "if19_gone 1" in s and g in s
          and "Re-ingest these projects: if19_gone" not in s,
          "CA4-1: a stale row whose file is gone is listed (with its path) for forget --path, not for re-ingest")
    con = M.connect()
    try:
        rep = M._stale_report(con)
    finally:
        con.close()
    check(len(rep["paths"]["gone"]) == 5 and rep["projects"]["perf"]["gone"] == 3000 and rep["unchecked"] == 0,
          "U3: the report counts every gone row but keeps only 5 paths per kind (%d paths)" % len(rep["paths"]["gone"]))
    rc, out, dj = _run_json(M.cmd_status)
    check(dj and dj.get("stale_scan_missing", {}).get("if19_gone") == 1, "M-c: status --json reports stale_scan_missing")

    # -- RT4-4: NTFS default-stream spellings store ONE row
    ads = os.path.join(base, "AdsTree")
    f = _write(os.path.join(ads, "a.md"), "# A\n\nOne file reached through stream spellings, long enough.\n")
    for spelled in (ads, ads + "::$INDEX_ALLOCATION", ads + ":$I30:$INDEX_ALLOCATION", f + "::$DATA"):
        _ingest(spelled, "if19_ads")
    rows = _q("SELECT source_path FROM files WHERE project='if19_ads'")
    check(rows == [(f,)], "RT4-4: default-stream spellings store ONE row (%r)" % rows)

    # -- RT4-5 + M-b + M-c: a re-scan keeps `touched`; a SCAN_VERSION bump re-scans; --json lists stale projects
    cd = os.path.join(base, "touch")
    _write(os.path.join(cd, "t.md"), _cap("if19-touch"))
    _ingest(cd, "if19_touch")
    before = _q("SELECT touched FROM captures WHERE id='if19-touch'")[0][0]
    real_ver = M.SCAN_VERSION
    M.SCAN_VERSION = real_ver + "-test-bump"
    try:
        rc, _, dj = _run_json(M.cmd_status)
        stale_json = (dj or {}).get("stale_scan", {}).get("if19_touch")
        time.sleep(0.05)
        rc, out = _ingest(cd, "if19_touch")
    finally:
        M.SCAN_VERSION = real_ver
    after = _q("SELECT touched FROM captures WHERE id='if19-touch'")[0][0]
    check(stale_json == 1, "M-c: status --json lists a project with stale rows (%r)" % stale_json)
    check("re-scanned        : 1" in out, "M-b: a SCAN_VERSION bump re-scans unchanged files")
    check(after == before, "RT4-5: a re-scan keeps the capture's touched (%r -> %r)" % (before, after))
    md = os.path.join(base, "TouchMig")
    _write(os.path.join(md, "m.md"), _cap("if19-touch-mig"))
    real_sp = M._storage_spelling
    M._storage_spelling = os.path.abspath
    try:
        _ingest(md.lower(), "if19_tmig")
    finally:
        M._storage_spelling = real_sp
    before = _q("SELECT touched FROM captures WHERE id='if19-touch-mig'")[0][0]
    time.sleep(0.05)
    rc, out = _ingest(md, "if19_tmig")
    after = _q("SELECT touched, source_path FROM captures WHERE id='if19-touch-mig'")[0]
    check("old spellings" in out and after[0] == before and "TouchMig" in after[1],
          "RT4-5: an alias migration keeps the capture's touched (%r -> %r)" % (before, after[0]))

    # -- M-d: TAB is kept; VT and FF still separate words (only line-breaking whitespace, never deleted)
    d = os.path.dirname(_write(os.path.join(base, "ws", "w.md"),
                               "# W\n\ncol_a\tcol_b and left\x0cright and up\x0bdown, long enough.\n"))
    _ingest(d, "if19_ws")
    t = "\n".join(x for (x,) in _q("SELECT text FROM chunks WHERE project='if19_ws'"))
    check("col_a\tcol_b" in t and "leftright" not in t and "updown" not in t,
          "M-d: TAB is kept and VT/FF are not deleted (%r)" % t[:80])

    # -- M-e: a capture-id takeover removes the old owner's links
    od = os.path.join(base, "takeA")
    _write(os.path.join(od, "a.md"), _cap("if19-take", extra="applies_to:\n  - some-other-id: like\n"))
    _ingest(od, "if19_take")
    old_src = os.path.join(od, "a.md")
    check(_q("SELECT COUNT(*) FROM links WHERE source_path=?", (old_src,))[0][0] == 1, "PRECONDITION M-e: the old owner has a link")
    os.replace(od, od + "-offline")
    try:
        _ingest(os.path.dirname(_write(os.path.join(base, "takeB", "b.md"), _cap("if19-take"))), "if19_take")
    finally:
        os.replace(od + "-offline", od)
    check(_q("SELECT COUNT(*) FROM links WHERE src_id='if19-take' AND source_path=?", (old_src,))[0][0] == 0,
          "M-e: a takeover removes the old owner's links")


def test_ingest_fixes_round5():
    print("\n[20] ingest fixes 2026-10-04, audit round 5")
    import re as _re
    base = os.path.join(_TMP, "if20")
    upper = "".join(c for c in _secret("akia20", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AKIA" + upper

    # -- R5-1 / R5-4 / CA5-5: every rules line that does not become a compiled rule is a recorded problem
    hk = os.path.join(base, "hooks")
    os.makedirs(hk, exist_ok=True)
    real_hooks = M.HOOKS
    M.HOOKS = hk
    try:
        with open(os.path.join(hk, "secret-rules.txt"), "w", encoding="utf-8") as fh:
            fh.write("# c\n\ngood@@zz-good-zz\ntypo@zz-[0-9]{4}\n@@no-name\nno-pattern@@   \nhuge@@a{99999999999}\n")
        probs = []
        rules = M.load_secret_rules(probs)
        os.remove(os.path.join(hk, "secret-rules.txt"))
        os.makedirs(os.path.join(hk, "secret-rules.txt"))          # unreadable: a directory in its place
        probs_dir = []
        M.load_secret_rules(probs_dir)
    finally:
        M.HOOKS = real_hooks
    joined = " | ".join(probs)
    check([n for n, _ in rules] == ["good"] and joined.count("is not a 'name@@regex' rule") == 3
          and "'huge' does not compile" in joined and "OverflowError" in joined,
          "R5-1/R5-4: a single-@ line, an empty name, an empty pattern and an OverflowError rule are all RECORDED (%r)" % probs)
    check(any("cannot be read" in p for p in probs_dir), "CA5-5: an unreadable rules file is a recorded problem, not a crash")
    real_probs = M.SECRET_RULES_PROBLEMS
    M.SECRET_RULES_PROBLEMS = ["line 4 is not a 'name@@regex' rule (test)"]
    try:
        rc, _, dj = _run_json(M.cmd_status)
    finally:
        M.SECRET_RULES_PROBLEMS = real_probs
    check(dj and dj.get("secret_rules_problems") == ["line 4 is not a 'name@@regex' rule (test)"],
          "V1: status --json lists secret_rules_problems")

    # -- R5-2: BOM-less UTF-16 with an invisible char INSIDE a key leaks no fragment
    for enc in ("utf-16-le", "utf-16-be"):
        d = os.path.join(base, "u16-" + enc)
        os.makedirs(d, exist_ok=True)
        key = akia[:12] + "\N{ZERO WIDTH SPACE}" + akia[12:]
        with open(os.path.join(d, "k.txt"), "wb") as fh:
            fh.write(("# K\n\nThe deploy key is %s and the rest is ordinary prose.\n" % key).encode(enc))
        _ingest(d, "if20_u16")
        stored = "\n".join(t for (t,) in _q("SELECT text FROM chunks WHERE source_path LIKE ?", ("%u16-" + enc + "%",)))
        note = _q("SELECT note FROM files WHERE source_path LIKE ?", ("%u16-" + enc + "%",))
        # Detected as UTF-16, so the bright line drops it whole (2026-10-05): no fragment can be stored.
        check(note == [("SKIPPED-secret:non-utf8-secret",)] and akia[:6] not in stored and akia[-6:] not in stored,
              "R5-2: a BOM-less %s key split by U+200B leaks no 6-char fragment (dropped whole)" % enc)

    # -- R5-3: ingest names stale rows under its root that the walk did not re-scan (here: now gitignored)
    gd = os.path.join(base, "gi")
    _write(os.path.join(gd, "keep.md"), "# K\n\nStill walked, re-scanned normally, long enough.\n")
    ign = _write(os.path.join(gd, "old.md"), "# O\n\nWill be gitignored after the old scan, long enough.\n")
    _ingest(gd, "if20_gi")
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if20_gi'")
        con.commit()
    finally:
        con.close()
    _write(os.path.join(gd, ".gitignore"), "old.md\n")
    rc, out = _ingest(gd, "if20_gi")
    check(rc == 0 and "re-scanned        : 1" in out and "still hold an OLDER secret scan" in out and ign in out,
          "R5-3: a stale row the walk skipped (gitignored) is NAMED by ingest for forget --path")

    # -- R5-3 / CA5-3: status buckets - skipped (sensitive now), unreachable (stat fails), unchecked (budget)
    sd = os.path.join(base, "buckets")
    fs = _write(os.path.join(sd, "nowsens.md"), "# S\n\nTreated as sensitive after the old scan, long enough.\n")
    fu = _write(os.path.join(sd, "offline.md"), "# U\n\nIts drive goes offline after the old scan, long enough.\n")
    _ingest(sd, "if20_b")
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if20_b'")
        con.commit()
    finally:
        con.close()
    real_sens, real_stat = M.is_sensitive_path, M.os.stat

    def stat_off(p, *a, **kw):
        if os.path.normcase(str(p)) == os.path.normcase(fu):
            raise PermissionError(5, "Access is denied", p)
        return real_stat(p, *a, **kw)
    M.is_sensitive_path = lambda p: os.path.normcase(p) == os.path.normcase(fs) or real_sens(p)
    M.os.stat = stat_off
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.cmd_status(_Args())
    finally:
        M.is_sensitive_path, M.os.stat = real_sens, real_stat
    s = buf.getvalue()
    sk = [ln for ln in s.splitlines() if "now SKIPPED by ingest" in ln]
    un = [ln for ln in s.splitlines() if "could not be checked" in ln]
    check(sk and "if20_b 1" in sk[0] and fs in s, "R5-3: a stale row whose file ingest now SKIPS is listed for forget --path")
    check(un and "if20_b 1" in un[0] and "GONE" not in " ".join(ln for ln in s.splitlines() if "if20_b" in ln and "GONE" in ln),
          "CA5-3: a stat failure is UNREACHABLE, not GONE")
    gone_line = [ln for ln in s.splitlines() if "GONE from disk" in ln]
    check(gone_line and gone_line[0].split(": ", 1)[1].startswith("perf 3000"), "V6: each kind lists projects by count, largest first")
    real_kind = M._stale_kind
    M._stale_kind = lambda sp: (time.sleep(0.2), real_kind(sp))[1]
    con = M.connect()
    try:
        rep = M._stale_report(con, budget=0.3)
    finally:
        con.close()
        M._stale_kind = real_kind
    check(rep["unchecked"] > 0, "CA5-3: the stale report stops at its time budget and counts the rest unchecked (%d)" % rep["unchecked"])

    # -- CA5-4: with TWO stored alias spellings, `touched` survives (first non-None, not the last alias)
    td = os.path.join(base, "TwoAlias")
    _write(os.path.join(td, "t.md"), _cap("if20-two"))
    real_sp, real_drop = M._storage_spelling, M._drop_alias_rows
    M._drop_alias_rows = lambda *a, **kw: None
    try:
        M._storage_spelling = os.path.abspath
        _ingest(td.lower(), "if20_two")                            # owns the capture
        _ingest(td.upper(), "if20_two")                            # duplicate id, no capture row
    finally:
        M._storage_spelling, M._drop_alias_rows = real_sp, real_drop
    before = _q("SELECT touched FROM captures WHERE id='if20-two'")[0][0]
    time.sleep(0.05)
    _ingest(td, "if20_two")
    after = _q("SELECT touched FROM captures WHERE id='if20-two'")
    check(after and after[0][0] == before, "CA5-4: with two aliases dropped, the capture keeps its touched (%r -> %r)"
          % (before, after[0][0] if after else None))

    # -- CA5-6: an EMPTY --project is refused by query and recent too
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rq = M.cmd_query(_Args(query="anything", project=""))
        rr = M.cmd_recent(_Args(project=""))
    check(rq == 2 and rr == 2, "CA5-6: query and recent refuse --project \"\" (rc=%r, %r)" % (rq, rr))

    # -- CA5-7: the scan tag covers the module's own redaction patterns
    real_pk = M._PRIVKEY_RE
    t0 = M._scan_tag()
    M._PRIVKEY_RE = _re.compile("changed-for-test")
    try:
        t1 = M._scan_tag()
    finally:
        M._PRIVKEY_RE = real_pk
    check(t0 != t1, "CA5-7: changing _PRIVKEY_RE changes the scan tag")

    # -- R5-6: the default project drops a default-stream suffix
    ad = os.path.dirname(_write(os.path.join(base, "adsproj", "a.md"), "# A\n\nDefault project from a stream spelling.\n"))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M.cmd_ingest(_Args(path=ad + ":$I30:$INDEX_ALLOCATION", project=None))
    check(_q("SELECT project FROM files WHERE source_path LIKE ?", ("%adsproj%",)) == [("adsproj",)],
          "R5-6: the default project name drops the stream suffix")

    # -- U1: the invisible-char count is not re-added for an unchanged file
    iv = os.path.dirname(_write(os.path.join(base, "inv", "i.md"), "# I\n\nZero\N{ZERO WIDTH SPACE}width inside, long enough here.\n"))
    _, o1 = _ingest(iv, "if20_inv")
    _, o2 = _ingest(iv, "if20_inv")
    check("invisible chars" in o1 and "invisible chars" not in o2, "U1: the invisible count is taken only on a real ingest")

    # -- U2 + CA4-4 positive control: the first event in an EMPTY flag log is written
    flag_path = os.path.join(M.LOG_DIR, M.FLAG_LOG)
    saved = open(flag_path, encoding="utf-8").read() if os.path.exists(flag_path) else None
    try:
        open(flag_path, "w").close()
        _run_json(M.cmd_query, query="zero width inside", project="if20_inv")
        with contextlib.redirect_stdout(io.StringIO()):
            rc = M.cmd_flag(_Args(reason="first in an empty log"))
        ev = M._read_jsonl(M.FLAG_LOG)
    finally:
        with open(flag_path, "w", encoding="utf-8") as fh:
            fh.write(saved or "")
    check(rc == 0 and len(ev) == 1 and ev[0].get("reason") == "first in an empty log",
          "U2: flag-last writes the first event into an EMPTY flag log (%d events)" % len(ev))

    # -- CA4-6 order: control chars are stripped BEFORE newlines are normalized. A UTF-8 file with a NUL between
    #    CR and LF (BOM-less UTF-16 now decodes properly, so only this shape still tells the order apart; M73).
    d = os.path.join(base, "crnul")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "c.md"), "wb") as fh:
        fh.write(b"# C\r\n\r\nline one of text\r\x00\nline two of text, long enough.\r\n")
    _ingest(d, "if20_crnul")
    got = _q("SELECT text FROM chunks WHERE project='if20_crnul'")
    check(got and "line one of text\nline two of text" in got[0][0],
          "CA4-6: CR NUL LF becomes ONE newline (strip before normalize) (%r)" % (got[0][0] if got else None))

    # -- V7: a repeat single private-key run reports the drop, not an unchanged file
    pk = os.path.join(_TMP, "if19", "pk", "k.txt")
    rc, out = _ingest(pk, "if19_pk")
    check(rc == 2 and "SKIPPED secret FILES : 1" in out and "unchanged (skip)  : 0" in out,
          "V7: an unchanged private-key file counts as a dropped secret file, not unchanged")


def test_ingest_fixes_round6():
    print("\n[21] ingest fixes 2026-10-04, audit round 6")
    import re as _re
    base = os.path.join(_TMP, "if21")
    upper = "".join(c for c in _secret("akia21", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AK" + "IA" + upper

    def recoverable(project):
        rows = _q("SELECT text FROM chunks WHERE project=?", (project,))
        blob = "\n".join(t for (t,) in rows)
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                if akia.encode("ascii") in blob.encode(enc, "ignore"):
                    return True
            except Exception:
                pass
        return akia in blob

    # -- RT6-S1: mixed-encoding files are dropped whole, not stored as recoverable garble
    a = os.path.join(base, "mixA")
    os.makedirs(a, exist_ok=True)
    with open(os.path.join(a, "log.txt"), "wb") as fh:            # PowerShell `>` then cmd `>>`
        fh.write(b"\xff\xfe" + "# Log\r\n\r\nFirst line written by PowerShell.\r\n".encode("utf-16-le")
                 + ("Appended note: key is %s and more words follow here.\n" % akia).encode("utf-8"))
    rc, out = _ingest(a, "if21_mixA")
    note = _q("SELECT note FROM files WHERE project='if21_mixA'")
    check(note == [("SKIPPED-secret:non-utf8-secret",)] and not recoverable("if21_mixA"),
          "RT6-S1: a UTF-16 file with an appended UTF-8 secret is dropped whole (%r)" % note)
    b = os.path.join(base, "mixB")
    os.makedirs(b, exist_ok=True)
    head = ("key %s\n" % akia).encode("utf-8")
    body = ("# Body\n\n" + "Ordinary prose in a BOM-less UTF-16 body, repeated. " * 8 + "\n").encode("utf-16-le")
    with open(os.path.join(b, "m.txt"), "wb") as fh:
        fh.write(head + body)
    _ingest(b, "if21_mixB")
    note = _q("SELECT note FROM files WHERE project='if21_mixB'")
    check(note == [("SKIPPED-secret:non-utf8-secret",)] and not recoverable("if21_mixB"),
          "RT6-S1: a UTF-8 head holding a key before a BOM-less UTF-16 body is dropped whole (%r)" % note)
    c = os.path.join(base, "pure16")
    os.makedirs(c, exist_ok=True)
    with open(os.path.join(c, "p.txt"), "wb") as fh:
        fh.write(b"\xff\xfe" + ("# P\n\nThe key is %s in a pure UTF-16 file, long enough.\n" % akia).encode("utf-16-le"))
    _ingest(c, "if21_pure")
    note = _q("SELECT note FROM files WHERE project='if21_pure'")
    check(note == [("SKIPPED-secret:non-utf8-secret",)] and not recoverable("if21_pure"),
          "BRIGHT LINE: a pure UTF-16 file holding a key is dropped whole too (%a)" % note)
    # CONTROLS against over-dropping: UTF-16 files with NO secret are indexed, ASCII and non-ASCII prose alike.
    for i, prose in enumerate(("Plain prose in a UTF-16 file, nothing secret, long enough to chunk.",
                               "\N{CYRILLIC CAPITAL LETTER PE}\N{CYRILLIC SMALL LETTER IE}\N{CYRILLIC SMALL LETTER ER}"
                               "\N{CYRILLIC SMALL LETTER IE} prose with some ASCII words, long enough to chunk too.")):
        cd = os.path.join(base, "clean16-%d" % i)
        os.makedirs(cd, exist_ok=True)
        with open(os.path.join(cd, "c.txt"), "wb") as fh:
            fh.write(b"\xff\xfe" + ("# C\n\n%s\n" % prose).encode("utf-16-le"))
        _ingest(cd, "if21_clean%d" % i)
        note = _q("SELECT note FROM files WHERE project=?", ("if21_clean%d" % i,))
        check(note == [(None,)] and _q("SELECT COUNT(*) FROM chunks WHERE project=?", ("if21_clean%d" % i,))[0][0] >= 1,
              "BRIGHT LINE CONTROL %d: a UTF-16 file with NO secret is indexed, not dropped (%a)" % (i, note))

    # -- RT7-1: a UTF-8 secret appended RIGHT AFTER a UTF-16 one (spans merge, counts tie) is still dropped
    ghp = "gh" + "p_" + _secret("ghp21", 36)
    for i, (sep, tail_enc) in enumerate(((b"", "utf-8"), (b"xx", "utf-8"), (b"", "cp1252"))):
        d = os.path.join(base, "tie%d" % i)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "t.txt"), "wb") as fh:
            fh.write(b"\xff\xfe" + ("# t\n\nnote " + akia).encode("utf-16-le") + sep + ghp.encode(tail_enc) + b"\n")
        _ingest(d, "if21_tie%d" % i)
        note = _q("SELECT note FROM files WHERE project=?", ("if21_tie%d" % i,))
        stored = "\n".join(t for (t,) in _q("SELECT text FROM chunks WHERE project=?", ("if21_tie%d" % i,)))
        leaked = ghp.encode("ascii") in stored.encode("utf-16-le", "ignore").replace(b"\x00", b"")
        check(note == [("SKIPPED-secret:non-utf8-secret",)] and not leaked,
              "RT7-1: a secret appended right after a UTF-16 secret is dropped (case %d: %a)" % (i, note))

    # -- CA7-2: the SAME secret once in the UTF-16 part and again in an appended UTF-8 part is dropped
    d = os.path.join(base, "dupkey")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "d.txt"), "wb") as fh:
        fh.write(b"\xff\xfe" + ("# Log\r\nfirst key %s\r\n" % ghp).encode("utf-16-le") + ("again: %s\n" % ghp).encode("utf-8"))
    _ingest(d, "if21_dup")
    note = _q("SELECT note FROM files WHERE project='if21_dup'")
    stored = "\n".join(t for (t,) in _q("SELECT text FROM chunks WHERE project='if21_dup'"))
    check(note == [("SKIPPED-secret:non-utf8-secret",)]
          and ghp.encode("ascii") not in stored.encode("utf-16-le", "ignore").replace(b"\x00", b""),
          "CA7-2: the same secret in both encodings is dropped, not hidden by its first copy (%a)" % note)

    # -- RT6-M1 + CA6-4/6: rules loader - hazards, line numbers, BOM+CRLF, empty, VT mid-line
    hk = os.path.join(base, "hooks")
    os.makedirs(hk, exist_ok=True)
    rp = os.path.join(hk, "secret-rules.txt")
    real_hooks = M.HOOKS
    M.HOOKS = hk

    def load(data):
        with open(rp, "wb") as fh:
            fh.write(data)
        probs = []
        rules = M.load_secret_rules(probs)
        return [n for n, _ in rules], probs
    try:
        cases = {
            "nul": load(b"good@@zz-good-zz\nnul@@xox[a-z]-[0-9]{4}\x00\n"),
            "fffd": load(b"good@@zz-good-zz\nbadbyte@@xox[a-z]-[0-9]{4}\x85zzz\n"),
            "subtract": load(b"good@@zz-good-zz\nsub@@[0-9A-Za-z-[Z]]{8}\n"),
            "posix": load(b"good@@zz-good-zz\nposix@@[[:alpha:]]{8}\n"),
            "line5": load(b"# a\n# b\ngood@@zz-good-zz\n\nnot a rule line\n"),
            "bomcrlf": load(b"\xef\xbb\xbf# c\r\ngood@@zz-good-zz\r\n"),
            "empty": load(b"# only comments\n\n"),
            "vt": load(b"good@@zz-good-zz\nv@@x\x0bw@@y\n"),
            "lonecr": load(b"r1@@ZQXV-[0-9]{6}\rr2@@PLMK-[0-9]{6}\r"),
            "nothazard": load(b"esc@@\\[ID-[0-9]+\\]\nslack@@xox[baprs]-[0-9a-zA-Z]{10,}\nposixlit@@\\[\\[:alpha:\\]\\]\n"),
            "neg": load(b"good@@zz-good-zz\nneg@@[^a-z-[b]]\n"),
            "escclass": load(b"good@@zz-good-zz\nesc@@[\\]a-z-[b]]\n"),
            "c01": load(b"good@@zz-good-zz\nc@@a\x01b\n"),
            "c1f": load(b"good@@zz-good-zz\nc@@a\x1fb\n"),
            "c7f": load(b"good@@zz-good-zz\nc@@a\x7fb\n"),
        }
    finally:
        M.HOOKS = real_hooks
    for k in ("nul", "fffd", "subtract", "posix"):
        names, probs = cases[k]
        check(names == ["good"] and any("which Python would not read" in p for p in probs)
              and all(p.isascii() for p in probs),
              "RT6-M1: a %s rule is RECORDED (in ASCII), not loaded with another meaning (%a)" % (k, probs))
    check(any(p.startswith("line 5 ") for p in cases["line5"][1]), "CA6-4: problem line numbers are 1-based (%a)" % cases["line5"][1])
    check(cases["bomcrlf"] == (["good"], []), "CA6-4: a BOM + CRLF rules file loads clean (%a)" % (cases["bomcrlf"],))
    check(any("no secret rules loaded" in p for p in cases["empty"][1]), "X26: a comment-only rules file is a recorded problem")
    check(cases["vt"][0] == ["good"] and cases["vt"][1], "CA6-6: a VT inside a line does not split it into two rules (%a)" % (cases["vt"],))
    check(cases["nothazard"] == (["esc", "slack", "posixlit"], []),
          "CA7-5: an escaped bracket, the Slack shape and an escaped [[: are NOT hazards (%a)" % (cases["nothazard"],))
    for k in ("neg", "escclass", "c01", "c1f", "c7f"):
        check(cases[k][0] == ["good"] and cases[k][1], "CA7-5/MG: hazard case %s is RECORDED (%a)" % (k, cases[k][1]))
    check(cases["lonecr"][1] and "r1" not in cases["lonecr"][0],
          "RT7-2: a lone-CR rules file whose first line is a rule is RECORDED, not one CR-requiring rule (%a)" % (cases["lonecr"],))

    # -- RT6-M2: ingest --project "" is refused
    d = os.path.dirname(_write(os.path.join(base, "emptyproj", "e.md"), "# E\n\nEmpty project name test prose.\n"))
    rc, out = _ingest(d, "")
    check(rc == 2 and not _q("SELECT * FROM files WHERE source_path LIKE ?", ("%emptyproj%",)),
          "RT6-M2: ingest --project \"\" is refused, nothing stored (rc=%r)" % rc)

    # -- _stale_kind: missing drive = unreachable; the walk's skips = skipped
    free = [L for L in "ZYXWVUTSRQPONMLKJIHG" if not os.path.exists(L + ":\\")]
    if free:
        check(M._stale_kind(free[0] + ":\\x\\a.md") == "unreachable", "CA6-1: a file on a missing drive is UNREACHABLE, not gone")
    else:
        print("  NOTE  no free drive letter; missing-drive check SKIPPED")
    sk = os.path.join(base, "skips")
    nm = _write(os.path.join(sk, "node_modules", "n.md"), "# N\n\nUnder a skipped dir.\n")
    py = _write(os.path.join(sk, "s.py"), "x = 1\n")
    cl = _write(os.path.join(sk, ".claude", "c.md"), "# C\n\nUnder an agent config dir.\n")
    plain = _write(os.path.join(sk, "plain.md"), "# P\n\nAn ordinary file.\n")
    # SKIP_DIRS is root-dependent (the walk prunes only BELOW its root), so status leaves it to ingest (round-7
    # code-auditor): a file under node_modules, or under a ROOT that sits inside build\, stays 'rescan'.
    bd = _write(os.path.join(sk, "build", "site", "b.md"), "# B\n\nA root that lives inside a build folder.\n")
    check(M._stale_kind(nm) == "rescan" and M._stale_kind(bd) == "rescan" and M._stale_kind(py) == "skipped"
          and M._stale_kind(cl) == "skipped" and M._stale_kind(plain) == "rescan",
          "CA6-2/CA7-4: non-ingestible and .claude files are 'skipped'; SKIP_DIRS ancestors are left to ingest")
    real_rp = M._is_reparse
    M._is_reparse = lambda p: os.path.normcase(p) == os.path.normcase(plain) or real_rp(p)
    try:
        rk = M._stale_kind(plain)
    finally:
        M._is_reparse = real_rp
    check(rk == "skipped" and M._stale_kind(os.path.join(sk, "a" + chr(0) + "b.md")) == "unreachable",
          "MA/MD: a stale file that is now a link is 'skipped'; a path the OS rejects (NUL) is 'unreachable'")
    real = (M._is_hardlinked, M._canonical, M.GOVERNED_ROOTS)
    try:
        M._is_hardlinked = lambda p: os.path.normcase(p) == os.path.normcase(plain)
        hl = M._stale_kind(plain)
        M._is_hardlinked = real[0]
        M._canonical = lambda p: os.path.normcase(os.path.join(base, ".ssh", "plain.md")) \
            if os.path.normcase(os.path.abspath(p)) == os.path.normcase(plain) else real[1](p)
        cs = M._stale_kind(plain)
        M._canonical = real[1]
        M.GOVERNED_ROOTS = list(real[2]) + [M._canonical(sk)]
        gv = M._stale_kind(plain)
    finally:
        M._is_hardlinked, M._canonical, M.GOVERNED_ROOTS = real
    check(hl == "skipped" and cs == "skipped" and gv == "skipped",
          "X12: hard-linked, canonical-sensitive and governed stale files are 'skipped' (%r, %r, %r)" % (hl, cs, gv))

    # -- X15-X18: --json skipped/unreachable/unchecked keys and the "not checked" text
    sj = os.path.join(base, "jsonkinds")
    f_sk = _write(os.path.join(sj, "a.md"), "# A\n\nWill be classed skipped.\n")
    f_un = _write(os.path.join(sj, "b.md"), "# B\n\nWill be classed unreachable.\n")
    _ingest(sj, "if21_kinds")
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if21_kinds'")
        con.commit()
    finally:
        con.close()
    real_kind = M._stale_kind
    M._stale_kind = lambda sp: ("skipped" if sp == f_sk else "unreachable" if sp == f_un else real_kind(sp))
    try:
        rc, _, dj = _run_json(M.cmd_status)
    finally:
        M._stale_kind = real_kind
    check(dj and dj.get("stale_scan_skipped", {}).get("if21_kinds") == 1
          and dj.get("stale_scan_unreachable", {}).get("if21_kinds") == 1,
          "X16/X17: status --json reports skipped and unreachable stale rows")
    real_budget = M._STATUS_STAT_BUDGET_S
    M._STATUS_STAT_BUDGET_S = 0.2
    M._stale_kind = lambda sp: (time.sleep(0.15), real_kind(sp))[1]
    try:
        rc, _, dj = _run_json(M.cmd_status)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.cmd_status(_Args())
    finally:
        M._stale_kind, M._STATUS_STAT_BUDGET_S = real_kind, real_budget
    check(dj and dj.get("stale_scan_unchecked", 0) > 0 and "not checked within" in buf.getvalue(),
          "X15/X18: unchecked stale rows are reported in --json and in the text")

    # -- X6, X20/X21: stale_left does not list a SIBLING root's rows; more than 5 print "... and N more"
    s1 = os.path.join(base, "sib")
    s2 = os.path.join(base, "sib2")
    _write(os.path.join(s2, "x.md"), "# X\n\nA stale row in the sibling root.\n")
    for i in range(7):
        _write(os.path.join(s1, "g%d.md" % i), "# G\n\nGitignored after the old scan, number %d.\n" % i)
    _ingest(s2, "if21_sib")
    _ingest(s1, "if21_sib")
    con = M.connect()
    try:
        con.execute("UPDATE files SET scan_tag=NULL WHERE project='if21_sib'")
        con.commit()
    finally:
        con.close()
    _write(os.path.join(s1, ".gitignore"), "g*.md\n")
    rc, out = _ingest(s1, "if21_sib")
    check("7 stored file(s) under this root" in out and "sib2" not in out and "... and 2 more" in out,
          "X6/X20/X21: stale_left lists only this root's rows, 5 paths then '... and 2 more'")

    # -- RT6-M4: a root whose name holds a lone surrogate fails per file (rc 4), never a traceback
    sur = os.path.join(base, "dir" + chr(0xDCFF))
    try:
        os.makedirs(sur, exist_ok=True)
        with open(os.path.join(sur, "s.md"), "w", encoding="utf-8") as fh:
            fh.write("# S\n\nA note under a lone-surrogate directory name.\n")
        made = True
    except (OSError, UnicodeError):
        made = False
    if not made:
        print("  NOTE  this file system rejects a lone-surrogate name; RT6-M4 SKIPPED")
    else:
        try:
            rc, out = _ingest(sur, "if21_sur")
            crashed = None
        except Exception as exc:
            rc, crashed = None, "%s: %s" % (type(exc).__name__, exc)
        check(crashed is None and rc == 4, "RT6-M4: a lone-surrogate root returns 4, not a traceback (rc=%r, %a)" % (rc, crashed))

    # -- _bomless_utf16 thresholds (X3, X3b, X3c, X4, X22)
    bu = M._bomless_utf16
    check(bu(b"a\x00" * 65 + b"\x00\x00" * 35) is None, "X3: NULs in BOTH parities (UTF-32-like) are not UTF-16")
    check(bu(b"a\x00" * 55 + b"ab" * 45) is None, "X3b: 55% NUL parity stays under the 60% bar")
    check(bu(b"\x00a" * 65 + b"\x00\x00" * 35) is None, "X3c: BE with NULs in both parities is not UTF-16")
    check(bu(b"a\x00b\x00c\x00") is None, "X4: fewer than 4 code units is never classified")
    check(bu(b"a\x00b\x00c\x00d\x00\x00") == "utf-16-le", "X22: a trailing odd byte is not counted in a parity")

    # -- X33: only a real default-stream SUFFIX is stripped
    check(M._strip_default_stream("C:\\a\\b::$DATAx") == "C:\\a\\b::$DATAx"
          and M._strip_default_stream("C:\\a\\b::$DATA") == "C:\\a\\b",
          "X33: the stream suffix is stripped only at a component end")


def test_ingest_fixes_round8():
    print("\n[22] ingest fixes 2026-10-05, audit round 8")
    base = os.path.join(_TMP, "if22")
    upper = "".join(c for c in _secret("akia22", 80) if c.isupper() or c.isdigit())[:16]
    akia = "AK" + "IA" + upper
    zsplit = akia[:9] + "\N{ZERO WIDTH SPACE}" + akia[9:]

    def joined_leak(project):
        blob = "".join(t for (t,) in _q("SELECT text FROM chunks WHERE project=?", (project,)))
        return akia in "".join(blob.split())                    # pieces split by whitespace rejoin to the key

    # -- R8-F1: NUL-bearing files on the UTF-8 path with an invisible char INSIDE a key are dropped whole
    body = "# K\n\nThe deploy key is %s and the rest is ordinary prose.\n" % zsplit
    shapes = {
        "u8head_u16bom_frag": "Plain UTF-8 prose head line here.\n".encode("utf-8") + b"\xff\xfe" + zsplit.encode("utf-16-le"),
        "u8head_u16le_frag": "Plain UTF-8 prose head line here.\n".encode("utf-8") + zsplit.encode("utf-16-le"),
        "u8head_u32le_frag": "Plain UTF-8 prose head line here.\n".encode("utf-8") + zsplit.encode("utf-32-le"),
        "u8bom_u16le": b"\xef\xbb\xbf" + body.encode("utf-16-le"),
        "odd_u16le": b"x" + body.encode("utf-16-le"),
        "odd_u16be": b"x" + body.encode("utf-16-be"),
        "u32le_nobom": body.encode("utf-32-le"),
        "u32be_nobom": body.encode("utf-32-be"),
        "odd_u32le": b"x" + body.encode("utf-32-le"),          # needs a non-zero UTF-32 alignment offset
    }
    for i, (name, data) in enumerate(shapes.items()):
        d = os.path.join(base, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "k.txt"), "wb") as fh:
            fh.write(data)
        proj = "if22_s%d" % i          # SHORT: a long underscore name is refused as secret-shaped by ingest
        rc, _ = _ingest(d, proj)
        note = _q("SELECT note FROM files WHERE project=?", (proj,))
        check(note == [("SKIPPED-secret:non-utf8-secret",)] and not joined_leak(proj),
              "R8-F1: %s with a ZWSP-split key is dropped whole (rc=%r, %a)" % (name, rc, note))
    # CONTROL: plain UTF-8 (no NUL) with a ZWSP-split key is stripped and REDACTED in place, not dropped
    d = os.path.dirname(_write(os.path.join(base, "u8zw", "k.md"), body))
    _ingest(d, "if22_u8zw")
    note = _q("SELECT note FROM files WHERE project='if22_u8zw'")
    check(note == [(None,)] and not joined_leak("if22_u8zw") and _q("SELECT COUNT(*) FROM chunks WHERE project='if22_u8zw'")[0][0],
          "R8-F1 CONTROL: plain UTF-8 with a ZWSP-split key is redacted in place, not dropped (%a)" % note)

    # -- M89: BOM-less UTF-16 with NO secret is still DECODED (not just NUL-stripped): non-ASCII prose survives.
    #    (Since round 8 the bright line catches these files' secrets either way; detection is about fidelity.)
    for enc in ("utf-16-le", "utf-16-be"):
        d = os.path.join(base, "nobom-" + enc)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "n.txt"), "wb") as fh:
            fh.write(("# N\n\nPlain prose from Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich, nothing secret here.\n").encode(enc))
        proj = "if22_nb%s" % enc[-2:]
        _ingest(d, proj)
        got = _q("SELECT text FROM chunks WHERE project=?", (proj,))
        check(got and "Z\N{LATIN SMALL LETTER U WITH DIAERESIS}rich" in got[0][0],
              "M89: a BOM-less %s file with no secret is decoded, non-ASCII intact" % enc)

    # -- G2: the UTF-8 reading is STRIPPED before scanning (BOM'd UTF-16 head + UTF-8 tail key with a ZWSP)
    d = os.path.join(base, "g2")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "g.txt"), "wb") as fh:
        fh.write(b"\xff\xfe" + "# Log\nFirst line.\n".encode("utf-16-le") + ("tail %s\n" % zsplit).encode("utf-8"))
    rc, out = _ingest(d, "if22_g2")
    note = _q("SELECT note FROM files WHERE project='if22_g2'")
    check(note == [("SKIPPED-secret:non-utf8-secret",)] and "SKIPPED secret FILES : 1" in out,
          "G2/G7: a UTF-8 tail key split by a ZWSP is found once stripped; the first drop is counted (%a)" % note)

    # -- G1: a private-key header visible only in another reading (BOM'd UTF-16 head + UTF-8 ENCRYPTED tail)
    dash = "-" * 5
    pem = "%sBEGIN ENCRYPTED PRIV%s%s\nAbC\n%sEND ENCRYPTED PRIV%s%s\n" % (dash, "ATE KEY", dash, dash, "ATE KEY", dash)
    d = os.path.join(base, "g1")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "p.txt"), "wb") as fh:
        fh.write(b"\xff\xfe" + "# Keys\nbelow\n".encode("utf-16-le") + pem.encode("utf-8"))
    _ingest(d, "if22_g1")
    check(_q("SELECT note FROM files WHERE project='if22_g1'") == [("SKIPPED-secret:non-utf8-secret",)],
          "G1: a private-key header in the UTF-8 reading only drops the file")

    # -- CA8-3: a UTF-16 file dropped for a key, re-saved as UTF-8 with the same text, is redacted and indexed
    d = os.path.join(base, "resave")
    os.makedirs(d, exist_ok=True)
    text = "# R\n\nThe key %s in a note that is later re-saved, long enough.\n" % akia
    p = os.path.join(d, "r.txt")
    with open(p, "wb") as fh:
        fh.write(b"\xff\xfe" + text.encode("utf-16-le"))
    _ingest(d, "if22_resave")
    first = _q("SELECT note FROM files WHERE project='if22_resave'")
    with open(p, "wb") as fh:
        fh.write(text.encode("utf-8"))
    rc, out = _ingest(d, "if22_resave")
    second = _q("SELECT note, chunk_count FROM files WHERE project='if22_resave'")
    # The round-8 `redecide` (index it once re-saved as UTF-8) was REMOVED after round 9 (R9-S1): a dropped
    # file stays dropped while its text is unchanged - the safe direction.
    check(first == [("SKIPPED-secret:non-utf8-secret",)] and second == [("SKIPPED-secret:non-utf8-secret", 0)]
          and not joined_leak("if22_resave"),
          "R9-S1/CA8-3: re-saved as UTF-8 with the same text, a dropped file STAYS dropped (%a -> %a)" % (first, second))

    # -- R9-S1: a MIXED file (UTF-16 prose + UTF-8 key tail) re-saved as its UTF-16 decoding in UTF-8 stays dropped
    d = os.path.join(base, "mixresave")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "m.txt")
    raw = b"\xff\xfe" + ("# M\n\n" + "Ordinary prose written by PowerShell. " * 10 + "\n").encode("utf-16-le") \
        + ("key %s\n" % akia).encode("utf-8")
    with open(p, "wb") as fh:
        fh.write(raw)
    _ingest(d, "if22_mixre")
    t_chosen = raw.decode("utf-16", errors="replace")              # what an editor shows and saves
    with open(p, "wb") as fh:
        fh.write(t_chosen.encode("utf-8"))
    _ingest(d, "if22_mixre")
    note = _q("SELECT note FROM files WHERE project='if22_mixre'")
    blob = "".join(t for (t,) in _q("SELECT text FROM chunks WHERE project='if22_mixre'"))
    recov = any(akia.encode("ascii") in blob.encode(c, "ignore")[o:] for c in ("utf-16-le", "utf-16-be") for o in (0, 1))
    check(note == [("SKIPPED-secret:non-utf8-secret",)] and not recov,
          "R9-S1: a mixed file re-saved as its UTF-16 decoding STAYS dropped; nothing recoverable is stored (%a)" % note)

    # -- R9-M2: the size cap drops a large NUL-bearing file visibly; the scan is fast below it
    d = os.path.dirname(_write(os.path.join(base, "capped", "c.md"), "# C\n\nNo secret here, just prose.\n"))
    with open(os.path.join(d, "c.md"), "ab") as fh:
        fh.write(b"\x00" * 64)
    real_cap = M._ALT_SCAN_CAP
    M._ALT_SCAN_CAP = 50
    try:
        rc, out = _ingest(d, "if22_cap")
    finally:
        M._ALT_SCAN_CAP = real_cap
    check(_q("SELECT note FROM files WHERE project='if22_cap'") == [("SKIPPED-secret:too-large",)]
          and "SKIPPED too large : 1" in out and "SKIPPED secret FILES" not in out,
          "R9-M2/CA10-2: a NUL-bearing file over the scan cap is dropped visibly, reported as too large, not as a secret")
    # CA10-3: the exact boundary - a file of exactly cap bytes is scanned; one byte over is dropped.
    raw_b = b"\xff\xfe" + "# B\n\nBoundary note, nothing secret in it at all.\n".encode("utf-16-le")
    for k, (cap, want) in enumerate(((len(raw_b), None), (len(raw_b) - 1, "SKIPPED-secret:too-large"))):
        bd = os.path.join(base, "bound%d" % k)
        os.makedirs(bd, exist_ok=True)
        with open(os.path.join(bd, "b.txt"), "wb") as fh:
            fh.write(raw_b)
        M._ALT_SCAN_CAP = cap
        try:
            _ingest(bd, "if22_bd%d" % k)
        finally:
            M._ALT_SCAN_CAP = real_cap
        check(_q("SELECT note FROM files WHERE project=?", ("if22_bd%d" % k,)) == [(want,)],
              "CA10-3: cap %s the file size gives %s" % ("==" if k == 0 else "one byte under", want or "indexed"))
    # CA10-3: at the REAL cap, an ordinary few-KB UTF-16 note is indexed (a cap regression would drop these).
    nd = os.path.join(base, "u16note")
    os.makedirs(nd, exist_ok=True)
    with open(os.path.join(nd, "n.txt"), "wb") as fh:
        fh.write(b"\xff\xfe" + ("# N\n\n" + "An ordinary UTF-16 note line, nothing secret. " * 100 + "\n").encode("utf-16-le"))
    _ingest(nd, "if22_u16n")
    check(_q("SELECT note FROM files WHERE project='if22_u16n'") == [(None,)]
          and _q("SELECT COUNT(*) FROM chunks WHERE project='if22_u16n'")[0][0] >= 1,
          "CA10-3: a few-KB UTF-16 note is indexed at the real scan cap")
    big = ("Plain prose line in a UTF-16 log, nothing secret here at all. " * 32 + "\n") * 500    # about 2 MB as UTF-16
    rawbig = b"\xff\xfe" + big.encode("utf-16-le")
    t0 = time.time()
    hits = [r for r in M._alt_readings(rawbig) if M._secret_spans(M._newlines(M._strip_invisible(r)))]
    took = time.time() - t0
    # Bound loosened to 40 s (round-10 code-auditor: 20 s flaked under parallel load); the pre-fix code took ~45 s/MB.
    check(not hits and took < 40.0, "R9-M2: scanning every reading of a %.1f MB UTF-16 file takes %.1fs (< 40s)"
          % (len(rawbig) / 1e6, took))

    # -- R9-M2 equivalence: the regex strip keeps the Cf category, not only Default_Ignorable. U+FFF9 is Cf and
    #    outside every _DEFAULT_IGNORABLE range, so a key split by it is caught only through the Cf half (M120).
    d = os.path.dirname(_write(os.path.join(base, "cf", "c.md"),
                               "# C\n\nKey %s%s%s in prose, long enough.\n" % (akia[:9], chr(0xFFF9), akia[9:])))
    _ingest(d, "if22_cf")
    blob = "".join(t for (t,) in _q("SELECT text FROM chunks WHERE project='if22_cf'"))
    check(blob and akia not in blob.replace(chr(0xFFF9), ""),
          "R9-M2: a key split by U+FFF9 (Cf, not Default_Ignorable) is stripped and redacted")
    check(M._invisible_re().match(chr(0xFFF9)) is not None and M._invisible_re().match("a") is None,
          "R9-M2: the invisible class holds Cf characters outside the Default_Ignorable ranges")

    # -- R9-N1: a .gitignore pattern naming a file whose name holds a ZWNJ still matches it
    d = os.path.join(base, "gizwnj")
    zname = "a\N{ZERO WIDTH NON-JOINER}b.md"
    _write(os.path.join(d, zname), "# Z\n\nIgnored by its exact name, ZWNJ included.\n")
    _write(os.path.join(d, "keep.md"), "# K\n\nKept by the ZWNJ gitignore test.\n")
    _write(os.path.join(d, ".gitignore"), zname + "\n")
    rc, out = _ingest(d, "if22_zw")
    names = sorted(os.path.basename(p) for (p,) in _q("SELECT source_path FROM files WHERE project='if22_zw'"))
    check(names == ["keep.md"], "R9-N1: a gitignore pattern with a ZWNJ matches the ZWNJ file name (%a)" % names)
    # A UTF-8 .gitignore with a stray NUL after a pattern still matches (M121: only NULs and a BOM are removed)
    d = os.path.join(base, "ginul")
    _write(os.path.join(d, "skip.md"), "# S\n\nIgnored despite a stray NUL in the gitignore line.\n")
    _write(os.path.join(d, "keep.md"), "# K\n\nKept by the NUL gitignore test.\n")
    with open(os.path.join(d, ".gitignore"), "wb") as fh:
        fh.write(b"skip.md\x00\n")
    _ingest(d, "if22_gn")
    names = sorted(os.path.basename(p) for (p,) in _q("SELECT source_path FROM files WHERE project='if22_gn'"))
    check(names == ["keep.md"], "M121: a stray NUL in a .gitignore pattern line is removed (%a)" % names)

    # -- CA8-4/5: the hazard scanner - escaped backslash before a class, and linear on unclosed '['
    B = chr(92)
    check(M._rule_hazard(B + B + "[a-z-[b]]") is not None and M._rule_hazard(B + "[ID-[0-9]+" + B + "]") is None
          and M._rule_hazard("[]a-z-[b]]") is not None,
          "CA8-4: an escaped BACKSLASH before a subtraction class is a hazard; an escaped bracket is not")
    t0 = time.time()
    M._rule_hazard("[" * 40000)
    M._rule_hazard("[a" * 20000)
    check(time.time() - t0 < 1.0, "CA8-5: the hazard scan is linear on unclosed '[' (%.3fs)" % (time.time() - t0))

    # -- CA8-2 (G4): a sqlite error on the stale_left query is a WARN (rc stays 0), not silence
    d = os.path.dirname(_write(os.path.join(base, "sq", "s.md"), "# S\n\nA file for the stale_left error branch.\n"))
    real_tag, calls = M._scan_tag, [0]

    def tag_then_fail():
        calls[0] += 1
        if calls[0] > 1:                                       # the per-file call works; the stale_left one fails
            raise sqlite3.OperationalError("database is locked (test)")
        return real_tag()
    import sqlite3
    M._scan_tag = tag_then_fail
    try:
        rc, out = _ingest(d, "if22_sq")
    finally:
        M._scan_tag = real_tag
    check(rc == 0 and "could not check for older-scan rows" in out,
          "CA8-2: a sqlite error on the stale check is WARNED (rc=%r)" % rc)

    # -- R8-F2: a UTF-16 .gitignore is honored
    d = os.path.join(base, "gi16")
    _write(os.path.join(d, "keep.md"), "# K\n\nKept by the UTF-16 gitignore test.\n")
    _write(os.path.join(d, "skip.md"), "# S\n\nIgnored by the UTF-16 gitignore test.\n")
    with open(os.path.join(d, ".gitignore"), "wb") as fh:
        fh.write(b"\xff\xfe" + "skip.md\r\n".encode("utf-16-le"))
    rc, out = _ingest(d, "if22_gi16")
    names = sorted(os.path.basename(p) for (p,) in _q("SELECT source_path FROM files WHERE project='if22_gi16'"))
    check(names == ["keep.md"] and "skipped gitignore : 1" in out, "R8-F2: a UTF-16 .gitignore is honored (%a)" % names)


def main():
    print("Mnemosyne captures regression suite")
    print("DB: %s  (throwaway - the real index is never opened)" % os.environ["MNEMOSYNE_DB"])
    # PER-FUNCTION ISOLATION (X-FIX-3 audit round 1): a CRASH in one test function used to
    # abort main() and silently drop every later function's assertions - no FAIL line, no
    # summary. Each function now runs in its own handler and a crash is recorded as a FAIL.
    try:
        for _t in (test_parser, test_invalid_and_not_capture, test_item_grammar, test_ids_links_forget, test_forget_both_flags, test_forget_project_confirm, test_secrets, test_slugs_survive, test_marker_prune, test_json, test_audit_round1, test_audit_2026_09_27, test_audit_2026_10_02, test_ingest_fixes_2026_10_04, test_ingest_fixes_round1, test_ingest_fixes_round2, test_ingest_fixes_round2_ca, test_ingest_fixes_round3, test_ingest_fixes_round4, test_ingest_fixes_round5, test_ingest_fixes_round6, test_ingest_fixes_round8):
            try:
                _t()
            except Exception as _exc:
                import traceback
                traceback.print_exc()
                check(False, "%s CRASHED: %s: %s" % (_t.__name__, type(_exc).__name__, _exc))
    finally:
        shutil.rmtree(_TMP, ignore_errors=True)
    print("\n%s: %d failure(s)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    for f in FAILS:
        print("  - %s" % f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
