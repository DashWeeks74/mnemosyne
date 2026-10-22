#!/usr/bin/env python3
"""Regression suite for Mnemosyne's store-time redaction and chunking (Session N, 2026-08-03).

Exists because Defect 3 was: the health signal is BLIND to this class. `mnemosyne status` reported
`[OK] bad-retrieval rate 0%` while 27.9% of stored chunks carried a `[secret-redacted]` marker -
nobody flags a hit as bad when the prose is right and only an identifier is masked. This file is the
check that CAN fail on it.

Both directions are asserted, because they are bounded by different evidence (see the memory note
`feedback-corpus-bounds-false-positives`):

  MUST-KEEP  - the false-POSITIVE direction. Sourced from the real corpus.
  MUST-MASK  - the false-NEGATIVE direction. Sourced from an ADVERSARY, not from the corpus, because
               narrowing a deny opens holes a corpus structurally cannot see.

Plus the chunking cap, the chunk-boundary security invariant, and an end-to-end round trip.

Sections [7]-[11] were added by Session X-FIX-1 (2026-08-10) to close the five coverage holes the
Session X audit rated FATAL. Before them this suite could not fail on its own subject: with the
redaction at mnemosyne.py:910 neutered it still reported 103 PASS / exit 0 while two credentials sat
verbatim in the index. The standing acceptance criterion is now the inverse of that measurement -
NEUTER THE REDACTION AND THIS SUITE MUST GO RED. If a future change makes that mutation green again,
the suite has stopped testing the thing it exists to test, whatever its PASS count says.

The round trip runs against a THROWAWAY database - MNEMOSYNE_DB and MNEMOSYNE_LOG_DIR are redirected
before mnemosyne is imported, so this suite can never touch the real index or the real logs.

Run with the install's own venv, from the Mnemosyne folder (it needs hooks\\secret-rules.txt beside
mnemosyne.py; it never reads or writes outside a fresh temp folder otherwise):
    .venv\\Scripts\\python.exe test_redaction.py        (Windows)
    .venv/bin/python test_redaction.py                   (Mac/Linux - Windows-only sections need Windows)
"""
import os
import shutil
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="mnemo-test-")
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


# --------------------------------------------------------------------------------------------
# 1. MUST-KEEP - the false-positive direction, sourced from the real corpus.
# --------------------------------------------------------------------------------------------
MUST_KEEP = [
    # PowerShell verb-noun guard identifiers. All four were absent from EVERY chunk in the real
    # index on 2026-08-03, so lexical search could never match them.
    "Test-MyGuardConfigPath",
    "Test-MyMutatingCommand",
    "Test-MyShortNamePath",
    "ConvertTo-MyCanonicalPath",
    "Get-MyGovernedPatterns",
    "Test-MySensitivePath",
    "Test-MyGovernedRefsAllInWriteRoots",
    # SCREAMING_SNAKE and hyphenated caps.
    "APP_REVIEW_CHECKLIST",
    "MIN_QUERIES_FOR_SIGNAL",
    "MY-GOVERNED-FIXTURE-",
    # Memory-note slugs. The first two busted the old 36-char cap; the third did not, which is what
    # split three near-identical slugs in the same frontmatter position and made the bug look random.
    "feedback-corpus-bounds-false-positives",
    "project-fixture-root-in-governed-list",
    "feedback-redteam-fixture-root",
    "feedback-debugger-vs-inline-measure",
    # Design-doc slugs, including date-prefixed ones.
    "session-g-setup-script-invocation-design",
    "2026-07-19-app-indicator-standardization-design",
    # Path fragments - the single largest masked class in the corpus (57 occurrences for the first).
    "/MyProject/workspace/indicators/charting",
    "/MyProject/hooks/command-guard",
    "indicators/charting/_app/_tools/encoding-gate",
    "/c/MyProject/hooks",
    # Font and product names.
    "IBMPlexMono-SemiBold",
    "AcmeWidgets-branded",
]

# Structures that carry MEANING, not just a name. The memory graph is built out of these; the old
# rule ate the link TARGETS, so "which memory notes exist" became unanswerable inside the index.
MUST_KEEP_STRUCTURE = [
    "See [[feedback-corpus-bounds-false-positives]] for the rule.",
    "See [[project-fixture-root-in-governed-list]] for the workflow.",
    "- [Guard fix queue (2026-08-01)](project_guard_fix_queue.md) - 4 items",
    "- [Validated behaviors](feedback_validated_behaviors.md) - verify before acting",
    "An override for the config dir (MY_HOOKS_CONFIG_DIRECTORY or similar) is the worst option.",
]


def test_must_keep():
    print("\n[1] MUST-KEEP - identifiers, paths and link targets survive (false-positive direction)")
    for tok in MUST_KEEP:
        out, n = M.redact_secrets(tok)
        check(n == 0 and out == tok, "kept: %s" % tok)
    for text in MUST_KEEP_STRUCTURE:
        out, n = M.redact_secrets(text)
        check(n == 0 and out == text, "kept intact: %s" % text[:58])


# --------------------------------------------------------------------------------------------
# 2. MUST-MASK - the false-negative direction, sourced from an ADVERSARY.
#    Strings are ASSEMBLED at runtime so this file never contains a credential-shaped literal.
# --------------------------------------------------------------------------------------------
def _b64ish(seed, n, alphabet=None):
    """Deterministic pseudo-random credential-shaped material (no RNG seed drift across runs)."""
    import hashlib
    alphabet = alphabet or "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    out, h = [], hashlib.sha256(seed.encode()).digest()
    while len(out) < n:
        for b in h:
            out.append(alphabet[b % len(alphabet)])
            if len(out) >= n:
                break
        h = hashlib.sha256(h).digest()
    return "".join(out)


def _must_mask_cases():
    cases = [
        ("random base64-ish 40",            _b64ish("a", 40)),
        ("random base64-ish 32",            _b64ish("b", 32)),
        ("random base64-ish 24",            _b64ish("c", 24)),
        ("base64url with - and _",          _b64ish("d", 18) + "-" + _b64ish("e", 18) + "_" + _b64ish("f", 12)),
        ("base64 with / separators",        _b64ish("g", 14) + "/" + _b64ish("h", 14) + "/" + _b64ish("i", 14)),
        ("letters-only, no separator",      _b64ish("j", 30, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")),
        ("hex 64",                          _b64ish("k", 64, "0123456789abcdef")),
        ("hex 40 dash-chunked",             "-".join(_b64ish("l" + str(i), 8, "0123456789abcdef") for i in range(5))),
        ("prefixed token, mixed suffix",    "svc-20260803-88213-" + _b64ish("m", 16)),
        ("JWT-shaped, three parts",         ".".join(_b64ish("n" + str(i), 22) for i in range(3))),
        ("uuid",                            "c907226a-b174-4caa-b2e3-464e23607e61"),
        # The design-DA's constructed "un-branded internal token" shape, all three case spellings.
        # The all-lowercase one was EXEMPT under the pre-2026-08-03 rule; the long numeric-part cap
        # closes all three, so this is the one place the change is strictly stricter than before.
        ("DA shape, lowercase",             "svc-20260803-88213-qwertyasdfgh"),
        ("DA shape, SCREAMING",             "SVC-20260803-88213-QWERTYASDFGH"),
        ("DA shape, Pascal",                "Svc-20260803-88213-Qwertyasdfgh"),
        ("DA shape, digit in suffix",       "svc-20260803-88213-qwerty7asdfgh"),
        # 12-word hyphen-joined phrase: must exceed the per-segment part cap.
        ("12-word hyphen phrase",           "-".join(["abandon", "ability", "able", "about", "above", "absent",
                                                      "absorb", "abstract", "absurd", "abuse", "access", "accident"])),
        # --- isolated red-team, 2026-08-03 ---
        # FATAL: the max-word-length cap originally fired ONLY when a segment held exactly one word,
        # so any short label defeated it and the blob merely raised the mean. Reproduced, fixed,
        # pinned here at several prefix and blob shapes.
        ("labelled blob, lowercase",        "id-" + _b64ish("rt1", 60, "abcdefghijklmnopqrstuvwxyz")),
        ("labelled blob, SCREAMING",        "KEY-" + _b64ish("rt2", 55, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
        ("labelled blob, snake",            "tok_" + _b64ish("rt3", 40, "abcdefghijklmnopqrstuvwxyz")),
        # Mixed alphabet on purpose: a 17-char run drawn from 26 letters often has <12 distinct
        # characters, which the entropy gate declines for LOW VARIETY - a pass that would prove
        # nothing about the word-length cap this case exists to exercise.
        ("labelled blob, just over 16",     "ref-" + _b64ish("rt4", 17)),
        ("labelled blob, two words",        "sess-" + _b64ish("rt5", 30, "abcdefghijklmnopqrstuvwxyz")
                                            + "-" + _b64ish("rt6", 30, "abcdefghijklmnopqrstuvwxyz")),
        # SERIOUS: a chance false negative on genuinely random base64url. This exact string was
        # exempted before the fix; it is the shape (JWT segment / OAuth token) the heuristic exists
        # to catch, so it is pinned rather than left to the fuzzer to rediscover.
        ("random base64url, chance case",   "PDVGDRKoAebhZX-lRHPIbm"),
    ]
    return cases


def test_must_mask():
    print("\n[2] MUST-MASK - constructed credential shapes still redacted (false-negative direction)")
    for label, s in _must_mask_cases():
        out, n = M.redact_secrets(s)
        check(n >= 1 and M.REDACT_MARK in out and s not in out, "masked: %s" % label)


# --------------------------------------------------------------------------------------------
# 2b. DECLARED RESIDUALS. These are NOT masked, deliberately. Asserting the current behaviour
#     means a future change that silently alters it - in either direction - fails here and has to
#     be argued rather than drifted into. Every one predates 2026-08-03 except where noted.
# --------------------------------------------------------------------------------------------
KNOWN_RESIDUALS = [
    # An unlabeled hyphen-joined word-passphrase is character-identical to a kebab slug. The
    # 2026-08-03 change WIDENS this from <=5 words to <=8 words per path segment. Labeled
    # passphrases are still caught by the denylist rules, which this change does not touch.
    ("hyphen word-passphrase", "correct-horse-battery-staple"),
    # Too few DISTINCT characters to clear the entropy gate (`distinct < 12`), so the entropy path
    # never claimed this shape. Unchanged by the 2026-08-03 rewrite - verified against the prior
    # code, not assumed.
    ("digits-only tuple", "1234-5678-9012-3456-7890"),
]


def test_known_residuals():
    print("\n[2b] DECLARED RESIDUALS - documented gaps, pinned so they cannot drift silently")
    for label, s in KNOWN_RESIDUALS:
        _, n = M.redact_secrets(s)
        check(n == 0, "still exempt (documented residual): %s" % label)


# --------------------------------------------------------------------------------------------
# 3. Chunking honours MAX_CHUNK, except for an unbreakable whitespace-free run.
# --------------------------------------------------------------------------------------------
def test_chunk_cap():
    print("\n[3] chunking - MAX_CHUNK is enforced (Defect 2)")
    bullets = "\n".join("- bullet number %d with some explanatory prose after it, long enough to matter" % i
                        for i in range(120))
    doc = "# Section\n\n" + bullets + "\n"
    chunks = M.chunk_markdown(doc)
    over = [c for c in chunks if len(c[2]) > M.MAX_CHUNK]
    check(len(chunks) > 1, "a 120-bullet list (one paragraph) splits into %d chunks" % len(chunks))
    check(not over, "no chunk exceeds MAX_CHUNK (%d over)" % len(over))

    one_line = "word " * 3000
    chunks = M.chunk_markdown("# S\n\n" + one_line + "\n")
    over = [c for c in chunks if len(c[2]) > M.MAX_CHUNK]
    check(not over, "a single 15000-char line splits at word boundaries (%d over)" % len(over))

    # An unbreakable run is emitted OVER-LONG on purpose - see _split_at_whitespace.
    blob = "x" * 3000
    chunks = M.chunk_markdown("# S\n\n" + blob + "\n")
    check(len(chunks) == 1 and len(chunks[0][2]) == 3000,
          "a whitespace-free 3000-char run is NOT sliced (deliberate; named by the warning)")

    # Ordinals must stay unique per file, or provenance breaks.
    ords = [c[1] for c in M.chunk_markdown(doc)]
    check(len(ords) == len(set(ords)), "chunk ordinals are unique")


def test_real_token_budget():
    """The REAL tokenizer, not approx_tokens.

    approx_tokens assumes 3.5 chars/token; dense technical prose measured 2.05 (0.60 worst case), so
    a chunk inside MAX_CHUNK could still be embed-truncated while the estimate said it was fine.
    Asserting against the estimate here would be asserting through the broken instrument."""
    print("\n[3b] real bge token budget - chunks are not embed-truncated (Defect 2, second half)")
    import mnemo_embed as E
    if not E.EMBED_AVAILABLE:
        check(True, "SKIPPED - embed layer unavailable (lexical-only install)")
        return
    tk = E.get_counting_tokenizer()
    check(tk is not None, "a truncation-free counting tokenizer is reachable")
    if tk is None:
        return
    # Verify the INSTRUMENT before trusting it: a huge string must report >>512, not exactly 512.
    huge = "canonicalisation governed-roots write-roots " * 400
    check(E.count_tokens(huge) > 2000,
          "instrument check: count_tokens does not cap at MAX_TOKENS (got %d)" % E.count_tokens(huge))
    # Dense, token-hungry text: punctuation, code, tables - the shape that broke the estimate.
    dense = "\n".join("| `%s` | `--flag-%d=x` | 0x%04X | %s |" % ("Test-MyGuardConfigPath", i, i * 7,
                                                                  "n/a; see design doc, sec 3.2.1")
                      for i in range(300))
    chunks = M._enforce_token_budget(M.chunk_markdown("# Dense\n\n" + dense + "\n"))
    over = [c for c in chunks if E.count_tokens(c[2]) > E.MAX_TOKENS]
    check(not over, "dense table text: %d chunk(s) over the real 512-token cap" % len(over))
    check(len(set(c[1] for c in chunks)) == len(chunks), "ordinals stay unique after re-splitting")


# --------------------------------------------------------------------------------------------
# 4. SECURITY INVARIANT: a chunk boundary never lands inside a credential.
#    Chunking runs BEFORE redact_secrets, and redaction is per chunk - so a cut inside a token
#    would produce two undetected fragments. This is the design-DA's FATAL finding, pinned.
# --------------------------------------------------------------------------------------------
def test_boundary_never_splits_a_secret():
    print("\n[4] security invariant - chunking cannot tear a credential in half")
    secret = _b64ish("boundary", 44)
    for pad in (900, 1350, 1390, 1400, 1410, 1800, 2600):
        # Place the secret right where a naive slicer would cut.
        body = ("filler " * (pad // 7)) + secret + (" trailing" * 200)
        pieces = [c[2] for c in M.chunk_markdown("# S\n\n" + body + "\n")]
        redacted = [M.redact_secrets(p)[0] for p in pieces]
        intact = sum(1 for p in pieces if secret in p)
        leaked = [r for r in redacted if secret in r]
        check(intact == 1 and not leaked,
              "pad=%-5d secret lives in exactly 1 chunk and is redacted there" % pad)


# --------------------------------------------------------------------------------------------
# 5. END-TO-END round trip through a throwaway DB: ingest -> query.
#    Verification by EXECUTION, not by reasoning about the scanner.
# --------------------------------------------------------------------------------------------
def test_round_trip():
    print("\n[5] round trip - real ingest, real query, throwaway DB")
    src = os.path.join(_TMP, "fixture")
    os.makedirs(src, exist_ok=True)
    tail_marker = "zarquon platypus threnody"          # distinctive, only in the TAIL of a long section
    doc = ["# Guard notes", "",
           "The predicate Test-MyGuardConfigPath is also the write guard's non-promptable deny.",
           "See [[feedback-corpus-bounds-false-positives]] for what a corpus measurement is worth.", ""]
    doc += ["- filler bullet %d about canonicalisation and governed roots and write roots" % i
            for i in range(90)]
    doc += ["- the final bullet mentions %s as the tail sentinel" % tail_marker, ""]
    with open(os.path.join(src, "notes.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(doc))

    class A:  # argparse stand-in
        path = src
        project = "testproj"
        allow_governed = False
        watch = False
    rc = M.cmd_ingest(A())
    check(rc == 0, "ingest returned 0")

    con = M.connect()
    rows = [r[0] for r in con.execute("SELECT text FROM chunks WHERE project='testproj'")]
    con.close()
    check(bool(rows), "chunks were stored (%d)" % len(rows))
    check(any("Test-MyGuardConfigPath" in t for t in rows),
          "the identifier is present in stored text (lexical search can match it)")
    check(any("feedback-corpus-bounds-false-positives" in t for t in rows),
          "the wiki-link target is present in stored text")
    check(not any(M.REDACT_MARK in t for t in rows),
          "no chunk in an ordinary technical note carries a redaction marker")
    check(any(tail_marker in t for t in rows), "the tail of the long section is stored")
    check(all(len(t) <= M.MAX_CHUNK for t in rows), "every stored chunk is within MAX_CHUNK")
    import mnemo_embed as E
    if E.EMBED_AVAILABLE:
        bad = [t for t in rows if E.count_tokens(t) > E.MAX_TOKENS]
        check(not bad, "every stored chunk is within the REAL 512-token cap (%d over)" % len(bad))

    class Q:
        query = "Test-MyGuardConfigPath what does it protect"
        k = 5
        project = "testproj"
        lexical = True
    rc = M.cmd_query(Q())
    check(rc == 0, "query returned 0")


# --------------------------------------------------------------------------------------------
# 6. FORBIDDEN TREES - '.claude' must be unindexable from EVERY start point (Session N2, 2026-08-04).
#
#    SKIP_DIRS already listed '.claude', but it is consulted only in the os.walk dirname prune, so it
#    fires only when the walk DESCENDS past the directory. Measured 2026-08-04: pointing ingest at a
#    file inside .claude, or at a directory already inside it, ingested the content - both bypasses
#    proven by execution. 12 rows from the default account's memory tree had entered the real index
#    that way. These cases pin all three start points so the prune-only regression cannot return.
# --------------------------------------------------------------------------------------------
def test_forbidden_tree():
    print("\n[6] forbidden trees - .claude is unindexable from every start point")

    # predicate level
    cases_true = [
        r"C:\Users\someone\.claude\projects\x\memory\note.md",
        r"C:\Users\someone\.claude",
        r"C:/Users/someone/.claude/projects/x/note.md",
        r"C:\a\.CLAUDE\b\note.md",                      # case-insensitive
    ]
    cases_false = [
        r"C:\MyProject\workspace\docs\design.md",
        r"C:\MyProject\projects\c--MyProject-workspace\memory\note.md",
        r"C:\Users\someone\AppData\Local\Temp\fixture\note.md",   # temp fixtures must still work
        r"C:\a\claude\b\note.md",                       # no leading dot - a normal directory
        r"C:\a\.claudex\b\note.md",                     # near-miss name
    ]
    for p in cases_true:
        check(M.is_forbidden_tree(p), "forbidden: %s" % p)
    for p in cases_false:
        check(not M.is_forbidden_tree(p), "allowed  : %s" % p)

    # end to end - all three start points, driven through cmd_ingest
    base = os.path.join(_TMP, "fakehome")
    inner = os.path.join(base, ".claude", "projects", "memory")
    os.makedirs(inner, exist_ok=True)
    note = os.path.join(inner, "note.md")
    with open(note, "w", encoding="utf-8") as fh:
        fh.write("# Synthetic\n\nProse long enough to clear the minimum chunk size for ingestion.\n")

    class A(object):
        def __init__(self, path, project):
            self.path = path
            self.project = project
            self.allow_governed = False
            self.watch = False

    def stored(project):
        con = M.connect()
        try:
            return con.execute("SELECT COUNT(*) FROM chunks WHERE project=?", (project,)).fetchone()[0]
        finally:
            con.close()

    rc = M.cmd_ingest(A(note, "forbid_file"))
    check(rc != 0 and stored("forbid_file") == 0, "direct FILE inside .claude is refused")

    rc = M.cmd_ingest(A(inner, "forbid_dir"))
    check(rc != 0 and stored("forbid_dir") == 0, "directory INSIDE .claude is refused")

    rc = M.cmd_ingest(A(base, "forbid_above"))
    check(stored("forbid_above") == 0, "walk from ABOVE .claude indexes nothing from it")

    # --- the FATAL the red-team found 2026-08-04 ------------------------------------------------
    # The root check fires only on the ingest ROOT, and the dirname prune was CASE-SENSITIVE, so
    # walking a PARENT of '.CLAUDE' indexed its contents with exit 0 and no refusal. These cases
    # pin the walk vector at every case spelling; they FAIL against the pre-fix code.
    for vi, variant in enumerate([".CLAUDE", ".Claude", ".cLaUdE"]):
        # A DISTINCT parent per variant (fixed 2026-10-04). 'walkcase_CLAUDE' / '_Claude' / '_cLaUdE' are ONE
        # directory on a case-insensitive disk, so the '.Claude' and '.cLaUdE' dirs were never created
        # (makedirs found '.CLAUDE'), and the sibling check passed only because the CA-4 defect indexed
        # the same tree again under each typed case. CA-4 (on-disk storage spelling) exposed it.
        parent = os.path.join(_TMP, "walkcase%d_%s" % (vi, variant.strip(".")))
        vdir = os.path.join(parent, variant)
        os.makedirs(vdir, exist_ok=True)
        with open(os.path.join(vdir, "agent-config.md"), "w", encoding="utf-8") as fh:
            fh.write("# Agent config\n\nCANARY_WALK_BYPASS prose long enough to clear the min chunk size.\n")
        # a sibling that legitimately SHOULD be ingested, so this is not a blanket refusal of the parent
        okd = os.path.join(parent, "normal")
        os.makedirs(okd, exist_ok=True)
        with open(os.path.join(okd, "note.md"), "w", encoding="utf-8") as fh:
            fh.write("# Normal\n\nOrdinary prose long enough to clear the minimum chunk size here.\n")

        proj = "walk_" + variant.strip(".")
        M.cmd_ingest(A(parent, proj))
        con = M.connect()
        try:
            leaked = con.execute(
                "SELECT COUNT(*) FROM chunks WHERE project=? AND text LIKE '%CANARY_WALK_BYPASS%'",
                (proj,)).fetchone()[0]
            kept = con.execute(
                "SELECT COUNT(*) FROM chunks WHERE project=? AND source_path LIKE ?",
                (proj, "%" + os.sep + "normal" + os.sep + "%")).fetchone()[0]
        finally:
            con.close()
        check(leaked == 0, "walk from a parent does NOT index %s content" % variant)
        check(kept > 0, "walk from that same parent still indexes the normal sibling (%s)" % variant)

    # --- the tool's OWN write-path (red-team round 2, 2026-08-04) --------------------------------
    # Mnemosyne refused to READ from .claude but would WRITE its index and telemetry INTO one if
    # MNEMOSYNE_DB pointed there. The check exits the process, so it has to be driven out-of-process.
    import subprocess

    evil_db_dir = os.path.join(_TMP, "writepath", ".claude")
    os.makedirs(evil_db_dir, exist_ok=True)
    evil_db = os.path.join(evil_db_dir, "evil.db")
    env = dict(os.environ)
    env["MNEMOSYNE_DB"] = evil_db
    env.pop("MNEMOSYNE_LOG_DIR", None)          # let it derive, so both paths are exercised
    proc = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "mnemosyne.py"),
         "status"],
        env=env, capture_output=True, text=True)
    check(proc.returncode == 2, "an index path inside .claude is refused (exit 2, got %s)" % proc.returncode)
    check(not os.path.exists(evil_db), "and no database file is created there")

    # MNEMOSYNE_DB="" - set but EMPTY. Two-arg .get() treats that as present, so DB_PATH became the
    # empty string, sqlite3.connect("") opens a private temp DB wherever TMP points, and the guard was
    # checking the CWD instead. Import-only subprocess: reads the resolved paths without connecting,
    # so this never opens the real index. (Red-team round 3, 2026-08-04.)
    env_empty = dict(os.environ)
    env_empty["MNEMOSYNE_DB"] = ""
    env_empty.pop("MNEMOSYNE_LOG_DIR", None)
    probe = ("import mnemosyne as m; print(m.DB_PATH); print(m.WATCH_FILE)")
    p2 = subprocess.run([sys.executable, "-c", probe], env=env_empty, capture_output=True, text=True,
                        cwd=os.path.dirname(os.path.abspath(__file__)))
    lines = [ln.strip() for ln in p2.stdout.splitlines() if ln.strip()]
    mod_dir = os.path.dirname(os.path.abspath(M.__file__))
    check(len(lines) == 2 and lines[0] == os.path.join(mod_dir, "mnemosyne.db"),
          'MNEMOSYNE_DB="" falls back to the real default, not the empty string')
    check(len(lines) == 2 and lines[1] == os.path.join(mod_dir, "watch-projects.txt"),
          'MNEMOSYNE_DB="" resolves WATCH_FILE consistently with DB_PATH')

    # STANDALONE BUILD: the built-in default log dir is <install>\logs (beside the default DB), so it
    # needs NO forbidden-tree exemption, and there is none - every log artifact gets the .claude,
    # governed and hard-link checks. Pinned so an exemption flag is not quietly re-introduced.
    check(not hasattr(M, "_LOG_DIR_IS_BUILTIN_DEFAULT"),
          "no builtin-default exemption flag exists")
    check(all(cf for _, _, cf in M._runtime_artifacts()),
          "EVERY runtime artifact (DB, companions, watch file, log dir, log files) gets the .claude check")
    check(M._default_log_dir() == os.path.join(os.path.dirname(os.path.abspath(os.environ["MNEMOSYNE_DB"])),
                                               "logs"),
          "with MNEMOSYNE_DB set, the default log dir follows the DB")
    env_none = dict(os.environ)
    env_none.pop("MNEMOSYNE_DB", None)
    env_none.pop("MNEMOSYNE_LOG_DIR", None)
    p3 = subprocess.run([sys.executable, "-c", "import mnemosyne as m; print(m.LOG_DIR); print(m.DB_PATH)"],
                        env=env_none, capture_output=True, text=True,
                        cwd=os.path.dirname(os.path.abspath(__file__)))
    l3 = [ln.strip() for ln in p3.stdout.splitlines() if ln.strip()]
    check(p3.returncode == 0 and len(l3) == 2 and l3[0] == os.path.join(mod_dir, "logs")
          and l3[1] == os.path.join(mod_dir, "mnemosyne.db"),
          "with no overrides, DB and logs default to the install folder (%r)" % (l3,))
    # and a log dir inside .claude is refused like any other artifact (no default is exempt)
    env_claude_log = dict(os.environ)
    env_claude_log["MNEMOSYNE_LOG_DIR"] = os.path.join(_TMP, "logpath", ".claude", "logs")
    p4 = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      "mnemosyne.py"), "status"],
                        env=env_claude_log, capture_output=True, text=True)
    check(p4.returncode == 2 and not os.path.exists(env_claude_log["MNEMOSYNE_LOG_DIR"]),
          "a log dir inside .claude is refused (exit 2, nothing created; got %s)" % p4.returncode)

    # the watch list must follow the index, not the module directory
    module_default = os.path.join(os.path.dirname(os.path.abspath(M.__file__)), "watch-projects.txt")
    check(os.path.abspath(M.WATCH_FILE) != os.path.abspath(module_default),
          "WATCH_FILE follows MNEMOSYNE_DB rather than the real operator file")
    check(os.path.dirname(os.path.abspath(M.WATCH_FILE)) == os.path.dirname(os.path.abspath(M.DB_PATH)),
          "WATCH_FILE sits beside the index it describes")

    # and the allowed case still works, so this is not a blanket refusal
    ok_dir = os.path.join(_TMP, "sanctioned")
    os.makedirs(ok_dir, exist_ok=True)
    with open(os.path.join(ok_dir, "note.md"), "w", encoding="utf-8") as fh:
        fh.write("# Sanctioned\n\nProse long enough to clear the minimum chunk size for ingestion.\n")
    rc = M.cmd_ingest(A(ok_dir, "allowed_proj"))
    check(rc == 0 and stored("allowed_proj") > 0, "a sanctioned directory still ingests")


# ================================================================================================
# SESSION X-FIX-1 (2026-08-10) - the five coverage holes Session X proved FATAL.
#
# The audit's decisive measurement: across a full green run, `is_governed` was called 13 times and
# returned true 0 times, `is_sensitive_path` 10 times and 0 true, and all 26 real denylist rules
# produced 0 matches across 83 texts. A predicate whose protective branch is never taken cannot be
# pinned by any assertion in the run - `return False` is undetectable BY CONSTRUCTION. Worse, the
# store path was wired to nothing: neutering the redaction at mnemosyne.py:910 left the suite at
# 103 PASS / exit 0 with two credentials sitting verbatim in the index, while the ingest banner
# still printed "token never stored". Sections [7]-[11] close that.
#
# HOW THE FIXTURES REACH THE GATES, and why NOT by parameterising the loaders.
# `HOOKS` (mnemosyne.py:35), `GOVERNED_ROOTS` (:550) and `SECRET_RULES` (:298) are plain module
# globals. A test rebinds them, or points HOOKS at a temp dir and creates the config file there AT
# RUNTIME from inside Python, then re-calls the loader. Adding a `roots=` parameter to
# `load_governed_roots` would be cheaper to write and is REJECTED: it puts an agent-settable
# un-protect switch (`roots=[]`) into guard code to make a test easier, which is exactly what
# Session H rejected for the config path: a protection list must never be switchable off by a
# caller. A test-only log-dir knob would be acceptable precedent - that kind of knob is
# decision-IRRELEVANT, this one would move every verdict.
#
# TWO KINDS OF PIN, because rebinding a global can hide the very mutation it exists to catch.
#   STRUCTURAL - asserts the module-level global IS what its loader returned. Catches the
#                "loader result discarded" class (`GOVERNED_ROOTS = []`), which rebinding masks.
#   FUNCTIONAL - drives the real predicate/loader against a synthetic fixture. Catches the
#                "predicate always returns False" class, and works on any machine.
# Both are needed; neither alone is sufficient.
# ================================================================================================

def _chunk_rows(project, cols="text, anchor, source_path"):
    """Every stored chunk row for a project, read back from the THROWAWAY database."""
    con = M.connect()
    try:
        return list(con.execute("SELECT %s FROM chunks WHERE project=?" % cols, (project,)))
    finally:
        con.close()


def _fts_blob(project):
    """All FTS text+anchor for a project, joined. The FTS table is a SEPARATE copy of the content -
    a fix that redacts `chunks` but not `chunks_fts` still leaves the value searchable and echoed."""
    con = M.connect()
    try:
        rows = con.execute(
            "SELECT f.text, f.anchor FROM chunks_fts f JOIN chunks c ON c.id=f.rowid "
            "WHERE c.project=?", (project,)).fetchall()
    finally:
        con.close()
    return "\n".join((r[0] or "") + "\n" + (r[1] or "") for r in rows)


class _Args(object):
    """argparse stand-in for cmd_ingest."""

    def __init__(self, path, project, allow_governed=False):
        self.path = path
        self.project = project
        self.allow_governed = allow_governed
        self.watch = False


def _write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


# --- runtime path-alias lookups (section [12]) ----------------------------------------------
# Every one of these is derived AT RUNTIME. A pinned literal GUID or a literal HarddiskVolume3 is
# machine-specific and would make section [12] pass or fail for reasons that have nothing to do
# with the guard. Callers ASSERT that these succeeded - see [12d] - rather than silently skipping.
def _volume_name_for(mount):
    r"""'\\?\Volume{GUID}\' for a mount point ('C:\\'), or None."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(64)
        ok = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(mount, buf, 64)
        return buf.value if ok else None
    except Exception:
        return None


def _dos_device_for(dos):
    r"""'\Device\HarddiskVolumeN' for 'C:', or None. Resolves WITHOUT admin (measured 2026-08-12,
    IsUserAnAdmin()==False), which is what makes the GLOBALROOT spellings reachable by an
    unprivileged caller rather than a theoretical curiosity."""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.QueryDosDeviceW(dos, buf, 1024)
        return buf.value if n else None
    except Exception:
        return None


def _own_routable_admin_share(tail):
    r"""(host, spelling, why) for one of THIS box's own ROUTABLE addresses reaching `tail` via C$.

    Runtime-derived: a literal address is machine- and DHCP-specific, which is half of why this
    class cannot be closed by a fixed host list. Loopback is excluded because `locals_` already
    covers it; link-local is excluded because fe80:: is not reachable over SMB here (measured
    2026-08-12: OSError). Returns (None, None, reason) when nothing is reachable.
    """
    import ipaddress
    import socket
    tried = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError as e:
        return None, None, "getaddrinfo failed (%s)" % e
    seen = set()
    for info in infos:
        a = info[4][0].split("%")[0]
        if a in seen:
            continue
        seen.add(a)
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        host = "[%s]" % a if ip.version == 6 else a
        spelling = "\\\\" + host + "\\C$" + tail
        try:
            os.stat(spelling)
        except OSError as e:
            tried.append("%s -> %s" % (host, type(e).__name__))
            continue
        return host, spelling, ""
    return None, None, ("no routable address reached the tree; tried: %s"
                        % (", ".join(tried) or "none found"))


_PROSE = ("Ordinary decision prose, long enough to clear the minimum chunk size so the chunk is "
          "actually stored rather than silently dropped by MIN_CHUNK.")


# --------------------------------------------------------------------------------------------
# 7. THE STORE PATH - redaction must actually be CONNECTED to what gets written. (hole 1, hole 5)
#
#    This is the section the whole X-FIX-1 session is measured by. Sections [2]/[2b] test
#    `redact_secrets` as a pure function and section [5] never plants a secret in its fixture, so
#    before this the two ends were wired to opposite sides of a wire nothing checked was connected.
#    Section [5]'s only redaction assertion - `not any(REDACT_MARK in t for t in rows)` - is
#    satisfied TRIVIALLY by a store that redacts nothing; the assertions here are its inverse.
# --------------------------------------------------------------------------------------------
def test_store_path_redaction():
    print("\n[7] store path - the redactor is CONNECTED to the database (holes 1 and 5)")
    one = _b64ish("store-one", 40)
    two = _b64ish("store-two", 40)          # second secret in the SAME chunk -> hole 5
    src = os.path.join(_TMP, "storepath")
    _write(os.path.join(src, "notes.md"),
           "# Rotation notes\n\n%s The old value %s was retired and the replacement %s was issued "
           "on the same day.\n" % (_PROSE, one, two))

    rc = M.cmd_ingest(_Args(src, "storeproj"))
    check(rc == 0, "ingest returned 0")
    rows = _chunk_rows("storeproj")
    check(bool(rows), "chunks were stored (%d)" % len(rows))

    body = "\n".join(r[0] for r in rows)
    # POSITIVE control first: if nothing was redacted at all, the two absence checks below are
    # vacuous for the same reason section [5]'s was. Assert the marker IS there before asserting
    # the values are NOT.
    check(M.REDACT_MARK in body, "a redaction marker IS present in stored text (positive control)")
    check(one not in body, "first credential is absent from chunks.text")
    check(two not in body, "second credential in the SAME chunk is absent too (hole 5)")

    fts = _fts_blob("storeproj")
    check(one not in fts and two not in fts,
          "neither credential is FTS-searchable (chunks_fts is a separate copy)")

    # Unit-level pin for hole 5: the span list must not be truncated to its first element.
    both = "before " + one + " middle " + two + " after"
    out, n = M.redact_secrets(both)
    check(n == 2 and one not in out and two not in out,
          "redact_secrets masks BOTH spans in one text (n=%d)" % n)


# --------------------------------------------------------------------------------------------
# 8. GOVERNED-TREE REFUSAL - guarantee 1, previously asserted NOWHERE. (hole 2)
#
#    Mutations `is_governed -> False`, `load_governed_roots -> []` and deleting the per-file
#    re-check inside the walk were ALL green before this section existed. `load_governed_roots -> []`
#    is exactly what happens if governed-roots.txt is emptied, renamed, or its parse breaks - the
#    partial-edit residual the design already declares, which until now had no test-side backstop.
# --------------------------------------------------------------------------------------------
def test_governed_refusal():
    print("\n[8] governed trees - the refusal that guarantee 1 rests on")

    # -- 8a STRUCTURAL: the live list is what the loader returned -----------------------------
    # Catches "loader result discarded" (`GOVERNED_ROOTS = []`), which 8b-8d cannot catch because
    # they rebind the global themselves. Stated as an EQUALITY, not a non-emptiness: a machine that
    # legitimately governs nothing must still pass (no governed-roots.txt is the NORMAL install).
    check(M.GOVERNED_ROOTS == M.load_governed_roots(),
          "module GOVERNED_ROOTS is exactly what load_governed_roots() returns")

    # -- 8b FUNCTIONAL: the loader really reads a real file ------------------------------------
    # Session X could only prove the parse at the LINE level - a shell guard leaf-matched the config
    # filename, so no fixture could be created by a shell command. Created here from inside Python
    # at runtime instead, which exercises the os.path.exists + utf-8-sig decode the audit could not.
    gov_root = os.path.join(_TMP, "govtree")
    os.makedirs(gov_root, exist_ok=True)
    fake_hooks = os.path.join(_TMP, "fakehooks")
    os.makedirs(fake_hooks, exist_ok=True)
    saved_hooks = M.HOOKS
    try:
        M.HOOKS = fake_hooks
        _write(os.path.join(fake_hooks, "governed-roots.txt"),
               "# synthetic fixture - never the operator's real list\n" + gov_root + "\n")
        loaded = M.load_governed_roots()
        check(M._canonical(gov_root) in loaded,
              "the loader reads a real file and canonicalises the root it finds")
    finally:
        M.HOOKS = saved_hooks
    check(M.HOOKS == saved_hooks, "HOOKS is restored after the loader fixture")

    saved_roots = M.GOVERNED_ROOTS
    try:
        M.GOVERNED_ROOTS = [M._canonical(gov_root)]

        # -- 8c FUNCTIONAL: the predicate's PROTECTIVE branch is taken -------------------------
        inside = os.path.join(gov_root, "sub", "note.md")
        for p, want, label in [
            (gov_root, True, "the governed root itself"),
            (inside, True, "a file inside the governed root"),
            (gov_root + "-sibling", False, "a near-miss sibling with the root as a name PREFIX"),
            (os.path.join(_TMP, "elsewhere", "note.md"), False, "an unrelated path"),
        ]:
            check(M.is_governed(p) is want, "is_governed=%s: %s" % (want, label))

        # -- 8d END TO END: ingest AT a governed root is refused -------------------------------
        _write(os.path.join(gov_root, "positions.md"),
               "# Live positions\n\n%s CANARY_GOVERNED_ROOT must never be indexed.\n" % _PROSE)
        rc = M.cmd_ingest(_Args(gov_root, "gov_root_proj"))
        rows = _chunk_rows("gov_root_proj")
        check(rc == 2, "ingest AT a governed root exits 2 (got %s)" % rc)
        check(not rows, "and stores nothing (%d chunks)" % len(rows))

        # -- 8e END TO END: the PER-FILE re-check inside the walk ------------------------------
        # mnemosyne.py:993. The root-level check cannot see this: the ingest root is ungoverned and
        # the governed tree is reached by descending into it. Deleting this clause was a GREEN
        # mutation. The sibling assertion keeps it honest - this must be a targeted skip, not a
        # blanket refusal of the parent.
        parent = os.path.join(_TMP, "govwalk")
        gov_sub = os.path.join(parent, "live_stack")
        _write(os.path.join(gov_sub, "positions.md"),
               "# Live\n\n%s CANARY_GOVERNED_SUBDIR must never be indexed.\n" % _PROSE)
        _write(os.path.join(parent, "normal", "note.md"), "# Normal\n\n%s\n" % _PROSE)
        M.GOVERNED_ROOTS = [M._canonical(gov_sub)]
        M.cmd_ingest(_Args(parent, "gov_walk_proj"))
        walk_rows = _chunk_rows("gov_walk_proj")
        blob = "\n".join(r[0] for r in walk_rows)
        kept = [r for r in walk_rows if (os.sep + "normal" + os.sep) in r[2]]
        check("CANARY_GOVERNED_SUBDIR" not in blob,
              "walking a parent does NOT index the governed subdirectory (per-file re-check)")
        check(bool(kept), "and the ungoverned sibling in that same walk IS still indexed")

        # -- 8f DEFECT PIN, STILL OPEN (label corrected by X-FIX-2) ----------------------------
        # `is_governed` tests `p.startswith(r + os.sep)` (mnemosyne.py), so a bare drive root
        # becomes "c:\\" and prefixes NOTHING: `C:\` in governed-roots.txt protects ZERO paths while
        # looking maximal. This asserts TODAY'S BEHAVIOUR so the defect cannot drift unnoticed; it is
        # NOT a statement that the behaviour is correct. Same convention as Session B's git revspecs
        # and Session K's two residuals: a wrong behaviour is pinned as wrong and labelled, never
        # silently encoded.
        #
        # LABEL CORRECTED 2026-08-11: this said "EXPECTED TO FLIP in X-FIX-2". X-FIX-2 ran and did
        # NOT touch it - its scope was the namespace-reduction port and the SENSITIVE_PATH[3] typo,
        # and the bare-drive-root question belongs to F3 (the governed-roots.txt PARSE divergence),
        # which is still open. A pin labelled with a session that has already shipped reads as
        # "someone forgot", which is how a deliberate deferral decays into an apparent oversight.
        # It carries no session name now: it flips when F3 closes, whichever session does that.
        # Note the ruling already made on the PowerShell guard's side: skip a
        # bare drive root at load, count it, and let the heartbeat warn. That is a census FINDING
        # to port, not a novel judgement to make.
        #
        # F3 CLOSED, SEMANTICS RULED (design decision 2026-09-27): a bare drive root is DROPPED AT
        # LOAD AND REPORTED, matching the PowerShell guard. History: before
        # X-FIX-3 it protected ZERO paths (the prefix test needs a separator after it); X-FIX-3's
        # ancestor-identity walk then made it govern the WHOLE DRIVE, so mnemosyne refused to run at
        # all (predicted in project-guard-fix-queue: "F3's expected behaviour INVERTS under an ancestor
        # walk"). Driven through _parse_governed_lines because the real file is hard-denied.
        # Mutation caught: removing the drive-root clause in _parse_governed_lines.
        fixture_root = os.path.join(_TMP, "f3_fixture_root")
        os.makedirs(fixture_root, exist_ok=True)
        roots, skipped = M._parse_governed_lines(
            ["C:\\\n", "d:/\n", "# comment\n", "\n", fixture_root + "\n"])
        check(skipped == ["C:\\", "d:/"],
              "F3: bare drive roots are DROPPED and COUNTED at load (%r)" % (skipped,))
        check(roots == [M._canonical(fixture_root)],
              "F3: an ordinary root on the same list still loads")
        M.GOVERNED_ROOTS = roots
        check(M.is_governed(r"C:\Windows\note.md") is False,
              "F3: so a dropped drive root governs nothing (it does not become whole-drive)")
        _saved_skipped = list(M.GOVERNED_SKIPPED)
        M.GOVERNED_SKIPPED[:] = skipped
        try:
            import contextlib as _cl
            import io as _io

            class _S(object):
                json = False
            with _cl.redirect_stdout(_io.StringIO()) as _out:
                M.cmd_status(_S())
        finally:
            M.GOVERNED_SKIPPED[:] = _saved_skipped
        check("line IGNORED" in _out.getvalue() and "d:/" in _out.getvalue(),
              "F3: and `status` reports every dropped line, loudly")
        # DRIVE-RELATIVE and other NON-ABSOLUTE lines (round 9, both auditors): 'C:' and 'C:.' used to
        # canonicalize against the process CWD - a governed root that moved with the launch directory.
        # Checked from TWO working directories so a CWD-dependent result cannot pass by luck.
        # Mutation caught: removing the raw-absolute check.
        _cwd0 = os.getcwd()
        try:
            for _where in (os.path.splitdrive(_TMP)[0] + os.sep, _TMP):
                os.chdir(_where)
                r2, s2 = M._parse_governed_lines(["C:\n", "C:.\n", "PROD\\live\n", "\\no-drive\n"])
                check(r2 == [] and s2 == ["C:", "C:.", "PROD\\live", "\\no-drive"],
                      "F3: drive-relative / relative / drive-less lines are DROPPED, cwd=%s (%r)"
                      % (_where, r2))
                # NAMESPACE-PREFIXED drive-relative forms (round-10 red-team): they pass a RAW prefix
                # test but reduce to 'C:'. Mutation caught: checking the raw line instead of the
                # namespace-reduced one.
                ns = ["\\\\?\\C:", "//?/C:", "\\\\.\\C:", "\\??\\C:", "\\\\?\\C:."]
                r3, s3 = M._parse_governed_lines([x + "\n" for x in ns])
                check(r3 == [] and s3 == ns,
                      "F3: namespace-prefixed drive-relative lines are DROPPED, cwd=%s (%r)"
                      % (_where, r3))
        finally:
            os.chdir(_cwd0)
    finally:
        M.GOVERNED_ROOTS = saved_roots
    check(M.GOVERNED_ROOTS == saved_roots, "GOVERNED_ROOTS is restored after the fixtures")


# --------------------------------------------------------------------------------------------
# 9. CREDENTIAL-FILENAME FILTER - the 12-pattern SENSITIVE_PATH list, previously exercised by
#    not one single assertion. (hole 3)
#
#    `is_sensitive_path -> False` was a 103 PASS mutation. Config and credential files are the
#    class most likely to carry LABELED secrets, which is the class the entropy path declines.
# --------------------------------------------------------------------------------------------
def test_sensitive_filenames():
    print("\n[9] credential filenames - the SENSITIVE_PATH filter is exercised (hole 3)")
    must_skip = [
        r"C:\proj\.credentials.json",
        r"C:\proj\api-credentials.md",
        r"C:\proj\service-secrets.json",
        r"C:\proj\.env",
        r"C:\proj\.env.production",
        r"C:/proj/keys",                       # see the DEFECT PIN below - forward slash only
        r"C:\proj\.ssh\config",
        r"C:\proj\server.pem",
        r"C:\proj\.aws\credentials",
        r"C:\proj\.npmrc",
        r"C:\home\.gnupg\secring",
        r"C:\proj\id_rsa",
    ]
    must_keep = [
        r"C:\proj\notes.md",
        r"C:\proj\environment-design.md",      # near-miss: contains 'env' but is not .env
        r"C:\proj\credentialing-policy.md",    # near-miss: 'credential' as a word STEM
        r"C:\MyProject\workspace\docs\session-x-mnemosyne-audit.md",
    ]
    for p in must_skip:
        check(M.is_sensitive_path(p), "sensitive: %s" % p)
    for p in must_keep:
        check(not M.is_sensitive_path(p), "ordinary : %s" % p)

    # -- WAS A DEFECT PIN (X-FIX-1), FIXED BY X-FIX-2 2026-08-11 --------------------------------
    # SENSITIVE_PATH[3] (mnemosyne.py) opened with `[\/]`, a class holding an ESCAPED FORWARD SLASH
    # and nothing else, where every sibling pattern uses `[\\/]` - backslash OR slash. On the native
    # Windows paths this tool actually walks, pattern [3] never fired, so the filter's verdict
    # depended on how the caller happened to spell the separator. The names uniquely lost were the
    # key* family with a text extension - key.md, keys.md, apikey.md, api_key.md - which ARE
    # is_ingestible. (secret(s).md and credential(s).md are caught by [1]/[2], which have no
    # separator class; foo.key by [7].)
    #
    # The FIRST of these two assertions FLIPPED from `is False` to `is True` when the fix landed.
    # That is the pin doing its job, NOT an assertion relaxed to get green: it was labelled
    # "flips when fixed" precisely so this moment would be unambiguous. RED-then-GREEN was
    # demonstrated against unmutated production code - flipping the assertion first produced
    # exactly 1 failure, and the one-character regex fix then produced 0.
    #
    # Blast radius MEASURED before shipping, because widening a deny is what this repo does not do
    # as a drive-by (Sessions N and N2 both shipped fix-induced defects into this file): across
    # 1,116 distinct real paths - all 170 source_paths in the author's real index plus every
    # ingestible file in the author's workspace - the widening newly skips ZERO and loosens ZERO. keyboard.md,
    # hotkeys.md, key-bindings.md, monkey.md, turnkey.md, keynote.md and a keys\ DIRECTORY are all
    # unaffected. Direction is fail-safe regardless: over-denying here costs one unindexed file.
    check(M.is_sensitive_path(r"C:\proj\key.md") is True,
          "FIXED (X-FIX-2): backslash path 'key.md' IS filtered - the pin flipped, as labelled")
    check(M.is_sensitive_path(r"C:/proj/key.md") is True,
          "and the identical name spelled with a forward slash still is (unchanged by the fix)")

    # end to end - a credential-named file in an ordinary tree is skipped, its neighbour is not
    src = os.path.join(_TMP, "sensitive")
    _write(os.path.join(src, "api-credentials.md"),
           "# Access\n\n%s CANARY_SENSITIVE_FILENAME must never be indexed.\n" % _PROSE)
    _write(os.path.join(src, "notes.md"), "# Notes\n\n%s\n" % _PROSE)
    M.cmd_ingest(_Args(src, "sens_proj"))
    rows = _chunk_rows("sens_proj")
    blob = "\n".join(r[0] for r in rows)
    check("CANARY_SENSITIVE_FILENAME" not in blob,
          "a credential-named file is not indexed, driven end to end through cmd_ingest")
    check(bool(rows), "and its ordinary neighbour in the same directory still is (%d chunks)" % len(rows))

    # -- the SINGLE-FILE ingest form, which is a DIFFERENT code path ----------------------------
    # Found by the X-FIX-1 red-team, which proved the directory case above cannot pin it.
    # cmd_ingest has TWO is_sensitive_path call sites: one in the os.walk loop (mnemosyne.py:989)
    # and one in the final `for full, _ in targets` loop (:1014). They are NOT equally redundant.
    # When cmd_ingest is pointed at a single FILE the walk never runs (:970-971), so the final-loop
    # check is the ONLY guard on that path - yet deleting it was a fully GREEN mutation, because the
    # directory case above is silenced by the walk-loop check before the final loop is ever reached.
    # This is the audit's "no layer of the layered defences is individually pinned" shape, so each
    # call site now has a case that fails when it alone is removed.
    direct = os.path.join(_TMP, "sensitive_direct", "api-credentials.md")
    _write(direct, "# Access\n\n%s CANARY_SENSITIVE_DIRECT must never be indexed.\n" % _PROSE)
    M.cmd_ingest(_Args(direct, "sens_direct_proj"))
    direct_rows = _chunk_rows("sens_direct_proj")
    check(not direct_rows,
          "a credential-named file named DIRECTLY as the ingest target is skipped too (%d chunks)"
          % len(direct_rows))


# --------------------------------------------------------------------------------------------
# 10. THE DENYLIST HALF OF THE REDACTOR - previously unpinned end to end. (hole 4)
#
#     `load_secret_rules -> []` was a 103 PASS mutation, and so was running with no hooks\ directory
#     at all: the suite could not tell a loaded 26-rule denylist from none. The consequence is not
#     theoretical - a LOW-ENTROPY, WORD-SHAPED labeled value is declined by the entropy path (by
#     design, it is what stops the redactor eating every kebab-case identifier) so the denylist is
#     the ONLY thing that catches that class.
#
#     No real rule text is read, reproduced or asserted on here - only a COUNT, plus synthetic rules.
# --------------------------------------------------------------------------------------------
def test_denylist_is_loaded_and_wired():
    print("\n[10] denylist - rules are loaded AND consulted (hole 4)")

    # -- STRUCTURAL: the live list is what the loader returned, and it is not empty -------------
    # Non-emptiness is asserted here but NOT for GOVERNED_ROOTS (8a), and the asymmetry is
    # deliberate: hooks\secret-rules.txt ships with Mnemosyne, so an empty denylist means the redactor is
    # running on half its logic and the suite SHOULD be red - whereas an empty governed list is a
    # legitimate state (most installs govern nothing).
    reloaded = M.load_secret_rules()
    check(len(M.SECRET_RULES) == len(reloaded),
          "module SECRET_RULES matches load_secret_rules() (%d rules)" % len(M.SECRET_RULES))
    check(len(M.SECRET_RULES) > 0, "the denylist is non-empty - the rules file was found and parsed")

    # -- FUNCTIONAL: a denylist-only value is masked BECAUSE of the denylist --------------------
    # The fixture is chosen so the entropy path provably declines it: all-lowercase short words
    # joined by hyphens is character-identical to a kebab slug. Verified below in both directions,
    # so this cannot pass by the entropy path doing the work.
    denyonly = "sc-fixture-tok-correct-horse-battery"
    _, n_before = M.redact_secrets(denyonly)
    check(n_before == 0,
          "control: the entropy path DECLINES the fixture, so only a rule can catch it")

    saved = M.SECRET_RULES
    try:
        M.SECRET_RULES = [("fixture-rule", __import__("re").compile(r"sc-fixture-tok-[a-z\-]{10,}"))]
        out, n = M.redact_secrets("The retired value was " + denyonly + " and it is gone.")
        check(n == 1 and denyonly not in out and M.REDACT_MARK in out,
              "a synthetic rule masks it -> redact_secrets really consults SECRET_RULES")

        # and end to end into the store, which is where hole 1 and hole 4 compound
        src = os.path.join(_TMP, "denylist")
        _write(os.path.join(src, "notes.md"),
               "# Rotation\n\n%s The retired value was %s and it is gone.\n" % (_PROSE, denyonly))
        M.cmd_ingest(_Args(src, "deny_proj"))
        rows = _chunk_rows("deny_proj")
        blob = "\n".join(r[0] for r in rows)
        check(bool(rows) and M.REDACT_MARK in blob, "positive control: something was redacted on ingest")
        check(denyonly not in blob, "the denylist-only value is absent from chunks.text")
        check(denyonly not in _fts_blob("deny_proj"), "and absent from chunks_fts")
    finally:
        M.SECRET_RULES = saved
    check(M.SECRET_RULES == saved, "SECRET_RULES is restored after the fixture")


# --------------------------------------------------------------------------------------------
# 11. ANCHOR REDACTION (Session X FATAL 2, fixed in X-FIX-1 as a one-line change at
#     mnemosyne.py:917).
#
#     `chunk_markdown` consumes a heading line into the section stack and never appends it to any
#     section body, so heading text survives in exactly ONE place: `anchor`. Before the fix,
#     `ingest_file` redacted `ctext` only and inserted the RAW anchor into both `chunks` and
#     `chunks_fts` - so a secret on a heading line was stored unredacted, FTS-searchable, echoed to
#     the console by `cmd_query`, and written into the dashboard-served query log.
#
#     NOTE what is deliberately NOT redacted: `source_path`. It is the `files` PRIMARY KEY
#     (mnemosyne.py:856) and the join key; `_forget_file` deletes on exact equality (:869-874) and
#     the unchanged-skip selects on it (:887). Redacting or canonicalising it would orphan the
#     corpus while `forget` still printed success. A secret in a FILENAME therefore remains an open
#     finding, recorded for X-FIX-3, not closed here.
# --------------------------------------------------------------------------------------------
def test_anchor_redaction():
    print("\n[11] anchors - a secret on a HEADING line is redacted before it is stored")
    tok = _b64ish("anchor-secret", 40)

    # the mechanism this rests on: heading text reaches `anchor` and nothing else
    pieces = M.chunk_markdown("# Rotated the token %s\n\n%s\n" % (tok, _PROSE))
    check(any(tok in a and tok not in c for a, _o, c in pieces),
          "mechanism: heading text lands in the anchor and NOT in the section body")

    src = os.path.join(_TMP, "anchors")
    _write(os.path.join(src, "notes.md"),
           "# Rotated the token %s\n\n%s\n" % (tok, _PROSE))
    rc = M.cmd_ingest(_Args(src, "anchor_proj"))
    check(rc == 0, "ingest returned 0")
    rows = _chunk_rows("anchor_proj")
    check(bool(rows), "chunks were stored (%d)" % len(rows))

    anchors = "\n".join(r[1] or "" for r in rows)
    check(M.REDACT_MARK in anchors, "positive control: the anchor carries a redaction marker")
    check(tok not in anchors, "the credential is absent from chunks.anchor")
    check(tok not in _fts_blob("anchor_proj"), "and absent from chunks_fts (anchor column included)")


# --------------------------------------------------------------------------------------------
def test_path_namespace_aliases():
    print("\n[12] path-NAMESPACE aliases - Session X FATAL 1 (X-FIX-2 2026-08-11) plus the "
          "\\\\?\\ alias class (X-FIX-2b 2026-08-12)")

    # abspath/realpath PRESERVE Windows namespace prefixes, and is_governed is a string prefix
    # test, so before the fix an aliased spelling of a protected file canonicalised to a
    # DIFFERENT string and slipped the gate: the audit drove 4 aliases end to end at rc=0 with
    # governed content indexed. _reduce_path_namespace (a port of ConvertTo-MyCanonicalPath's
    # reduction block) now runs BEFORE abspath. This section is the regression pin.

    _, tail = os.path.splitdrive(os.path.abspath(_TMP))
    host = os.environ.get("COMPUTERNAME") or "localhost"

    def aliases(base_tail):
        return [
            (r"\\?\ extended-length", "\\\\?\\C:" + base_tail),
            (r"//?/ forward-slash", "//?/C:" + base_tail.replace("\\", "/")),
            (r"\\.\ device form", "\\\\.\\C:" + base_tail),
            (r"\??\ NT object manager", "\\??\\C:" + base_tail),
            (r"\\localhost\C$ share", "\\\\localhost\\C$" + base_tail),
            (r"\\127.0.0.1\C$ share", "\\\\127.0.0.1\\C$" + base_tail),
            (r"\\<hostname>\C$ share", "\\\\" + host + "\\C$" + base_tail),
            (r"\\?\UNC\localhost\C$", "\\\\?\\UNC\\localhost\\C$" + base_tail),
        ]

    # -- 12a CANONICALISER: every alias reduces to the SAME canon as the plain spelling --------
    # Pins the reduction at the level it happens, so DELETING the _reduce_path_namespace call in
    # _canonical goes RED here even if a later edit changes how is_governed compares.
    plain_canon = M._canonical(_TMP)
    for label, spelling in aliases(tail):
        check(M._canonical(spelling) == plain_canon,
              "canon(%s) == canon(plain)" % label)

    # -- 12b PREDICATE: is_governed's protective branch is taken for every alias ---------------
    gov = os.path.join(_TMP, "ns_gov")
    sib = _TMP + os.sep + "ns_gov_sibling"          # shares the root's STRING prefix
    out = os.path.join(_TMP, "ns_elsewhere")
    for d in (gov, sib, out):
        os.makedirs(d, exist_ok=True)
    _, gov_tail = os.path.splitdrive(gov)

    saved_roots = M.GOVERNED_ROOTS
    try:
        M.GOVERNED_ROOTS = [M._canonical(gov)]

        # CONTROL FIRST: if the plain spelling is not governed the fixture never loaded and every
        # green line below would prove nothing (Session H's round-1 failure shape).
        check(M.is_governed(gov) is True, "CONTROL: the plain spelling IS governed")
        for label, spelling in aliases(gov_tail):
            check(M.is_governed(spelling) is True, "alias is governed: %s" % label)

        # CASE INVARIANCE of the DRIVE-LETTER test. Added by X-FIX-2b because every alias at [12b]
        # is built with an UPPER-case 'C', so making a drive check case-sensitive
        # (`^[A-Za-z]:` -> `^[A-Z]:`) was a fully GREEN mutation.
        #
        # EXACTLY ONE OF THESE TWO IS A DETECTOR, AND IT IS NOT THE OBVIOUS ONE. Measured
        # 2026-08-12, each branch mutated ALONE (the `elif` form is unique to the extended-length
        # branch, the plain `if` to the \??\ branch, so the two are separable):
        #   \??\  branch mutated  -> 241 PASS / 1 FAIL   <- the second line below is the sole detector
        #   \\?\  branch mutated  -> 242 PASS / 0 FAIL   <- FULLY GREEN. The first line CANNOT see it.
        # Why the first line cannot: os.path.abspath leaves '\\?\c:\...' untouched (already
        # absolute), and realpath then normalises the drive letter to upper case - VERIFIED even for
        # a NON-EXISTENT target - so X-FIX-2b's own second reduction pass repairs what the mutated
        # first pass missed. Under that mutation cmd_ingest still refuses at rc=2, so there is NO
        # live bypass; the extended-length line is a true-but-non-detecting coverage assertion and is
        # labelled as such rather than left to imply a protection it does not provide. Found by the
        # X-FIX-2b re-pass red-team, which caught this file claiming detection on both branches.
        #
        # The \??\ branch matters even though cmd_ingest rejects that spelling first, because
        # `_assert_safe_runtime_paths` calls is_governed RAW - a miss there is a WRITE-gate hole
        # (see [12j]), which is precisely why the predicate is worth asserting on its own.
        for _pfx, _why in (
            ("\\\\?\\", "extended-length branch - NON-DETECTOR, repaired by the 2nd pass"),
            ("\\??\\", "NT object branch - sole detector of the case-sensitivity mutation"),
        ):
            check(M.is_governed(_pfx + "c:" + gov_tail) is True,
                  "drive-letter test is case-INsensitive (%s, lower-case 'c:')" % _why)

        # -- 12b-i CASE INVARIANCE of the admin-share host compare ----------------------------
        # Closed after the X-FIX-2 red-team proved the pin could not detect its removal: the
        # \\<hostname>\C$ case above is built straight from COMPUTERNAME with NO case variation,
        # so replacing `sh_host.lower() in locals_` with `sh_host in locals_` was a fully GREEN
        # mutation (186 PASS / 0 FAIL) - while being a LIVE bypass, measured: under that mutation
        # a lowercased hostname and 'LOCALHOST' both reach the filesystem and read is_governed
        # False. SMB/NetBIOS resolution is case-insensitive, so case-folding is load-bearing, not
        # decoration. These cases make that mutation RED.
        #
        # THE FIRST TWO ARE COMPLEMENTARY, NOT REDUNDANT - do not "simplify" either away. There are
        # TWO .lower() calls (one on the probe host, one on COMPUTERNAME going into locals_) and
        # they fail differently. MEASURED both ways, on a machine whose COMPUTERNAME is uppercase:
        #   BOTH .lower() removed  -> 'lowercased' FAILS, 'uppercased' passes
        #   probe side only        -> 'uppercased' FAILS, 'lowercased' passes
        # So each of the pair is the ONLY detector of its own mutation. A round-2 adversary applied
        # just the probe-side mutation, saw 'lowercased' pass, and rated it vacuous decoration;
        # running the other mutation shows it is the sole detector there. Neither is redundant with
        # the \\<hostname>\C$ case at 12b either, which is built from the verbatim COMPUTERNAME.
        # The LOCALHOST / LocalHost cases catch BOTH mutations and are the belt to this pair's braces.
        for spelling, why in [
            (host.lower(), "hostname lowercased"),
            (host.upper(), "hostname uppercased"),
            ("LOCALHOST", "localhost in caps"),
            ("LocalHost", "localhost mixed case"),
        ]:
            check(M.is_governed("\\\\" + spelling + "\\C$" + gov_tail) is True,
                  "admin-share host compare is case-insensitive: %s" % why)

        # NEGATIVE CONTROLS: the reduction must not OVER-match. If either flips, the fix is wrong.
        check(M.is_governed(os.path.join(out, "note.md")) is False,
              "NEG CONTROL: an unrelated path is still ungoverned")
        check(M.is_governed(os.path.join(sib, "note.md")) is False,
              "NEG CONTROL: a sibling with the root as a name PREFIX is still ungoverned")

        # A REMOTE host's admin share is a DIFFERENT machine's file and must NOT be reduced to a
        # local drive. Deliberate in the source lib; asserted here so nobody "simplifies" it away.
        remote = "\\\\not-this-box\\C$" + gov_tail
        check(M._canonical(remote).startswith("\\\\"),
              "a REMOTE \\\\host\\C$ share is NOT reduced to a local drive path")
        # CHANGED BY X-FIX-3: this read "and is therefore not governed". An UNREACHABLE host's path
        # cannot be identified, and is_governed treats an unknown identity as GOVERNED (fail closed).
        # Harmless in practice - an unreachable ingest root is refused as "path not found" first -
        # and it is the direction the write gate needs. What still matters is the line above: the
        # remote spelling is not TEXTUALLY rewritten to a local drive.
        check(M._identity_verdict(remote, M._governed_ids()) is None,
              "an UNREACHABLE remote share has an UNKNOWN identity (it cannot be stat'ed)")
        check(M.is_governed(remote) is True,
              "and is therefore treated as governed - fail closed, not a textual match")

        # -- 12c END TO END: the GUARANTEE, not just the predicate -----------------------------
        _write(os.path.join(gov, "positions.md"),
               "# Live positions\n\n%s CANARY_NS_ALIAS must never be indexed.\n" % _PROSE)
        rc = M.cmd_ingest(_Args("\\\\?\\C:" + gov_tail, "ns_alias_proj"))
        rows = _chunk_rows("ns_alias_proj")
        check(rc == 2, "ingest via an aliased spelling is REFUSED (rc=2, was rc=0 pre-fix)")
        check(not rows, "and stores nothing")
        check("CANARY_NS_ALIAS" not in "\n".join(r[0] for r in rows),
              "the governed canary is absent from the index")

        # -- 12d THE \\?\ ALIAS CLASS, CLOSED BY THE POST-REALPATH REDUCTION (X-FIX-2b) ---------
        # This was X-FIX-2's OPEN FATAL, pinned here in both directions with a note that the
        # assertion FLIPS when a fix lands. It has landed, so it is flipped: these spellings are
        # now GOVERNED. That is the designed flip recorded in session-x-fix-2-record.md, not an
        # assertion being relaxed to get green.
        #
        # The first reduction leaves a volume-GUID / GLOBALROOT form INTACT on purpose - stripping
        # one textually yields a CWD-relative string, the source lib's round-3 FATAL - so the
        # aliased spelling canonicalised to a DIFFERENT string and cmd_ingest INDEXED a governed
        # tree through it at exit 0 while the plain spelling refused at rc=2. The closure does not
        # strip anything: realpath RESOLVES all of these to '\\?\C:\...', a spelling the ported
        # clause already handles, so _canonical runs the reduction ONCE MORE on realpath's output.
        # MEASURED non-admin 2026-08-12 - every spelling below has st_dev AND st_ino identical to
        # the plain one, which is what made them live bypasses rather than curiosities.
        #
        # THE RUNTIME LOOKUPS MUST NOT BE ALLOWED TO SKIP. They are the acceptance evidence for
        # this session's whole subject. The shape [12d] previously shipped with - wrap the lookup,
        # get a falsy flag, print a note - deletes the assertions while the suite still prints zero
        # failures. So an unobtainable volume name or device number FAILS here, loudly. (Contrast
        # [12h], a RESIDUAL pin, which may skip: core acceptance may redden the suite, a residual
        # pin may not.)
        vol_name = _volume_name_for("C:\\")
        dev_name = _dos_device_for("C:")
        check(bool(vol_name),
              "runtime lookup: GetVolumeNameForVolumeMountPointW('C:\\') yielded a volume name")
        check(bool(dev_name),
              "runtime lookup: QueryDosDeviceW('C:') yielded a device name (no admin required)")
        if vol_name and dev_name:
            vol = vol_name.rstrip("\\")                       # \\?\Volume{....}
            inner = vol[4:]                                   # Volume{....}
            leaf = gov_tail.lstrip("\\/")
            closed = [
                (r"\\?\Volume{guid}\ lower-case", vol.lower() + "\\" + leaf),
                (r"\\?\Volume{guid}\ UPPER-case", vol.upper() + "\\" + leaf),
                (r"\\?\Volume{guid}\ MiXeD-case",
                 "\\\\?\\" + inner[:8] + inner[8:].upper() + "\\" + leaf),
                (r"\\?\GLOBALROOT\Device\HarddiskVolumeN\ ",
                 "\\\\?\\GLOBALROOT" + dev_name + "\\" + leaf),
                (r"\\?\GLOBALROOT\??\C:\ ", "\\\\?\\GLOBALROOT\\??\\C:" + gov_tail),
            ]
            for label, spelling in closed:
                check(M.is_governed(spelling) is True,
                      "CLOSED by the post-realpath reduction: %s" % label)
                check(os.path.isdir(spelling) is True,
                      "  and it is genuinely readable, so the closure is load-bearing: %s" % label)

            # -- 12d-ii END TO END, BOTH DIRECTIONS ------------------------------------------
            # The Fatal was found end to end (governed content INDEXED at exit 0), so it is
            # closed end to end and not merely at the predicate. The UNGOVERNED control is not
            # decoration: without it, "rc=2, 0 chunks" cannot be distinguished from "ingest is
            # broken". It deliberately runs through the SAME volume-GUID spelling, and against a
            # FIXTURE tree - never a real one.
            _write(os.path.join(gov, "positions.md"),
                   "# Live positions\n\n%s CANARY_GUID_ALIAS must never be indexed.\n" % _PROSE)
            rc_g = M.cmd_ingest(_Args(vol + "\\" + leaf, "guid_alias_proj"))
            g_rows = _chunk_rows("guid_alias_proj")
            check(rc_g == 2,
                  "e2e: ingest via the volume-GUID spelling is REFUSED (rc=2, was rc=0 pre-fix)")
            check(not g_rows, "e2e: and stores nothing (%d rows)" % len(g_rows))
            check("CANARY_GUID_ALIAS" not in "\n".join(r[0] for r in g_rows),
                  "e2e: the governed canary is absent from the index")

            free = os.path.join(_TMP, "ns_free_fixture")
            _write(os.path.join(free, "notes.md"), "%s Ordinary ungoverned fixture prose.\n" % _PROSE)
            free_leaf = os.path.splitdrive(free)[1].lstrip("\\/")
            rc_f = M.cmd_ingest(_Args(vol + "\\" + free_leaf, "guid_free_proj"))
            f_rows = _chunk_rows("guid_free_proj")
            check(rc_f == 0,
                  "CONTROL: an UNGOVERNED fixture still ingests through the SAME spelling (rc=0), "
                  "so the refusal above is a refusal and not a broken ingest")
            check(bool(f_rows), "CONTROL: and it stores its chunk (%d rows)" % len(f_rows))

        # -- 12f SYMLINK WHOSE TARGET IS SPELLED \\localhost\C$\... (X-FIX-2b) ------------------
        # THIS DIFF IS NOT HOST-NEUTRAL, and that is the half most easily missed. The second
        # reduction runs the local-admin-share clause at a callsite it had never run at before -
        # realpath's OUTPUT - and realpath EMITS a UNC form for a directory symlink whose target
        # is spelled as the admin share. MEASURED 2026-08-12 against a fixture:
        #   before : realpath(link)=\\localhost\C$\...\gov  canon=\\localhost\c$\...  governed=False
        #   after  : same realpath, then reduced            canon=c:\...\gov          governed=True
        # So this is a SECOND live bypass the one statement closes. os.walk follows its start
        # point even with followlinks=False, so the end-to-end vector is real, not theoretical.
        # A directory symlink needs Developer Mode or elevation. Where it cannot be created this
        # prints a LOUD note instead of a vacuous PASS - and on that machine the admin-share
        # clause ships UNEXERCISED at its new callsite, which the note says out loud.
        link = os.path.join(_TMP, "ns_link_unc")
        try:
            os.symlink("\\\\localhost\\C$" + gov_tail, link, target_is_directory=True)
            linked = True
        except OSError as e:
            linked = False
            print("  NOTE  symlink->UNC case SKIPPED: cannot create a directory symlink "
                  "(%s: %s)." % (type(e).__name__, e))
            print("        The admin-share clause therefore ships UNEXERCISED at its new "
                  "post-realpath callsite on this machine.")
        if linked:
            check(os.path.realpath(link).startswith("\\\\"),
                  "MECHANISM: realpath really does emit a UNC form for this symlink")
            check(M.is_governed(link) is True,
                  "a symlink whose TARGET is spelled \\\\localhost\\C$ is governed (was False)")
            rc_l = M.cmd_ingest(_Args(link, "ns_link_proj"))
            check(rc_l == 2, "e2e: ingest through that symlink is REFUSED (rc=2, was rc=0 pre-fix)")
            check(not _chunk_rows("ns_link_proj"), "e2e: and stores nothing")

        # -- 12g RESIDUAL, PINNED: the \??\ NT object-manager CLASS survives the closure ---------
        # A CLASS, not two forms. All of these are reachable (isdir True) and same-inode as the
        # plain spelling, and the closure does NOT close them: realpath never emits a \??\ form,
        # so the second reduction has nothing to match. ('\??\C:' is absent on purpose - the
        # ported clause already reduces that one, and it is asserted governed at [12b].)
        #
        # They are contained AT THIS CALLSITE only because os.path.abspath MANGLES them - '\??\x'
        # becomes 'C:\??\x', and '\??\GLOBALROOT\??\C:\x' becomes the drive-RELATIVE 'C:x' because
        # ntpath.join resets on an embedded drive component - and the mangled string then fails
        # os.path.exists, so cmd_ingest exits rc=1 "path not found" BEFORE the governed test ever
        # runs. That is an ACCIDENT of abspath, not a chosen property, which is why it is a pinned
        # residual and not a closed item.
        #
        # "AT THIS CALLSITE" IS LOAD-BEARING - DO NOT READ IT AS "the class is contained". The
        # containment is a property of cmd_ingest's abspath, NOT of the gate, and a DIFFERENT
        # callsite of the same predicate is NOT contained: see [12j], where the same spelling
        # defeats the write-safety gate and a write LANDS in a governed tree. An earlier draft of
        # this comment claimed containment for the class; the X-FIX-2b red-team falsified it.
        #
        # THE PIN ASSERTS THE CONTAINMENT, NOT THE SYMPTOM. A pin of the shape
        # `is_governed(x) is False` + `isdir(x) is True` is PROVABLY BLIND here: mutate
        # cmd_ingest's `root = os.path.abspath(args.path)` to `root = args.path` and the gate moves
        # from rc=1 to rc=0 - it INDEXES a governed tree - while such a pin stays fully GREEN.
        # MEASURED 2026-08-12: that mutation turns the rc==1 assertions below RED. If a future
        # change makes them green under it, this pin has stopped pinning.
        nt_forms = [(r"\??\GLOBALROOT\??\C:\ ", "\\??\\GLOBALROOT\\??\\C:" + gov_tail)]
        if vol_name:
            _inner = vol_name.rstrip("\\")[4:]
            nt_forms.append((r"\??\Volume{guid}\ ",
                             "\\??\\" + _inner + "\\" + gov_tail.lstrip("\\/")))
            nt_forms.append((r"\??\GLOBALROOT\??\Volume{guid}\ ",
                             "\\??\\GLOBALROOT\\??\\" + _inner + "\\" + gov_tail.lstrip("\\/")))
        if dev_name:
            nt_forms.append((r"\??\GLOBALROOT\Device\HarddiskVolumeN\ ",
                             "\\??\\GLOBALROOT" + dev_name + "\\" + gov_tail.lstrip("\\/")))
        for i, (label, spelling) in enumerate(nt_forms):
            check(os.path.isdir(spelling) is True,
                  "REACHABILITY half of the residual: %s reaches the governed tree" % label)
            check(os.path.exists(os.path.abspath(spelling)) is False,
                  "CONTAINMENT half: abspath mangles it to %r, which does not exist - this and NOT "
                  "the governed test is what stops it: %s"
                  % (os.path.abspath(spelling), label))
            proj = "nt_obj_proj_%d" % i
            rc_n = M.cmd_ingest(_Args(spelling, proj))
            check(rc_n == 1,
                  "and cmd_ingest exits rc=1 'path not found' BEFORE the governed test: %s" % label)
            check(not _chunk_rows(proj), "  storing nothing: %s" % label)

        # -- 12j WRITE-GATE FATAL - CLOSED by X-FIX-3 2026-09-27 (history below kept as written) ------
        # Reported by the X-FIX-2b red-team and INDEPENDENTLY VERIFIED here 2026-08-12 before being
        # acted on. It is the counterexample to [12g]'s containment claim.
        #
        # `_assert_safe_runtime_paths()` gates the tool's OWN write targets - the index and the
        # telemetry dir - and is documented to "fail CLOSED and LOUD". It passes LOG_DIR to
        # is_governed() **RAW**: no abspath, unlike cmd_ingest. So a MNEMOSYNE_LOG_DIR spelled
        # \??\GLOBALROOT\??\C:\<governed>\logs reads UNGOVERNED, the gate returns normally, and then
        # `_log_event`'s own os.makedirs/open DO resolve the alias - so the telemetry LANDS INSIDE
        # THE GOVERNED TREE at exit 0. Measured through the real `_log_event`, not a hand-rolled
        # write. That is a guard failing OPEN, which is the one direction a guard may never fail.
        #
        # NOT introduced by X-FIX-2b - this spelling was ungoverned before and after the change -
        # and NOT fixed here: out of scope, recorded and handed off, same disposition as the
        # volume-GUID Fatal in X-FIX-2. Pinned in BOTH directions so it cannot drift silently.
        #
        # THE GENERAL SHAPE, which is worse than any single spelling: `_assert_safe_runtime_paths`
        # is defeated by EVERY is_governed() miss, because it is the one caller that passes its
        # path in RAW. So each alias already pinned in this section as a "read/ingest" defect is
        # ALSO a write-gate defect, and for the UNC-shaped ones the write LANDS - os.path.abspath
        # does not mangle a UNC path the way it mangles a bare \??\ string, and sqlite opens it
        # through CreateFileW like any other file. MEASURED 2026-08-12, same fixture, side by side:
        #   \\[::1]\C$\<gov>\mnemosyne.db   gate FAILS OPEN -> M.connect() SUCCEEDS
        #                                   -> a 49152-byte index LANDS at the plain governed path
        #   \??\GLOBALROOT\??\C:\<gov>\...  gate FAILS OPEN -> sqlite cannot open the mangled string
        #                                   -> nothing lands (CONTAINED BY ACCIDENT, not guarded)
        # So the \??\ half is SERIOUS and the UNC half is FATAL. An earlier draft of this comment
        # called the whole DB_PATH half "contained by accident, twice over" on the strength of the
        # \??\ measurement alone; the X-FIX-2b red-team refuted that generalisation and it was
        # re-measured before this text was rewritten. This escalates the blast radius of the
        # ALREADY-PINNED [12e] and [12h] residuals from "the ingest gate misses them" to "the tool
        # writes its own index into a governed tree at exit 0".

        def _gate_verdict(**over):
            """'refused' | 'open' | 'raised:<Type>' for the write gate under overridden globals.

            A bare `except SystemExit` here was a real defect, found by the X-FIX-2b red-team: any
            OTHER exception out of the gate propagated straight out of this function, crashing the
            process with a traceback and SILENTLY DELETING every assertion after this point -
            including [12i], [12h] and [12e], two of which are OPEN-FATAL pins - with no FAIL line
            for any of them. A test that can vanish is worse than one that fails, so an unexpected
            exception is turned into a reportable verdict instead.
            """
            saved = {k: getattr(M, k) for k in over}
            try:
                for k, v in over.items():
                    setattr(M, k, v)
                try:
                    M._assert_safe_runtime_paths()
                    return "open"
                except SystemExit:
                    return "refused"
                except BaseException as exc:                     # deliberate: see docstring
                    return "raised:%s" % type(exc).__name__
            finally:
                for k, v in saved.items():
                    setattr(M, k, v)

        _saved_log, _saved_db = M.LOG_DIR, M.DB_PATH
        gov_logs = os.path.join(gov, "logs")
        log_alias = "\\??\\GLOBALROOT\\??\\C:" + gov_tail + "\\logs"
        db_plain = os.path.join(gov, "mnemosyne.db")
        db_unc = "\\\\[::1]\\C$" + gov_tail + "\\mnemosyne.db"

        # CLOSED BY X-FIX-3 (2026-09-27): the pins below were DEFECT PINS asserting the gate FAILED
        # OPEN, and have FLIPPED to acceptance, as their comments promised. The closure is the
        # FILE-IDENTITY half of is_governed (X-FIX-3 design): the raw alias is
        # stat'ed exactly as the writer will open it, so a spelling the prefix test cannot reduce
        # still resolves to the governed root's (st_dev, st_ino). The gate now also checks every
        # artifact FILE, not just the two directories - see [13].
        #
        # REACHABILITY FIRST: each refusal is load-bearing only if the alias really reaches the
        # governed tree. Without these, a refusal could come from a broken spelling.
        check(os.path.isdir("\\??\\GLOBALROOT\\??\\C:" + gov_tail) is True,
              "REACHABILITY: the \\??\\GLOBALROOT spelling genuinely reaches the governed fixture")
        check(M.is_governed(log_alias) is True,
              "CLOSED (was OPEN FATAL): the \\??\\GLOBALROOT spelling of a governed log dir IS governed")
        check(_gate_verdict(LOG_DIR=gov_logs) == "refused",
              "CONTROL: the write gate refuses a plainly-spelled governed log dir")
        check(_gate_verdict(DB_PATH=db_plain) == "refused",
              "CONTROL: and a plainly-spelled governed DB_PATH")
        check(_gate_verdict(LOG_DIR=log_alias) == "refused",
              "CLOSED (was FAILS OPEN): the gate REFUSES the aliased log dir")
        # CONTROL the other way: the SAME alias form pointed at an UNGOVERNED dir must still pass,
        # or "refused" above could mean "the gate refuses every \??\ path".
        _free_logs = os.path.join(_TMP, "ns_free_logs")
        os.makedirs(_free_logs, exist_ok=True)
        _free_alias = "\\??\\GLOBALROOT\\??\\C:" + os.path.splitdrive(_free_logs)[1]
        check(_gate_verdict(LOG_DIR=_free_alias) == "open",
              "CONTROL: the SAME alias form to an UNGOVERNED log dir is still allowed")
        check(not os.path.exists(os.path.join(gov_logs, "mnemosyne-queries.jsonl")),
              "and no telemetry file exists inside the governed fixture")

        # The UNC half, where the INDEX ITSELF used to land. Guarded on reachability with a loud
        # NOTE (loopback SMB can be down); the design's identity measurement covers it either way.
        if os.path.isdir("\\\\[::1]\\C$" + gov_tail):
            check(_gate_verdict(DB_PATH=db_unc) == "refused",
                  "CLOSED (was OPEN FATAL): the gate REFUSES a UNC-aliased governed DB_PATH "
                  "(\\\\[::1]\\C$) that does not exist yet (nearest-existing-ancestor identity)")
            check(not os.path.exists(db_plain),
                  "and no index exists inside the governed fixture")
        else:
            print("  NOTE  UNC write-gate acceptance SKIPPED: \\\\[::1]\\C$ is not reachable here.")
        check((M.LOG_DIR, M.DB_PATH) == (_saved_log, _saved_db),
              "LOG_DIR and DB_PATH are restored after the write-gate pins")

        # -- 12i PLACEMENT PIN: the second reduction must NOT be wrapped in abspath ---------------
        # The obvious "tidy-up" is to make the second call symmetric with the first -
        #   ap = os.path.abspath(_reduce_path_namespace(ap))       <- FORBIDDEN
        # - and X-FIX-2b MEASURED that the whole suite stays 100% GREEN under exactly that edit,
        # so without this section the placement decision the entire diff rests on is unpinned.
        # It is not a style question. realpath's fallback can emit a DRIVE-RELATIVE string
        # ('\??\GLOBALROOT\??\C:\x' -> 'C:x', because ntpath.join resets on an embedded drive
        # component), and abspath then FABRICATES an absolute path from it by joining the process
        # CWD. Measured 2026-08-12 on one fixed input, three working directories:
        #   SHIPPED : c:users\...\gov                     governed=False  from all three
        #   ABSPATH : c:\users\...\gov                    governed=True   (cwd C:\)
        #             c:\work\project\users\...          governed=False  (cwd a project folder)
        #             c:\users\...\<tmp>\users\...\gov    governed=False  (cwd the fixture)
        # A gate predicate whose answer depends on the caller's CWD, on a path it invented, is the
        # reduction's own documented round-3 FATAL arriving through the back door. Pinned as
        # CWD-INVARIANCE, which is the property that actually matters, rather than by grepping the
        # source for a forbidden token.
        nt_gr = "\\??\\GLOBALROOT\\??\\C:" + gov_tail
        _drive = os.path.splitdrive(_TMP)[0] + os.sep
        _cwd0 = os.getcwd()
        try:
            seen_canon, seen_gov = [], []
            for _where in (_drive, _TMP):
                os.chdir(_where)
                seen_canon.append(M._canonical(nt_gr))
                seen_gov.append(M.is_governed(nt_gr))
        finally:
            os.chdir(_cwd0)
        check(len(set(seen_canon)) == 1,
              "PLACEMENT: _canonical is CWD-INVARIANT for a drive-relative realpath result - the "
              "second reduction is NOT wrapped in abspath (%r)" % (sorted(set(seen_canon)),))
        check(len(set(seen_gov)) == 1,
              "PLACEMENT: and so is the governed VERDICT, which is the property that matters (%r)"
              % (seen_gov,))

        # -- 12h this box's own ROUTABLE addresses - CLOSED by X-FIX-3 (was an OPEN FATAL residual) --
        # \\10.0.0.171\C$\... and this machine's global IPv6 literals reach the SAME inode as the
        # plain spelling and read is_governed=False - BEFORE AND AFTER this diff. The admin-share
        # clause compares the host against a fixed `locals_` set, a machine's routable addresses
        # are DHCP-mutable, and `.is_loopback` is False for every one of them, so NO name-based
        # fix closes this class. It needs the prefix-OR-identity (st_dev/st_ino) design session.
        # Pinned in BOTH directions so the residual gets the same mechanical visibility the closed
        # items get; the address is derived at runtime, never a literal.
        # Where nothing routable is reachable (VPN, offline, LanmanServer down) this prints a LOUD
        # note rather than reddening the suite for an environment difference - see [12d] for why
        # the asymmetry with core acceptance is deliberate.
        # CLOSED BY X-FIX-3 (2026-09-27) via the identity half - the flip this pin promised. The
        # prefix half still misses it (asserted, so the closure is attributed to the right half and
        # a regression of the identity half cannot hide behind a lucky textual match).
        r_host, r_spelling, r_why = _own_routable_admin_share(gov_tail)
        if r_spelling:
            check(os.path.isdir(r_spelling) is True,
                  "REACHABILITY: this box's routable address %s genuinely reaches the governed tree"
                  % r_host)
            check(not any(M._canonical(r_spelling) == r or M._canonical(r_spelling).startswith(r + os.sep)
                          for r in M.GOVERNED_ROOTS),
                  "ATTRIBUTION: the PREFIX half still misses it (no name list can close this class)")
            check(M.is_governed(r_spelling) is True,
                  "CLOSED (was OPEN FATAL): this box's own routable address %s IS governed" % r_host)
        else:
            print("  NOTE  routable-IP residual UNPINNED on this machine: %s" % r_why)
            print("        The class is still open; see session-x-fix-2b-record.md.")

        # -- 12e \[::1]\C$ - CLOSED by X-FIX-3 (was the SECOND OPEN FATAL; history kept below) ---
        # \\[::1]\C$\... - the IPv6-loopback admin share. _reduce_path_namespace's locals_ set
        # contains the bare "::1", but an IPv6 literal is only legal in a UNC path in BRACKETED
        # form, so the host group captures "[::1]" and the entry is DEAD AS WRITTEN. Found by the
        # X-FIX-2 red-team and independently reproduced: the alias reaches the SAME file as the
        # plain spelling (st_ino and st_dev identical) and cmd_ingest indexed a governed canary
        # at exit 0 through it while the plain spelling refused at rc=2. NOT fixed here by
        # operator ruling 2026-08-11 (record and hand off). The fix is to strip the brackets
        # before comparing; when it lands, the first assertion below FLIPS to True.
        # Pinned in BOTH directions so the defect cannot drift silently.
        # FLIPPED BY X-FIX-3 (2026-09-27). Closed TWICE, deliberately: the brackets are now stripped
        # before the locals_ compare (so '[::1]' reduces textually), and the identity half catches
        # it regardless. '[0:0:0:0:0:0:0:1]' is NOT in the textual list - it is the case that shows
        # the identity half, not the name list, is the real closure.
        check(M._canonical("\\\\[::1]\\C$" + gov_tail) == M._canonical(gov),
              "TEXTUAL: \\\\[::1]\\C$ now reduces to the plain drive spelling (brackets stripped)")
        for spelling in ("[::1]", "[0:0:0:0:0:0:0:1]"):
            ipv6 = "\\\\" + spelling + "\\C$" + gov_tail
            check(M.is_governed(ipv6) is True,
                  "CLOSED (was OPEN FATAL): %s admin share IS governed" % spelling)
        check(os.path.isdir("\\\\[::1]\\C$" + gov_tail) is True,
              "  and it genuinely reaches the governed tree, so the closure is load-bearing")
        # END TO END through the formerly-open spelling, with the ungoverned control.
        _write(os.path.join(gov, "positions.md"),
               "# Live positions\n\n%s CANARY_IPV6_ALIAS must never be indexed.\n" % _PROSE)
        rc6 = M.cmd_ingest(_Args("\\\\[0:0:0:0:0:0:0:1]\\C$" + gov_tail, "ipv6_alias_proj"))
        check(rc6 == 2 and not _chunk_rows("ipv6_alias_proj"),
              "e2e: ingest via \\\\[0:0:0:0:0:0:0:1]\\C$ is REFUSED (rc=%s) and stores nothing" % rc6)
    finally:
        M.GOVERNED_ROOTS = saved_roots
    check(M.GOVERNED_ROOTS == saved_roots, "GOVERNED_ROOTS is restored after the alias fixture")


# --------------------------------------------------------------------------------------------
# 13. X-FIX-3 (2026-09-27): prefix-OR-identity, hard links, the whole-artifact write gate, and
#     chunk-straddling secrets. Designed and devil's-advocated before it was built. Every block names
#     the mutation it exists to catch; each was applied and seen RED (record: x-fix-3 section 4).
# --------------------------------------------------------------------------------------------
def _gate(**over):
    """'refused' | 'open' for the write gate under overridden module globals (restored after)."""
    saved = {k: getattr(M, k) for k in over}
    try:
        for k, v in over.items():
            setattr(M, k, v)
        try:
            M._assert_safe_runtime_paths()
            return "open"
        except SystemExit:
            return "refused"
        except BaseException as exc:                         # never let a crash delete later pins
            return "raised:%s" % type(exc).__name__
    finally:
        for k, v in saved.items():
            setattr(M, k, v)


def test_x_fix_3():
    import contextlib
    import io
    import subprocess
    import time
    print("\n[13] X-FIX-3: identity half, hard links, whole-artifact write gate, straddling secrets")
    base = os.path.join(_TMP, "x3")
    gov = os.path.join(base, "gov")
    gov_sub = os.path.join(gov, "sub")
    free = os.path.join(base, "free")
    for d in (gov_sub, free):
        os.makedirs(d, exist_ok=True)
    _, free_tail = os.path.splitdrive(free)
    saved_roots = M.GOVERNED_ROOTS
    try:
        M.GOVERNED_ROOTS = [M._canonical(gov)]
        ids = M._governed_ids()
        check(len(ids) == 1, "CONTROL: the fixture root has a file identity (%d ids)" % len(ids))

        # -- 13a JUNCTION into a governed SUBDIR, reached through a spelling PREFIX cannot reduce.
        # Mutation caught: dropping the realpath step in _identity_verdict. A junction's own id is
        # the SUBDIR's, never the root's, and \??\ is not textually reduced - so without realpath
        # neither half sees it. Measured 2026-09-27: prefix False, identity True.
        j = os.path.join(free, "j")
        r = subprocess.run(["cmd", "/c", "mklink", "/J", j, gov_sub], capture_output=True)
        check(r.returncode == 0, "FIXTURE: junction free\\j -> gov\\sub created (rc=%s)" % r.returncode)
        via = "\\??\\GLOBALROOT\\??\\C:" + free_tail + "\\j\\mnemosyne.db"
        canon = M._canonical(via)
        check(not any(canon == g or canon.startswith(g + os.sep) for g in M.GOVERNED_ROOTS),
              "ATTRIBUTION: the PREFIX half misses a junction reached via \\??\\GLOBALROOT")
        check(M._identity_verdict(via, ids) is True,
              "the IDENTITY half resolves the junction and finds the governed root")
        check(_gate(DB_PATH=via) == "refused",
              "write gate REFUSES a DB behind a junction into a governed subdir (aliased spelling)")

        # -- 13b FAIL-CLOSED COMPOSITION (design-DA finding 2). Mutation caught: `if v is None:
        # return True` -> `return False` (or the compact `or v is True`). Asserted through the
        # COMPOSED is_governed, not _identity_verdict alone.
        free_note = os.path.join(free, "note.md")
        check(M.is_governed(free_note) is False, "CONTROL: an ungoverned path reads ungoverned")
        orig_iv = M._identity_verdict
        M._identity_verdict = lambda p, i: None
        try:
            check(M.is_governed(free_note) is True,
                  "an UNKNOWN identity makes is_governed return True (fail CLOSED)")
        finally:
            M._identity_verdict = orig_iv
        # A NATURAL None source, no monkeypatch: an ancestor that exists-or-not cannot be decided
        # because the name is invalid (WinError 123, not FileNotFound).
        check(M._identity_verdict(os.path.join(free, "bad<name>", "x.db"), ids) is None,
              "a non-NOT-FOUND stat error (invalid name) yields an UNKNOWN identity")
        check(_gate(DB_PATH=os.path.join(free, "bad<name>", "x.db")) == "refused",
              "and the write gate refuses a DB location it cannot verify")
        # Missing drive: nothing on the chain exists -> unknown -> refused.
        _missing = None
        for _L in "QZYXWVUTS":
            if not os.path.exists(_L + ":\\"):
                _missing = _L + ":\\nowhere\\mnemosyne.db"
                break
        if _missing:
            check(_gate(DB_PATH=_missing) == "refused",
                  "the write gate refuses a DB on a drive that does not exist (%s)" % _missing[:2])

        # -- 13c HARD LINKS (design-DA finding 1, FATAL). Measured: os.link needs no elevation and
        # neither half of is_governed can see one. Mutation caught: removing the _is_hardlinked
        # check from the ingest loop, or from _runtime_path_problem.
        canary = _write(os.path.join(gov, "canary.md"),
                        "# Positions\n\n%s CANARY_HARDLINK must never be indexed.\n" % _PROSE)
        hl_dir = os.path.join(free, "hl")
        os.makedirs(hl_dir, exist_ok=True)
        os.link(canary, os.path.join(hl_dir, "evil.md"))
        _write(os.path.join(hl_dir, "ordinary.md"), "%s CONTROL_ORDINARY_HL ordinary prose.\n" % _PROSE)
        check(M.is_governed(os.path.join(hl_dir, "evil.md")) is False,
              "MECHANISM: is_governed CANNOT see a hard link (this is why the bright line exists)")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = M.cmd_ingest(_Args(hl_dir, "x3_hardlink"))
        blob = "\n".join(t for t, _a, _s in _chunk_rows("x3_hardlink"))
        check(rc == 0 and "CONTROL_ORDINARY_HL" in blob,
              "CONTROL: the ordinary file beside the hard link IS indexed (rc=%s)" % rc)
        check("CANARY_HARDLINK" not in blob, "a hard link to a governed file is NOT indexed")
        check("skipped hard-link : 1" in buf.getvalue(), "and the skip is reported visibly")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc1 = M.cmd_ingest(_Args(os.path.join(hl_dir, "evil.md"), "x3_hardlink_root"))
        check(not _chunk_rows("x3_hardlink_root"),
              "a hard link given as a single-FILE ingest root is NOT indexed either (rc=%s)" % rc1)
        # Write gate: a planted hard link AS an artifact file writes THROUGH to the governed file.
        hl_logs = os.path.join(free, "hl_logs")
        os.makedirs(hl_logs, exist_ok=True)
        gov_target = _write(os.path.join(gov, "target.jsonl"), "")
        check(_gate(LOG_DIR=hl_logs) == "open", "CONTROL: a clean free log dir passes the gate")
        os.link(gov_target, os.path.join(hl_logs, M.QUERY_LOG))
        check(_gate(LOG_DIR=hl_logs) == "refused",
              "write gate REFUSES a log dir whose query log is a hard link (writes through)")
        hl_db = os.path.join(free, "hl_db")
        os.makedirs(hl_db, exist_ok=True)
        os.link(_write(os.path.join(gov, "t2.bin"), ""), os.path.join(hl_db, "m.db-wal"))
        check(_gate(DB_PATH=os.path.join(hl_db, "m.db")) == "refused",
              "write gate REFUSES a DB whose -wal companion is a hard link")

        # -- 13d WATCH_FILE is checked (design section 2.4). Mutation caught: dropping the
        # watch-file entry from _runtime_artifacts.
        check(_gate(WATCH_FILE=os.path.join(gov, "watch-projects.txt")) == "refused",
              "write gate REFUSES a governed WATCH_FILE even when DB_PATH and LOG_DIR are clean")

        # -- 13e TIMEOUT (design-DA finding 3). Mutation caught: a gate with no time bound.
        orig_p, orig_t = M._runtime_path_problem, M._GATE_TIMEOUT_S
        M._runtime_path_problem = lambda: time.sleep(3)
        M._GATE_TIMEOUT_S = 0.3
        try:
            t0 = time.time()
            v = _gate()
            dt = time.time() - t0
        finally:
            M._runtime_path_problem, M._GATE_TIMEOUT_S = orig_p, orig_t
        check(v == "refused" and dt < 2.0,
              "a stalled safety check REFUSES within its bound (%s after %.2fs)" % (v, dt))
        M._runtime_path_problem = lambda: 1 / 0
        try:
            check(_gate() == "refused", "an EXCEPTION inside the safety check REFUSES")
        finally:
            M._runtime_path_problem = orig_p

        # -- 13f UNIDENTIFIED root is reported, not silent.
        ghost = M._canonical(os.path.join(base, "not-created-yet"))
        M.GOVERNED_ROOTS = [M._canonical(gov), ghost]
        check(M._governed_unidentified() == [ghost],
              "a governed root with no file identity is reported by _governed_unidentified")
        M.GOVERNED_ROOTS = [M._canonical(gov)]

        # -- 13g PERFORMANCE: the identity half on a 600-file walk.
        many = os.path.join(free, "many")
        for i in range(30):
            for k in range(20):
                _write(os.path.join(many, "d%02d" % i, "n%02d.md" % k), "x")
        t0 = time.time()
        for dp, _dn, fn in os.walk(many):
            for f in fn:
                M.is_governed(os.path.join(dp, f))
        dt = time.time() - t0
        check(dt < 5.0, "is_governed over 600 files takes %.2fs (< 5s bound; measured ~0.3s)" % dt)
    finally:
        M.GOVERNED_ROOTS = saved_roots
    check(M.GOVERNED_ROOTS == saved_roots, "GOVERNED_ROOTS is restored after [13]")

    # -- 13h CHUNK-STRADDLING SECRET (brief item 4). Mutation caught: removing the whole-file
    # pre-redaction in ingest_file. Measured on the pre-fix code: stored in the clear. The value is
    # IDENTIFIER-shaped so the entropy backstop exempts it - only the labeled rule can catch it, and
    # only if the label and value are seen together.
    val = "correct-horse-battery-staple"
    check(M._entropy_token_kind(val, val) is None,
          "PRECONDITION: the value is exempt from the entropy backstop (else this proves nothing)")
    filler = ("word " * 270).strip()
    doc = "# Notes\n\n" + filler + " password =\n\n" + val + " and more prose follows here.\n"
    sdir = os.path.join(base, "straddle")
    _write(os.path.join(sdir, "n.md"), doc)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(sdir, "x3_straddle"))
    rows = _chunk_rows("x3_straddle")
    # Precondition on the RAW doc: the per-chunk path alone really does put the label and the value
    # in DIFFERENT chunks. (The redacted doc need not split - the mask swallows the blank lines.)
    raw_chunks = [c for _a, _o, c in M.chunk_markdown(doc)]
    check(any("password =" in c and val not in c for c in raw_chunks)
          and any(val in c and "password" not in c for c in raw_chunks),
          "PRECONDITION: raw chunking separates the label from the value (%d chunks)" % len(raw_chunks))
    check(not any(val in r[0] for r in rows),
          "a labeled secret STRADDLING a chunk boundary is masked (was stored in the clear)")
    check(any("more prose follows" in r[0] for r in rows),
          "and the surrounding prose is kept")
    # Heading secret still masked through the new path.
    hdir = os.path.join(base, "heading")
    tok = "ghp_" + "Zq9" * 12 + "x"
    _write(os.path.join(hdir, "h.md"), "# Deploy with %s\n\n%s body text.\n" % (tok, _PROSE))
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(hdir, "x3_heading"))
    hrows = _chunk_rows("x3_heading")
    check(hrows and not any(tok in (r[0] + r[1]) for r in hrows),
          "a secret on a HEADING line is still masked (text and anchor)")


# --------------------------------------------------------------------------------------------
# 14. X-FIX-3 whole-file audit, round 1 findings (isolated red-team + code-auditor, 2026-09-27).
# --------------------------------------------------------------------------------------------
def test_audit_round1():
    import contextlib
    import io
    import random
    import string
    print("\n[14] X-FIX-3 audit round 1: invisible-char secret splitting, per-file ingest isolation, -k")
    base = os.path.join(_TMP, "x3r1")

    # -- 14a INVISIBLE FORMAT CHARACTERS (red-team FATAL). A Cf char every 4 chars split a secret
    # below every rule and below the entropy run length; both passes missed it and the value was
    # stored recoverable by deleting the char. Mutation caught: removing the _strip_format_chars call
    # in ingest_file. Five chars, three secret kinds, driven through the REAL ingest.
    rnd = random.Random(7)
    ent = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(40))
    akia = "AKIA" + "QWERTYUIOPASDFGH"

    def split(s, ch):
        return ch.join(s[i:i + 4] for i in range(0, len(s), 4))

    check(M.redact_secrets(ent)[1] == 1 and M.redact_secrets("aws key " + akia)[1] == 1,
          "CONTROL: both secrets are caught when NOT split")
    for label, ch in (("ZWSP", "\u200b"), ("WJ", "\u2060"), ("SHY", "\u00ad"), ("BOM", "\ufeff"),
                      ("ZWJ", "\u200d")):
        d = os.path.join(base, "cf_" + label)
        _write(os.path.join(d, "n.md"),
               "# Notes\n\n%s entropy %s and aws key %s end.\n" % (_PROSE, split(ent, ch), split(akia, ch)))
        with contextlib.redirect_stdout(io.StringIO()):
            M.cmd_ingest(_Args(d, "x3r1_cf_" + label))
        rows = _chunk_rows("x3r1_cf_" + label)
        blob = "\n".join(r[0] + r[1] for r in rows).replace(ch, "")
        check(rows and ent not in blob and akia not in blob,
              "a secret split by %s is masked, not stored recoverable" % label)
    pk = os.path.join(base, "cf_pk")
    _write(os.path.join(pk, "k.md"), "%s\n-----BEGIN\u200b PRIVATE KEY-----\nMIIB\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(pk, "x3r1_pk"))
    check(not _chunk_rows("x3r1_pk"),
          "a private-key header split by ZWSP still drops the whole file")
    check(M._strip_format_chars("plain ascii") == "plain ascii"
          and M._strip_format_chars("caf\u00e9 \u2014 ok") == "caf\u00e9 \u2014 ok",
          "the strip removes ONLY format chars: ordinary non-ASCII letters and punctuation survive")

    # -- 14b ONE FILE'S EXCEPTION MUST NOT DISCARD THE RUN (auditor SERIOUS). Mutation caught:
    # removing the per-file try/except (the whole run then crashes and commits nothing).
    d = os.path.join(base, "iso")
    for i in range(5):
        _write(os.path.join(d, "f%d.md" % i), "%s ISO_MARK_%d prose.\n" % (_PROSE, i))
    orig = M.ingest_file

    def flaky(con, path, project, stats):
        if path.endswith("f2.md"):
            orig(con, path, project, stats)              # write its rows first, THEN fail
            raise ValueError("injected")
        return orig(con, path, project, stats)
    M.ingest_file = flaky
    try:
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            rc = M.cmd_ingest(_Args(d, "x3r1_iso"))
    finally:
        M.ingest_file = orig
    blob = "\n".join(r[0] for r in _chunk_rows("x3r1_iso"))
    check(all(("ISO_MARK_%d" % i) in blob for i in (0, 1, 3, 4)),
          "the four good files are committed despite one file raising")
    check("ISO_MARK_2" not in blob,
          "the failing file's partial rows are ROLLED BACK (savepoint), not left orphaned")
    check(rc == 4 and "NOT indexed" in buf.getvalue(),
          "and the run exits rc=4 with a visible error, not rc=0 (got rc=%s)" % rc)

    # -- 14c NEGATIVE -k (auditor MINOR). Mutation caught: removing the guard.
    class Q(object):
        query, k, project = "prose", -1, None
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        rc = M.cmd_query(Q())
    check(rc == 2, "query with a negative -k is refused (rc=%s)" % rc)


# --------------------------------------------------------------------------------------------
# 15. X-FIX-3 whole-file audit, round 2 findings (isolated red-team + code-auditor, 2026-09-27).
# --------------------------------------------------------------------------------------------
def test_audit_round2():
    import contextlib
    import hashlib
    import io
    import sqlite3
    print("\n[15] X-FIX-3 audit round 2: non-Cf invisible chars, capture error messages echoing secrets")
    base = os.path.join(_TMP, "x3r2")
    ent = "".join("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[b % 57]
                  for b in hashlib.sha256(b"x3r2-entropy").digest()[:40])
    check(M.redact_secrets(ent)[1] == 1, "CONTROL: the entropy token is caught when not split")

    # -- 15a INVISIBLE NON-Cf CHARACTERS (red-team SERIOUS). Round 1 stripped category Cf only;
    # these are Lo / Mn / tag chars that are Default_Ignorable and do the same job. Mutation caught:
    # reverting _strip_format_chars to the Cf-only test.
    for label, cp in (("HANGUL FILLER", 0x3164), ("HANGUL CHOSEONG FILLER", 0x115F),
                      ("HALFWIDTH HANGUL FILLER", 0xFFA0), ("CGJ", 0x034F), ("VS16", 0xFE0F),
                      ("TAG LATIN A", 0xE0041)):
        ch = chr(cp)
        d = os.path.join(base, "inv_%04x" % cp)
        _write(os.path.join(d, "n.md"), "# Notes\n\n%s value %s end.\n" % (_PROSE, ch.join(ent)))
        with contextlib.redirect_stdout(io.StringIO()):
            M.cmd_ingest(_Args(d, "x3r2_inv_%04x" % cp))
        rows = _chunk_rows("x3r2_inv_%04x" % cp)
        blob = "\n".join(r[0] + r[1] for r in rows).replace(ch, "")
        check(rows and ent not in blob, "a secret split by %s (U+%04X) is masked" % (label, cp))
    check(M._strip_format_chars("\uac00\ud55c \u00e9") == "\uac00\ud55c \u00e9",
          "real Hangul syllables and accented letters are NOT stripped (only fillers are)")

    # -- 15b CAPTURE ERROR MESSAGES MUST NOT ECHO A SECRET (red-team FATAL). The id and link-target
    # checks detected a secret-shaped value and then quoted it into the error, which is stored in
    # files.note and printed. Mutation caught: removing the central redact_secrets(cap_err) AND
    # restoring the quoted value at any site.
    hex64 = hashlib.sha256(b"x3r2-capture-secret").hexdigest()
    akia = "AKIA" + "".join("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[b % 32]
                            for b in hashlib.sha256(b"x3r2-akia").digest()[:16])
    cases = [
        ("id-hex", "---\nkind: capture\nid: %s\nwhat: x\n---\nBody prose here.\n" % hex64, hex64),
        ("id-upper", "---\nkind: capture\nid: %s\nwhat: x\n---\nBody prose here.\n" % akia, akia),
        ("link-hex", "---\nkind: capture\nid: fine-id\nwhat: x\napplies_to:\n  - %s: like\n---\n"
                     "Body prose here.\n" % hex64, hex64),
        # An UNTRUNCATED quoting site: "unknown status '%s'" echoes the raw value and only the central
        # redact_secrets(cap_err) masks it. Added after round 3's _q helper took over the id site and
        # left the central pass with no detector (mutation M18 went GREEN until this case existed).
        ("status", "---\nkind: capture\nid: fine-id\nwhat: x\nstatus: %s\n---\nBody prose here.\n"
                   % hex64, hex64),
    ]
    for label, body, secret in cases:
        d = os.path.join(base, "cap_" + label)
        _write(os.path.join(d, "c.md"), body)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            M.cmd_ingest(_Args(d, "x3r2_cap_" + label))
        con = sqlite3.connect(os.environ["MNEMOSYNE_DB"])
        try:
            notes = [r[0] or "" for r in con.execute(
                "SELECT note FROM files WHERE project=?", ("x3r2_cap_" + label,))]
        finally:
            con.close()
        check(any("CAPTURE-INVALID" in n for n in notes),
              "PRECONDITION (%s): the capture really was rejected, so its error was stored" % label)
        check(not any(secret in n for n in notes),
              "the stored capture error does NOT contain the secret (%s)" % label)
        check(secret not in buf.getvalue(), "nor does the printed ingest output (%s)" % label)


# --------------------------------------------------------------------------------------------
# 16. X-FIX-3 whole-file audit, round 3 findings (isolated red-team + code-auditor, 2026-09-27).
# --------------------------------------------------------------------------------------------
def test_audit_round3():
    import contextlib
    import hashlib
    import io
    import json
    import sqlite3
    print("\n[16] X-FIX-3 audit round 3: query-side secrets, forget case, truncate-then-redact")
    base = os.path.join(_TMP, "x3r3")
    hex64 = hashlib.sha256(b"x3r3-query-secret").hexdigest()
    check(M.redact_secrets("value " + hex64)[1] == 1, "CONTROL: the query secret is redactor-visible")

    # -- 16a QUERY SIDE (red-team FATAL). Mutation caught: logging / printing the raw query.
    _write(os.path.join(base, "q", "n.md"), "%s The credential policy lives here.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(os.path.join(base, "q"), "x3r3_q"))

    class Q(object):
        query = "what is our credential policy, the value is " + hex64
        k, project, lexical = 3, "x3r3_q", True
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        M.cmd_query(Q())
    check(hex64 not in out.getvalue(), "a secret inside a QUERY is not printed to stdout")
    qlog = os.path.join(M.LOG_DIR, M.QUERY_LOG)
    last = io.open(qlog, encoding="utf-8").read().splitlines()[-1]
    check("credential policy" in last, "PRECONDITION: the query really was logged")
    check(hex64 not in last, "and the query LOG entry does not contain the secret")
    Q.json = True
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        M.cmd_query(Q())
    check(hex64 not in out.getvalue() and json.loads(out.getvalue()).get("query"),
          "nor does the --json output")

    class F(object):
        reason = "bad hit, key was " + hex64
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        M.cmd_flag(F())
    flog = io.open(os.path.join(M.LOG_DIR, M.FLAG_LOG), encoding="utf-8").read()
    check(flog.strip() and hex64 not in flog and hex64 not in out.getvalue(),
          "flag-last stores and prints neither the query's nor the reason's secret")

    # -- 16b FORGET --path IS CASE-INSENSITIVE AND HONEST (red-team SERIOUS). Mutation caught:
    # reverting to the exact-match delete that printed "Forgot:" regardless.
    fdir = os.path.join(base, "Corpus")
    fp = _write(os.path.join(fdir, "Notes.md"), "%s FORGET_ME_MARK must be forgotten.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(fdir, "x3r3_forget"))
    check(any("FORGET_ME_MARK" in r[0] for r in _chunk_rows("x3r3_forget")), "PRECONDITION: ingested")

    class G(object):
        project = None
        path = os.path.join(base, "corpus", "notes.md")   # same file, different case
    with contextlib.redirect_stdout(io.StringIO()):
        rc = M.cmd_forget(G())
    check(rc == 0 and not _chunk_rows("x3r3_forget"),
          "forget --path with DIFFERENT CASE removes the rows (rc=%s)" % rc)
    G.path = os.path.join(base, "never-ingested.md")
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = M.cmd_forget(G())
    check(rc == 1 and "nothing forgotten" in out.getvalue(),
          "forget --path of something NOT indexed says so and exits rc=1 (got rc=%s)" % rc)

    # -- 16c TRUNCATE-THEN-REDACT (auditor SERIOUS). A 30-char entropy token placed so the message's
    # 60-char cut keeps only ~15 chars of it - below the 20-char entropy minimum. Mutation caught:
    # reverting any of the three sites to a raw slice.
    tok = "".join("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[b % 57]
                  for b in hashlib.sha256(b"x3r3-trunc").digest()[:30])
    check(M.redact_secrets(tok)[1] == 1, "CONTROL: the full token is caught")
    frag = tok[:15]
    cases = [
        ("frontmatter", "---\nkind: capture\nid: ok-id\nwhat: x\n%s %s\n---\nBody prose.\n" % ("x" * 44, tok)),
        ("id", "---\nkind: capture\nid: %s %s\nwhat: x\n---\nBody prose.\n" % ("X" * 44, tok)),
    ]
    for label, body in cases:
        d = os.path.join(base, "tr_" + label)
        _write(os.path.join(d, "c.md"), body)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            M.cmd_ingest(_Args(d, "x3r3_tr_" + label))
        con = sqlite3.connect(os.environ["MNEMOSYNE_DB"])
        try:
            notes = " ".join(r[0] or "" for r in con.execute(
                "SELECT note FROM files WHERE project=?", ("x3r3_tr_" + label,)))
        finally:
            con.close()
        check("CAPTURE-INVALID" in notes, "PRECONDITION (%s): the capture error was stored" % label)
        check(frag not in notes and frag not in out.getvalue(),
              "a secret straddling a message's truncation point leaves no fragment (%s)" % label)

    # -- 16d the invisible-char strip is REPORTED (auditor MINOR, accepted trade-off made visible).
    d = os.path.join(base, "zwj")
    _write(os.path.join(d, "e.md"), "%s family \U0001F468\u200d\U0001F469 emoji.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()) as out:
        M.cmd_ingest(_Args(d, "x3r3_zwj"))
    check("invisible chars   : 1 removed" in out.getvalue(),
          "removing a ZWJ is reported in the ingest output, not silent")


# --------------------------------------------------------------------------------------------
# 17. X-FIX-3 whole-file audit, round 4 findings (isolated red-team + code-auditor, 2026-09-27).
# --------------------------------------------------------------------------------------------
def test_audit_round4():
    import contextlib
    import hashlib
    import io
    import subprocess
    print("\n[17] X-FIX-3 audit round 4: secret-shaped project names, forget in case-sensitive dirs")
    base = os.path.join(_TMP, "x3r4")
    hex64 = hashlib.sha256(b"x3r4-project-secret").hexdigest()
    check(M.redact_secrets(hex64)[1] == 1, "CONTROL: the project value is redactor-visible")

    # -- 17a PROJECT NAME (red-team). Mutation caught: removing the refusal.
    d = _write(os.path.join(base, "p", "n.md"), "%s PROJECT_MARK plain prose.\n" % _PROSE)
    d = os.path.dirname(d)
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = M.cmd_ingest(_Args(d, hex64))
    check(rc == 2 and hex64 not in out.getvalue() and not _chunk_rows(hex64),
          "a secret-shaped --project is REFUSED (rc=%s), not echoed, nothing stored" % rc)
    bd = os.path.dirname(_write(os.path.join(base, hex64, "n.md"), "%s BASENAME_MARK prose.\n" % _PROSE))
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = M.cmd_ingest(_Args(bd, None))
    check(rc == 2 and "BASENAME_MARK" not in "\n".join(r[0] for r in _chunk_rows(hex64)),
          "the DEFAULT project (a secret-shaped directory basename) is refused too (rc=%s)" % rc)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = M.cmd_ingest(_Args(d, "x3r4_plain"))
    check(rc == 0 and _chunk_rows("x3r4_plain"), "CONTROL: a plain project name still ingests")

    # -- 17b FORGET IN A CASE-SENSITIVE DIRECTORY (auditor SERIOUS, a defect in the round-3 fix).
    # Mutation caught: reverting to normcase-only matching (deletes BOTH files).
    cs = os.path.join(base, "casesens")
    os.makedirs(cs, exist_ok=True)
    r = subprocess.run(["fsutil.exe", "file", "setCaseSensitiveInfo", cs, "enable"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  NOTE  case-sensitive directory unavailable here (fsutil rc=%s); 17b SKIPPED - the "
              "identity-based forget ships UNEXERCISED against a real collision on this machine."
              % r.returncode)
        return
    up = _write(os.path.join(cs, "Foo.md"), "%s CASE_UPPER_MARK one.\n" % _PROSE)
    lo = _write(os.path.join(cs, "foo.md"), "%s CASE_LOWER_MARK two.\n" % _PROSE)
    check(os.stat(up).st_ino != os.stat(lo).st_ino,
          "PRECONDITION: Foo.md and foo.md are genuinely DIFFERENT files in this directory")
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(cs, "x3r4_cs"))
    blob = "\n".join(r[0] for r in _chunk_rows("x3r4_cs"))
    check("CASE_UPPER_MARK" in blob and "CASE_LOWER_MARK" in blob, "PRECONDITION: both are indexed")
    # _resolve_target checks EVERY colliding file's anchors, not an arbitrary first row. Mutation
    # caught: `for (sp,) in rows[:1]` - one of the two anchors below then fails to resolve.
    _write(up, "# AlphaHead\n\n%s CASE_UPPER_MARK one.\n" % _PROSE)
    _write(lo, "# BetaHead\n\n%s CASE_LOWER_MARK two.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(cs, "x3r4_cs"))
    con = M.connect()
    try:
        norm = os.path.normcase(up)
        ok_a = M._resolve_target(con, norm + "#AlphaHead")[0]
        ok_b = M._resolve_target(con, norm + "#BetaHead")[0]
    finally:
        con.close()
    check(ok_a and ok_b, "a link into case-colliding files resolves either file's anchor (%s, %s)"
          % (ok_a, ok_b))

    class G(object):
        project = None
        path = lo
    with contextlib.redirect_stdout(io.StringIO()):
        rc = M.cmd_forget(G())
    blob = "\n".join(r[0] for r in _chunk_rows("x3r4_cs"))
    check(rc == 0 and "CASE_LOWER_MARK" not in blob,
          "forget foo.md removes foo.md (rc=%s)" % rc)
    check("CASE_UPPER_MARK" in blob,
          "and does NOT remove Foo.md, a different file that only normcase-collides")
    # Gone from disk + two colliding stored spellings, neither exact: ambiguous -> refused.
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(cs, "x3r4_cs"))
    os.remove(up)
    os.remove(lo)
    G.path = os.path.join(cs, "FOO.md")
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = M.cmd_forget(G())
    check(rc == 1 and "cannot be established" in out.getvalue() and _chunk_rows("x3r4_cs"),
          "a deleted file with colliding stored spellings is REFUSED as ambiguous, nothing forgotten")


# --------------------------------------------------------------------------------------------
# 18. X-FIX-3 whole-file audit, round 5: cmd_forget's three target states (2026-09-27).
# --------------------------------------------------------------------------------------------
def test_audit_round5():
    import contextlib
    import io
    import subprocess
    print("\n[18] X-FIX-3 audit round 5: forget by alias spelling, unknown identity, gone target")
    base = os.path.join(_TMP, "x3r5")

    class G(object):
        project = None
        path = None

    def forget(path):
        G.path = path
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = M.cmd_forget(G())
        return rc, out.getvalue()

    # -- 18a ALIAS SPELLING (red-team). Mutation caught: comparing identity only within the normcase
    # matches (the \\?\ spelling never normcase-equals the stored plain one).
    fp = _write(os.path.join(base, "alias", "note.md"), "%s ALIAS_FORGET_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(os.path.dirname(fp), "x3r5_alias"))
    check(_chunk_rows("x3r5_alias"), "PRECONDITION: ingested under the plain spelling")
    rc, _o = forget("\\\\?\\" + fp)
    check(rc == 0 and not _chunk_rows("x3r5_alias"),
          "forget via the \\\\?\\ spelling of the SAME file removes it (rc=%s)" % rc)

    cs = os.path.join(base, "casesens")
    os.makedirs(cs, exist_ok=True)
    r = subprocess.run(["fsutil.exe", "file", "setCaseSensitiveInfo", cs, "enable"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  NOTE  case-sensitive directory unavailable (fsutil rc=%s); 18b/18c SKIPPED." % r.returncode)
        return
    up = _write(os.path.join(cs, "Foo.md"), "%s R5_UPPER_MARK one.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(cs, "x3r5_cs"))
    check(any("R5_UPPER_MARK" in r[0] for r in _chunk_rows("x3r5_cs")), "PRECONDITION: Foo.md indexed")

    # -- 18c GONE TARGET WITH A STILL-EXISTING COLLIDER (never existed: foo.md). Foo.md exists, so it
    # is a DIFFERENT file. Mutation caught: the old unique-candidate rule, which forgot Foo.md.
    rc, out = forget(os.path.join(cs, "foo.md"))
    check(rc == 1 and any("R5_UPPER_MARK" in r[0] for r in _chunk_rows("x3r5_cs")),
          "forget of a GONE foo.md does NOT forget the existing, different Foo.md (rc=%s)" % rc)

    # -- 18b EXISTS BUT IDENTITY UNKNOWN (auditor SERIOUS). foo.md exists, never indexed; its stat
    # reports st_ino 0. Mutation caught: treating 'unknown' as 'gone' (forgot Foo.md at rc=0).
    lo = _write(os.path.join(cs, "foo.md"), "%s never indexed.\n" % _PROSE)
    real_stat = M.os.stat

    def fake_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        if os.path.basename(str(p)) == "foo.md":
            return os.stat_result((st.st_mode, 0, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                                   st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    M.os.stat = fake_stat
    try:
        rc, out = forget(lo)
    finally:
        M.os.stat = real_stat
    check(rc == 1 and any("R5_UPPER_MARK" in r[0] for r in _chunk_rows("x3r5_cs")),
          "forget of an existing file with NO usable identity refuses; Foo.md is untouched (rc=%s)" % rc)
    # Same, but BOTH files report no id (the whole directory is on a no-file-ID file system, e.g.
    # exFAT). This is the case that separates 'unknown' from 'gone': classified as gone, Foo.md would
    # also look gone and become a "unique match" - a different file forgotten at rc=0.
    # Mutation caught: classifying 'exists, no id' as 'gone'.
    def fake_stat_all(p, *a, **k):
        st = real_stat(p, *a, **k)
        if os.path.basename(str(p)).lower() == "foo.md":
            return os.stat_result((st.st_mode, 0, st.st_dev, st.st_nlink, st.st_uid, st.st_gid,
                                   st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    M.os.stat = fake_stat_all
    try:
        rc, out = forget(lo)
    finally:
        M.os.stat = real_stat
    check(rc == 1 and any("R5_UPPER_MARK" in r[0] for r in _chunk_rows("x3r5_cs")),
          "with NO ids anywhere, forget foo.md still refuses and leaves Foo.md (rc=%s)" % rc)
    # ...and the POSITIVE half: on such a file system the EXACT stored spelling is still forgettable.
    # Mutation caught: classifying 'exists, no id' as 'gone' (the gone branch then refuses it).
    ex = _write(os.path.join(base, "noid", "foo.md"), "%s NOID_EXACT_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(os.path.dirname(ex), "x3r5_noid"))
    M.os.stat = fake_stat
    try:
        rc, out = forget(ex)
    finally:
        M.os.stat = real_stat
    check(rc == 0 and not _chunk_rows("x3r5_noid"),
          "an existing no-identity file IS forgotten by its exact stored spelling (rc=%s)" % rc)
    check(M.os.stat is real_stat, "os.stat restored after the unknown-identity fixture")


# --------------------------------------------------------------------------------------------
# 19. X-FIX-3 whole-file audit, round 6: forget names what it removes, and is time-bounded.
# --------------------------------------------------------------------------------------------
def test_audit_round6():
    import contextlib
    import io
    import sqlite3
    import time
    print("\n[19] X-FIX-3 audit round 6: forget names every removed spelling; network sweep bounded")
    base = os.path.join(_TMP, "x3r6")

    class G(object):
        project = None
        path = None

    # -- 19a two documents ingested SEPARATELY, then hard-linked together outside mnemosyne. They
    # are one file now, so both rows go - but both NAMES must be printed. Mutation caught: removing
    # the per-spelling "removed:" lines.
    d = os.path.join(base, "hl")
    keep = _write(os.path.join(d, "important-decision.md"), "%s DECISION_MARK prose.\n" % _PROSE)
    other = _write(os.path.join(d, "scratch-note.md"), "%s SCRATCH_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(d, "x3r6_hl"))
    os.remove(other)
    os.link(keep, other)
    G.path = other
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = M.cmd_forget(G())
    o = out.getvalue()
    check(rc == 0 and "important-decision.md" in o and "scratch-note.md" in o,
          "forget names EVERY stored spelling it removes, incl. a differently-named one (rc=%s)" % rc)

    # -- 19b a stored NETWORK spelling whose stat stalls must not stall forget. Mutation caught: an
    # unbounded sweep (joins the thread with no timeout).
    d2 = os.path.join(base, "net")
    loc = _write(os.path.join(d2, "local.md"), "%s NET_LOCAL_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(d2, "x3r6_net"))
    dead = "\\\\x3r6-no-such-host\\share\\n.md"
    mixed = "/\\x3r6-no-such-host2\\share\\m.md"
    mapped = "Q:\\x3r6-no-such-host3-mapped\\m.md"
    con = sqlite3.connect(os.environ["MNEMOSYNE_DB"])
    try:
        con.execute("INSERT INTO files(source_path, project, mtime, content_hash, ingested_at, chunk_count)"
                    " VALUES(?,?,?,?,?,?)", (dead, "x3r6_net", 0, "x", "x", 0))
        # MIXED leading separators are a network path to Windows too (round-7 red-team). The old
        # blocklist classifier called this LOCAL, so it stalled the main thread, unbounded and
        # unreported. Mutation caught: restoring the `p[:2] in ("\\\\", "//")` classifier.
        con.execute("INSERT INTO files(source_path, project, mtime, content_hash, ingested_at, chunk_count)"
                    " VALUES(?,?,?,?,?,?)", (mixed, "x3r6_net", 0, "x", "x", 0))
        # A DRIVE-LETTER spelling can be a mapped network drive / subst of UNC / junction to a share
        # (round-8 red-team): no spelling is trusted to be fast, so it must be bounded and named too.
        # Mutation caught: any sweep that stats some spellings outside the bounded thread.
        con.execute("INSERT INTO files(source_path, project, mtime, content_hash, ingested_at, chunk_count)"
                    " VALUES(?,?,?,?,?,?)", (mapped, "x3r6_net", 0, "x", "x", 0))
        con.commit()
    finally:
        con.close()
    real_stat, real_budget = M.os.stat, M._FORGET_NET_BUDGET_S

    def slow_stat(p, *a, **k):
        if "x3r6-no-such-host" in str(p):
            time.sleep(3.0)
            raise OSError(53, "network path not found")
        return real_stat(p, *a, **k)
    M.os.stat, M._FORGET_NET_BUDGET_S = slow_stat, 0.3
    try:
        G.path = loc
        t0 = time.time()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = M.cmd_forget(G())
        dt = time.time() - t0
    finally:
        M.os.stat, M._FORGET_NET_BUDGET_S = real_stat, real_budget
    check(dt < 2.0, "forget returns within its network budget despite a stalled host (%.2fs)" % dt)
    check(rc == 0 and not any("NET_LOCAL_MARK" in r[0] for r in _chunk_rows("x3r6_net")),
          "and still forgets the local file (rc=%s)" % rc)
    o = out.getvalue()
    check("could not be checked" in o and "x3r6-no-such-host" in o and "x3r6-no-such-host2" in o
          and "x3r6-no-such-host3-mapped" in o,
          "and REPORTS every unchecked spelling BY NAME - UNC, mixed-separator and drive-letter alike")
    check("within 0.3s" in o, "and states the real budget, not a rounded '0s'")

    # -- 19c THE TARGET'S OWN STAT IS BOUNDED (round-9 red-team). Mutation caught: stat-ing the target
    # on the main thread before the bounded sweep.
    def slow_target(p, *a, **k):
        if os.path.basename(str(p)) == "local2.md":
            time.sleep(3.0)
        return real_stat(p, *a, **k)
    loc2 = _write(os.path.join(d2, "local2.md"), "%s NET_LOCAL2_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(d2, "x3r6_net"))
    M.os.stat, M._FORGET_NET_BUDGET_S = slow_target, 0.3
    try:
        G.path = loc2
        t0 = time.time()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = M.cmd_forget(G())
        dt = time.time() - t0
    finally:
        M.os.stat, M._FORGET_NET_BUDGET_S = real_stat, real_budget
    check(dt < 2.0 and rc == 1 and "target itself could not be checked" in out.getvalue(),
          "a target whose own stat stalls: refused within the budget (%.2fs, rc=%s)" % (dt, rc))
    check(any("NET_LOCAL2_MARK" in r[0] for r in _chunk_rows("x3r6_net")),
          "and nothing was forgotten")

    # -- 19d ORPHANED WORKERS STOP AT THE DEADLINE (round-9 auditor). 8 stalled spellings sort FIRST
    # and occupy every worker; 300 fast ones follow. Once the budget expires, a worker may finish the
    # one stat it is inside but must take NO new work. Mutation caught: removing the stop flag
    # (the orphans then stat the remaining ~300 spellings after cmd_forget has returned).
    loc3 = _write(os.path.join(d2, "local3.md"), "%s NET_LOCAL3_MARK prose.\n" % _PROSE)
    with contextlib.redirect_stdout(io.StringIO()):
        M.cmd_ingest(_Args(d2, "x3r6_net"))
    con = sqlite3.connect(os.environ["MNEMOSYNE_DB"])
    try:
        rows = [("A:\\x3r9-stall-%d.md" % i,) for i in range(8)]
        rows += [(os.path.join(_TMP, "x3r9-fast-%03d.md" % i),) for i in range(300)]
        con.executemany("INSERT INTO files(source_path, project, mtime, content_hash, ingested_at,"
                        " chunk_count) VALUES(?, 'x3r9', 0, 'x', 'x', 0)", rows)
        con.commit()
    finally:
        con.close()

    def stall_first(p, *a, **k):
        if "x3r9-stall" in str(p):
            time.sleep(1.0)
            raise FileNotFoundError(2, "gone")
        if "x3r6-no-such-host" in str(p):    # 19b's fake network rows: never a real lookup
            raise FileNotFoundError(2, "gone")
        return real_stat(p, *a, **k)
    M.os.stat, M._FORGET_NET_BUDGET_S = stall_first, 0.2
    try:
        G.path = loc3
        with contextlib.redirect_stdout(io.StringIO()):
            M.cmd_forget(G())
    finally:
        M.os.stat, M._FORGET_NET_BUDGET_S = real_stat, real_budget
    calls = [0]

    def counting(p, *a, **k):
        calls[0] += 1
        if "x3r6-no-such-host" in str(p):
            raise FileNotFoundError(2, "gone")
        return real_stat(p, *a, **k)
    M.os.stat = counting
    try:
        time.sleep(2.0)                      # the stalled stats finish at ~1s; watch what follows
    finally:
        M.os.stat = real_stat
    check(calls[0] < 10, "after the deadline, orphaned workers take no new work (%d stray stat calls)"
          % calls[0])


def main():
    print("Mnemosyne redaction + chunking regression suite")
    print("DB: %s  (throwaway - the real index is never opened)" % os.environ["MNEMOSYNE_DB"])
    # PER-FUNCTION ISOLATION (X-FIX-3 audit round 1): a CRASH in one test function used to
    # abort main() and silently drop every later function's assertions - no FAIL line, no
    # summary. Each function now runs in its own handler and a crash is recorded as a FAIL.
    try:
        for _t in (test_must_keep, test_must_mask, test_known_residuals, test_chunk_cap, test_real_token_budget, test_boundary_never_splits_a_secret, test_round_trip, test_forbidden_tree, test_store_path_redaction, test_governed_refusal, test_sensitive_filenames, test_denylist_is_loaded_and_wired, test_anchor_redaction, test_path_namespace_aliases, test_x_fix_3,
                   test_audit_round1, test_audit_round2,
                   test_audit_round3, test_audit_round4, test_audit_round5,
                   test_audit_round6):
            try:
                _t()
            except Exception as _exc:
                import traceback
                traceback.print_exc()
                check(False, "%s CRASHED: %s: %s" % (_t.__name__, type(_exc).__name__, _exc))
    finally:
        # CLEANUP IS VISIBLE, not swallowed (round-5 auditor): `ignore_errors=True` alone hid a
        # leaked test.db on essentially every run since 2026-08-10 (172 leftover mnemo-test-* dirs),
        # most likely a sqlite handle Windows releases late. Collect, retry once, then SAY what is left.
        import gc
        import time
        gc.collect()
        shutil.rmtree(_TMP, ignore_errors=True)
        if os.path.exists(_TMP):
            time.sleep(1.0)
            gc.collect()
            shutil.rmtree(_TMP, ignore_errors=True)
        if os.path.exists(_TMP):
            left = [os.path.join(dp, f) for dp, _dn, fn in os.walk(_TMP) for f in fn]
            print("\n  NOTE  fixture cleanup incomplete, %d file(s) left under %s: %s"
                  % (len(left), _TMP, ", ".join(os.path.basename(x) for x in left[:5])))
    print("\n%s: %d failure(s)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    for f in FAILS:
        print("  - %s" % f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
