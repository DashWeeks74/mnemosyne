#!/usr/bin/env python3
"""
Mnemosyne v1 - a local, offline memory of decisions & reasoning (lexical/BM25 foundation).

Standalone, portable build. Zero dependencies (stdlib + SQLite FTS5) for the lexical core; semantic
search is optional via mnemo_embed (fastembed, fully local, no API key). Secret-safe ingest,
provenance on every chunk, cite-don't-answer retrieval. Self-contained under this folder - no
dependency on any other project's paths, hooks, or venv.

Console output is ASCII-only (Rule B). Files are read UTF-8 with error replacement (Rule A).

Commands:
  ingest <path> [--project NAME] [--allow-governed]   walk, secret-safe, chunk, store
  query  "<question>" [-k N] [--project NAME]          BM25 search; every hit is a citation
  status                                               DB stats
  forget (--path P | --project NAME)                   remove ingested content
"""

import argparse
import hashlib
import os
import re
import math
import sqlite3
import stat as _stat
import sys
import json
from datetime import datetime, timedelta, timezone

try:
    import mnemo_embed as emb            # local embedding layer; degrades to lexical if unavailable
except Exception:
    emb = None

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(HERE, "hooks")  # local copy of the secret-rules denylist; self-contained
DB_PATH = os.environ.get("MNEMOSYNE_DB", os.path.join(HERE, "mnemosyne.db"))

MAX_CHUNK = 1400      # chars; larger sections are split by paragraph
MIN_CHUNK = 24        # skip trivially small chunks
INGEST_EXT = {".md", ".markdown", ".txt", ".rst", ".text"}
INGEST_STEMS = {"readme", "notes", "design", "vision", "progress", "changelog", "todo", "decisions"}
SKIP_DIRS = {".git", ".claude", "node_modules", "dist", "build", "__pycache__", ".venv",
             "venv", ".idea", ".vscode", "htmlcov", ".pytest_cache", "graphify-out"}

# Sensitive filename/path patterns (aligned with the hooks' Test-ScSensitivePath). Skip these files.
SENSITIVE_PATH = [
    r"(?i)[\\/]\.credentials\.json$",
    r"(?i)(?<![\w])[\w.-]*secrets?\.(?:json|ya?ml|toml|ini|cfg|conf|xml|txt|env|md|markdown|rst)$",
    r"(?i)(?<![\w])[\w.-]*credentials?\.(?:json|ya?ml|xml|ini|cfg|conf|txt|md|markdown|rst)$",
    r"(?i)[\/](?:credentials|secrets|secret|keys|key|apikeys|api_keys|apikey|api_key)(?:\.[a-z0-9]+)?$",
    r"(?i)(?<![\w.])\.env(?:\.[\w-]+)?$",
    r"(?i)[\\/]id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$",
    r"(?i)[\\/]\.ssh[\\/]",
    r"(?i)\.(?:pem|pfx|p12|keystore|jks|key)$",
    r"(?i)[\\/]\.aws[\\/]credentials$",
    r"(?i)[\\/]\.(?:npmrc|netrc|pypirc|git-credentials)$",
    r"(?i)[\\/]\.(?:gnupg|azure)[\\/]",
]
SENSITIVE_PATH_RE = [re.compile(p) for p in SENSITIVE_PATH]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# --- query telemetry (gives "measure" teeth so a model-upgrade decision is a FIRED signal, not a
# note nobody reads). Logs live next to the DB by default; override with MNEMOSYNE_LOG_DIR.
LOG_DIR = os.environ.get("MNEMOSYNE_LOG_DIR", os.path.join(HERE, "logs"))
QUERY_LOG = "mnemosyne-queries.jsonl"
FLAG_LOG = "mnemosyne-flags.jsonl"

# Upgrade-signal thresholds (surfaced by `status` now, by the dashboard card in phase 3).
FLAG_RATE_ACT = 0.15                 # >=15% bad-retrieval over the window -> re-embed with a bigger model
MIN_QUERIES_FOR_SIGNAL = 20          # ignore the rate until there's enough traffic to trust it
SIGNAL_WINDOW_DAYS = 30
# A "watched" project is one the OPERATOR has marked high-stakes (via `ingest --watch` or by editing the
# file): a corpus where you can't afford to learn recall is failing from accumulated bad hits, so we warn
# to re-evaluate the model the moment it's indexed. NOT domain-specific and NOT hardcoded - empty by
# default. The domain-agnostic safety net for every other project is the flag-rate trigger below.
WATCH_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watch-projects.txt")


def _watch_projects():
    """Set of operator-marked high-stakes project names (lowercased). Empty if the file is absent/empty."""
    out = set()
    try:
        with open(WATCH_FILE, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    out.add(line.lower())
    except OSError:
        pass
    return out


def _add_watch_project(name):
    """Append a project to the watchlist (dedup, case-insensitive). Best-effort."""
    if not name or name.lower() in _watch_projects():
        return False
    try:
        newfile = not os.path.exists(WATCH_FILE)
        with open(WATCH_FILE, "a", encoding="utf-8") as fh:
            if newfile:
                fh.write("# Operator-marked HIGH-STAKES projects (one name per line; '#' comments).\n"
                         "# Indexing any of these flips the re-embed signal to ACT - a proactive nudge to\n"
                         "# re-evaluate the embedding model before you rely on recall for a corpus that matters.\n"
                         "# Empty = nothing fires here; the flag-rate trigger still guards every project.\n")
            fh.write(name + "\n")
        return True
    except OSError:
        return False


def _log_event(fname, obj):
    """Append one JSONL telemetry event. Best-effort: logging must NEVER break a query (fail silent)."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        obj = dict(obj); obj["ts"] = now_iso()
        with open(os.path.join(LOG_DIR, fname), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj, ensure_ascii=True) + "\n")
    except OSError:
        pass


def _read_jsonl(fname):
    path = os.path.join(LOG_DIR, fname)
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def _recent(events, days=SIGNAL_WINDOW_DAYS):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    out = []
    for e in events:
        ts = e.get("ts")
        if not ts:
            continue
        try:
            if datetime.fromisoformat(ts) >= cutoff:
                out.append(e)
        except ValueError:
            continue
    return out


def upgrade_signal(con):
    """Decide whether bge-small should be re-embedded with a stronger model.

    Returns (level, reason) where level is 'ok' | 'watch' | 'act'. Two independent triggers, either fires:
      - an operator-marked HIGH-STAKES project (watch-projects.txt) got indexed -> re-evaluate the model;
      - the bad-retrieval flag-rate crossed the threshold over the recent window (domain-agnostic).
    This is the DA's teeth: the upgrade becomes a signal you SEE, tied to a real event, not a good intention.
    """
    projs = [r[0] or "" for r in con.execute("SELECT DISTINCT project FROM chunks")]
    watched = _watch_projects()
    hit = sorted({p for p in projs if p.lower() in watched})
    if hit:
        return ("act", "high-stakes corpus indexed (%s) - re-evaluate the embedding model (bge-base/large "
                        "or a domain-tuned model) before relying on recall for it" % ", ".join(hit))
    rq = _recent(_read_jsonl(QUERY_LOG))
    rf = _recent(_read_jsonl(FLAG_LOG))
    n = len(rq)
    rate = (len(rf) / n) if n else 0.0
    if n >= MIN_QUERIES_FOR_SIGNAL and rate >= FLAG_RATE_ACT:
        return ("act", "bad-retrieval rate %.0f%% over %d queries/%dd (>= %.0f%%) - re-embed with bge-base "
                       "and re-measure" % (rate * 100, n, SIGNAL_WINDOW_DAYS, FLAG_RATE_ACT * 100))
    if n >= MIN_QUERIES_FOR_SIGNAL and rate >= FLAG_RATE_ACT * 0.6:
        return ("watch", "bad-retrieval rate %.0f%% over %d queries/%dd - approaching the %.0f%% re-embed "
                         "threshold" % (rate * 100, n, SIGNAL_WINDOW_DAYS, FLAG_RATE_ACT * 100))
    if n < MIN_QUERIES_FOR_SIGNAL:
        return ("ok", "bge-small; only %d queries/%dd logged - too little traffic to judge recall yet"
                % (n, SIGNAL_WINDOW_DAYS))
    return ("ok", "bge-small healthy - bad-retrieval rate %.0f%% over %d queries/%dd" % (rate * 100, n, SIGNAL_WINDOW_DAYS))


def _write_status_snapshot(con):
    """Emit a single-object JSON snapshot for the dashboard (phase 3): corpus stats + query telemetry +
    the re-embed signal. The dashboard is a static file server (no DB access), so this is how the panel
    sees the DB. Best-effort - a snapshot write must NEVER break the command that triggered it."""
    try:
        nf = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        nc = con.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        ne = con.execute("SELECT COUNT(*) FROM chunks WHERE embedding IS NOT NULL").fetchone()[0]
        projs = []
        for p, n in con.execute("SELECT project,COUNT(*) FROM chunks GROUP BY project ORDER BY 2 DESC").fetchall():
            last = con.execute("SELECT MAX(ingested_at) FROM chunks WHERE project=?", (p,)).fetchone()[0]
            projs.append({"name": p, "chunks": n, "last": (last or "")[:19]})
        rq = _recent(_read_jsonl(QUERY_LOG))
        rf = _recent(_read_jsonl(FLAG_LOG))
        level, why = upgrade_signal(con)
        snap = {
            "ts": now_iso(), "db": DB_PATH,
            "files": nf, "chunks": nc, "embedded": ne,
            "semantic": bool(emb and emb.EMBED_AVAILABLE),
            "model": (emb.MODEL_NAME if (emb and emb.EMBED_AVAILABLE) else None),
            "projects": projs,
            "queries_window": len(rq), "flags_window": len(rf), "window_days": SIGNAL_WINDOW_DAYS,
            "signal": {"level": level, "reason": why},
            "watched": sorted(_watch_projects()),
        }
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, "mnemosyne-status.json")
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, ensure_ascii=True, indent=2)
        os.replace(tmp, path)
    except (OSError, sqlite3.Error):
        pass


def load_secret_rules():
    """Load the hooks' content secret patterns (name@@regex). Same denylist the guards use."""
    rules = []
    path = os.path.join(HOOKS, "secret-rules.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                t = line.strip()
                if not t or t.startswith("#") or "@@" not in t:
                    continue
                name, _, rx = t.partition("@@")
                name, rx = name.strip(), rx.strip()
                if name and rx:
                    try:
                        rules.append((name, re.compile(rx)))
                    except re.error:
                        continue
    return rules


SECRET_RULES = load_secret_rules()


KNOWN_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}


def _canonical(path):
    """Long, real, normcased path for gate comparison: expands 8.3 (Windows) + resolves links."""
    ap = os.path.abspath(path)
    try:
        ap = os.path.realpath(ap)
    except OSError:
        pass
    if os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(32768)
            n = ctypes.windll.kernel32.GetLongPathNameW(ap, buf, 32768)
            if n and n < 32768 and buf.value:
                ap = buf.value
        except Exception:
            pass
    return os.path.normcase(ap)


def _is_reparse(path):
    """True if path is a junction/symlink (Windows junctions ignore os.walk followlinks)."""
    try:
        return bool(os.lstat(path).st_file_attributes & _stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, AttributeError):
        try:
            return os.path.islink(path)
        except OSError:
            return False


def _shannon(t):
    if not t:
        return 0.0
    from collections import Counter
    n = len(t)
    return -sum((c / n) * math.log2(c / n) for c in Counter(t).values())


_HASHCTX = re.compile(r"(?i)\b(?:commit|sha|sha1|sha256|md5|hash|checksum|digest|revert|reverted|cherry[- ]?pick|rebase|revision|rev|git|fingerprint|etag)\b")
_HAS_UPPER   = re.compile(r"[A-Z]")            # secrets are mixed-case/base64; slug identifiers are lowercase
_IDENT_SPLIT = re.compile(r"[-/_]")            # identifier separators (kebab/snake/slash)
_IDENT_PART  = re.compile(r"[a-z]+|[0-9]+")    # each identifier part: a lowercase word OR a pure number


def _entropy_token_kind(tok, window):
    """Per-token verdict: 'high-entropy-hex' / 'high-entropy-token' / None, given the token's context.
    Hex is inherently ambiguous (hash/ID vs key): judged by CONTEXT (a hash/commit word nearby, or ID
    length, keeps it). Non-hex credential-shaped tokens judged by normalized entropy from length 20."""
    if tok in KNOWN_EXAMPLES:
        return None
    low = tok.lower()
    if re.fullmatch(r"[0-9a-f]+", low):                        # pure hex -> hash / id / sha / or a hex key
        if len(low) < 32:
            return None                                        # ObjectId(24), short SHA = an id, not a secret
        if _HASHCTX.search(window):
            return None                                        # adjacent hash/commit word -> not a secret
        return "high-entropy-hex"
    # FP guard (2026-07-19, sentinel-audited 2 rounds): a SHORT lowercase multi-word IDENTIFIER
    # (kebab/snake/slash slug, e.g. feedback-bqs-ui-tokens-css, ui-build/frontend-design) is not a secret.
    # Fail-safe hinges: NO uppercase (base64/mixed secrets have it; pure hex handled above); 3..5 parts each
    # a lowercase word or pure number; <=36 chars (caps out BIP-39 seed phrases + number tuples); and the
    # de-separated token must NOT be pure hex (dash-chunked hex = key material, not a slug). ACCEPTED inherent
    # residual: an UNLABELED short (<=5-word) all-lowercase word-passphrase is character-identical to a slug
    # and slips - same risk class as this ruleset's stated "accident-guard, not a DLP"; labeled passphrases
    # are still caught by the generic-secret rule.
    if not _HAS_UPPER.search(tok) and len(tok) <= 36:
        _parts = [p for p in _IDENT_SPLIT.split(tok) if p]
        if (3 <= len(_parts) <= 5
                and all(_IDENT_PART.fullmatch(p) for p in _parts)
                and not re.fullmatch(r"[0-9a-f]+", _IDENT_SPLIT.sub("", low))):
            return None
    distinct = len(set(tok))
    if distinct < 12:
        return None                                            # low variety -> a word/identifier
    ent = _shannon(tok)
    if ent >= 3.5 and (ent / math.log2(distinct)) >= 0.85:
        return "high-entropy-token"
    return None


def _entropy_secret(text):
    """First high-entropy secret token in text, or None (used by scan_secret / whole-file checks)."""
    for m in re.finditer(r"[A-Za-z0-9+/=_\-]{20,}", text):
        kind = _entropy_token_kind(m.group(0), text[max(0, m.start() - 48): m.end() + 16])
        if kind:
            return kind
    return None


REDACT_MARK = "[secret-redacted]"
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", re.I)


def _secret_spans(text):
    """All (start,end) spans that look like a secret VALUE: denylist-rule matches + entropy tokens."""
    spans = []
    for _name, rx in SECRET_RULES:
        try:
            for m in rx.finditer(text):
                if m.group(0) not in KNOWN_EXAMPLES:
                    spans.append((m.start(), m.end()))
        except re.error:
            continue
    for m in re.finditer(r"[A-Za-z0-9+/=_\-]{20,}", text):
        if _entropy_token_kind(m.group(0), text[max(0, m.start() - 48): m.end() + 16]):
            spans.append((m.start(), m.end()))
    return spans


def redact_secrets(text):
    """Replace every secret-looking span with a marker; return (redacted_text, count). Security-equivalent
    to dropping the chunk (the value is never stored) but keeps the surrounding decision/reasoning prose -
    the point of the memory. Used PER CHUNK; single-token secrets have no whitespace so redaction is complete."""
    spans = _secret_spans(text)
    if not spans:
        return text, 0
    spans.sort()
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    out, last = [], 0
    for s, e in merged:
        out.append(text[last:s]); out.append(REDACT_MARK); last = e
    out.append(text[last:])
    return "".join(out), len(merged)


def load_governed_roots():
    roots = []
    path = os.path.join(HOOKS, "governed-roots.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                t = line.strip()
                if t and not t.startswith("#"):
                    roots.append(_canonical(t))
    return roots


GOVERNED_ROOTS = load_governed_roots()


def is_governed(path):
    p = _canonical(path)
    for r in GOVERNED_ROOTS:
        if p == r or p.startswith(r + os.sep):
            return True
    return False


def is_sensitive_path(path):
    return any(rx.search(path) for rx in SENSITIVE_PATH_RE)


def scan_secret_rules(text):
    """Denylist (provider/labeled/private-key) match only. These can span lines (a PEM body), so the
    caller scans the WHOLE FILE with this and drops the whole file on a hit - boundary-safe."""
    for name, rx in SECRET_RULES:
        try:
            m = rx.search(text)
        except re.error:
            continue
        if m:
            val = m.group(0)
            if val in KNOWN_EXAMPLES:
                continue
            return name
    return None


def scan_secret(text):
    """Rules + the entropy backstop. Used PER CHUNK: an entropy token has no whitespace so it lives wholly
    in one chunk -> dropping just that chunk is boundary-safe and avoids nuking a whole doc for one hash."""
    r = scan_secret_rules(text)
    if r:
        return r
    return _entropy_secret(text)


def is_ingestible(path):
    base = os.path.basename(path)
    stem, ext = os.path.splitext(base)
    if ext.lower() in INGEST_EXT:
        return True
    if stem.lower() in INGEST_STEMS:
        return True
    return False


# ---- gitignore (common subset; documented limitation) -----------------------------------------
def load_gitignore(root):
    patterns = []
    gi = os.path.join(root, ".gitignore")
    if os.path.exists(gi):
        with open(gi, encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                t = line.strip()
                if t and not t.startswith("#") and not t.startswith("!"):
                    patterns.append(t.rstrip("/"))
    return patterns


def gitignored(rel_posix, patterns):
    import fnmatch
    parts = rel_posix.split("/")
    base = parts[-1]
    for pat in patterns:
        if pat.startswith("/"):
            if fnmatch.fnmatch(rel_posix, pat.lstrip("/")):
                return True
        elif "/" in pat:
            if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, "*/" + pat):
                return True
        else:
            if fnmatch.fnmatch(base, pat) or pat in parts:
                return True
    return False


# ---- chunking ----------------------------------------------------------------------------------
def _pack_paragraphs(text, anchor, start_ord):
    """Split a long block into <=MAX_CHUNK chunks on paragraph boundaries."""
    paras = re.split(r"\n\s*\n", text)
    chunks, buf, ordn = [], "", start_ord
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if buf and len(buf) + len(p) + 2 > MAX_CHUNK:
            chunks.append((anchor, ordn, buf.strip()))
            ordn += 1
            buf = p
        else:
            buf = (buf + "\n\n" + p) if buf else p
    if buf.strip():
        chunks.append((anchor, ordn, buf.strip()))
        ordn += 1
    return chunks, ordn


def chunk_markdown(text):
    """Yield (anchor, ord, text). Sections by heading; long sections split by paragraph."""
    lines = text.splitlines()
    stack = []          # list of (level, title)
    section, out, ordn = [], [], 0

    def flush():
        nonlocal section, ordn
        body = "\n".join(section).strip()
        section = []
        if len(body) < MIN_CHUNK:
            return
        anchor = " > ".join(t for _, t in stack) or "(top)"
        if len(body) <= MAX_CHUNK:
            out.append((anchor, ordn, body))
            ordn += 1
        else:
            packed, ordn2 = _pack_paragraphs(body, anchor, ordn)
            out.extend(packed)
            ordn = ordn2

    for ln in lines:
        m = re.match(r"^(#{1,6})\s+(.*)$", ln)
        if m:
            flush()
            level, title = len(m.group(1)), m.group(2).strip()
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
        else:
            section.append(ln)
    flush()
    return out


# ---- store -------------------------------------------------------------------------------------
def connect():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript("""
    CREATE TABLE IF NOT EXISTS chunks(
      id INTEGER PRIMARY KEY,
      project TEXT, source_path TEXT, anchor TEXT, ord INTEGER,
      text TEXT, content_hash TEXT, source_mtime REAL, ingested_at TEXT, embedding BLOB);
    CREATE TABLE IF NOT EXISTS files(
      source_path TEXT PRIMARY KEY, project TEXT, mtime REAL,
      content_hash TEXT, ingested_at TEXT, chunk_count INTEGER, note TEXT);
    CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(text, anchor, source_path);
    CREATE INDEX IF NOT EXISTS ix_chunks_src ON chunks(source_path);
    CREATE INDEX IF NOT EXISTS ix_chunks_prj ON chunks(project);
    """)
    try:
        con.execute("ALTER TABLE chunks ADD COLUMN embedding BLOB")   # migrate a pre-embedding DB
    except sqlite3.OperationalError:
        pass
    return con


def _forget_file(con, source_path):
    ids = [r[0] for r in con.execute("SELECT id FROM chunks WHERE source_path=?", (source_path,))]
    for cid in ids:
        con.execute("DELETE FROM chunks_fts WHERE rowid=?", (cid,))
    con.execute("DELETE FROM chunks WHERE source_path=?", (source_path,))
    con.execute("DELETE FROM files WHERE source_path=?", (source_path,))


def ingest_file(con, path, project, stats):
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        stats["errors"].append((path, str(e)))
        return
    mtime = os.path.getmtime(path)
    fhash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

    prev = con.execute("SELECT content_hash FROM files WHERE source_path=?", (path,)).fetchone()
    if prev and prev[0] == fhash:
        stats["unchanged"] += 1
        return
    _forget_file(con, path)  # re-ingest cleanly

    # Whole-file drop ONLY for a PRIVATE KEY: its base64 body spans chunk boundaries, so per-chunk
    # redaction can't safely catch it. Everything else (provider tokens, labeled secrets, entropy tokens)
    # is single-token / single-chunk, so it is REDACTED in place per chunk below - keeping the surrounding
    # decision/reasoning prose instead of nuking it (the round-4 denial-of-memory fix, needed on SC's own
    # security-dense notes where secret-SHAPED example strings are everywhere).
    if _PRIVKEY_RE.search(text):
        stats["secret_files"] += 1
        stats["secret_rules"]["private-key"] = stats["secret_rules"].get("private-key", 0) + 1
        con.execute(
            "INSERT OR REPLACE INTO files(source_path,project,mtime,content_hash,ingested_at,chunk_count,note)"
            " VALUES(?,?,?,?,?,?,?)", (path, project, mtime, fhash, now_iso(), 0, "SKIPPED-secret:private-key"))
        return

    chunks = chunk_markdown(text)
    stored = 0
    to_embed = []                       # (chunk_id, text) of STORED chunks -> batch-embedded below
    for anchor, ordn, ctext in chunks:
        ctext, nred = redact_secrets(ctext)   # mask secret-shaped tokens; keep the prose
        if nred:
            stats["redacted"] = stats.get("redacted", 0) + nred
        chash = hashlib.sha256(ctext.encode("utf-8", "replace")).hexdigest()
        cur = con.execute(
            "INSERT INTO chunks(project,source_path,anchor,ord,text,content_hash,source_mtime,ingested_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (project, path, anchor, ordn, ctext, chash, mtime, now_iso()))
        con.execute("INSERT INTO chunks_fts(rowid,text,anchor,source_path) VALUES(?,?,?,?)",
                    (cur.lastrowid, ctext, anchor, path))
        to_embed.append((cur.lastrowid, ctext))
        if emb and emb.approx_tokens(ctext) > emb.MAX_TOKENS:
            stats["oversized"] = stats.get("oversized", 0) + 1   # bge truncates >512 tok: count it, fail visibly
        stored += 1
    # Embed the stored chunks in one batch. Only CLEAN/stored chunks are embedded -> no secret is ever embedded.
    if to_embed and emb and emb.EMBED_AVAILABLE:
        try:
            vecs = emb.embed_passages([t for _, t in to_embed])
            for (cid, _), vec in zip(to_embed, vecs):
                con.execute("UPDATE chunks SET embedding=? WHERE id=?", (emb.to_blob(vec), cid))
            stats["embedded"] = stats.get("embedded", 0) + len(to_embed)
        except Exception as e:
            stats["errors"].append((path, "embed: " + str(e)))
    con.execute(
        "INSERT OR REPLACE INTO files(source_path,project,mtime,content_hash,ingested_at,chunk_count,note)"
        " VALUES(?,?,?,?,?,?,?)", (path, project, mtime, fhash, now_iso(), stored, None))
    stats["files"] += 1
    stats["chunks"] += stored


def cmd_ingest(args):
    root = os.path.abspath(args.path)
    if not os.path.exists(root):
        print("[ERROR] path not found: " + root); return 1
    if re.search(r"~\d", _canonical(root)):
        print("[REFUSED] path has an unresolved 8.3 short-name component: " + root)
        print("          Use the full long path so the governed-tree check can be trusted."); return 2
    if is_governed(root) and not args.allow_governed:
        print("[REFUSED] '%s' is under a GOVERNED tree (%s)." % (root, ", ".join(GOVERNED_ROOTS)))
        print("          Indexing a governed system is high-stakes. Pass --allow-governed ONLY after the")
        print("          ingester has passed a sentinel audit. Reading is allowed; indexing is not, by default.")
        return 2

    project = args.project or os.path.basename(root.rstrip("\\/")) or "default"
    stats = {"files": 0, "chunks": 0, "unchanged": 0, "skipped_sensitive": 0, "skipped_gitignore": 0,
             "skipped_governed": 0, "secret_chunks": 0, "secret_files": 0, "secret_rules": {}, "errors": []}
    con = connect()

    targets = []
    if os.path.isfile(root):
        targets.append((root, []))
    else:
        patterns = load_gitignore(root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # prune skip dirs AND reparse points (junctions ignore followlinks on Windows -> would
            # otherwise descend a junction pointing INTO a governed tree).
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not _is_reparse(os.path.join(dirpath, d))]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if not is_ingestible(full):
                    continue
                if _is_reparse(full):
                    stats["skipped_sensitive"] += 1; continue
                if is_sensitive_path(full):
                    stats["skipped_sensitive"] += 1; continue
                # Re-check GOVERNED per file on its real path - a junction/symlink can reach a governed
                # tree even when the ingest root was allowed (the root-only check missed this).
                if is_governed(full) and not args.allow_governed:
                    stats["skipped_governed"] += 1; continue
                rel = os.path.relpath(full, root).replace("\\", "/")
                if patterns and gitignored(rel, patterns):
                    stats["skipped_gitignore"] += 1; continue
                targets.append((full, patterns))

    if args.allow_governed and is_governed(root):
        print("[WARN] indexing a GOVERNED tree by explicit --allow-governed. Secret-scan is active; verify.")

    for full, _ in targets:
        if is_sensitive_path(full):
            stats["skipped_sensitive"] += 1; continue
        ingest_file(con, full, project, stats)
    con.commit()

    print("Mnemosyne ingest: project '%s'  <- %s" % (project, root))
    print("  files ingested   : %d" % stats["files"])
    print("  chunks stored     : %d" % stats["chunks"])
    print("  unchanged (skip)  : %d" % stats["unchanged"])
    print("  skipped sensitive : %d" % stats["skipped_sensitive"])
    print("  skipped gitignore : %d" % stats["skipped_gitignore"])
    print("  skipped governed  : %d" % stats["skipped_governed"])
    if stats["secret_files"]:
        print("  SKIPPED secret FILES : %d  <- whole file dropped (private key)" % stats["secret_files"])
    if stats.get("redacted"):
        print("  REDACTED tokens   : %d  <- masked in place; surrounding prose kept, token never stored" % stats["redacted"])
    if stats.get("oversized"):
        print("  [WARN] chunks > %d tokens: %d  (bge truncates; consider tighter chunking)" % (emb.MAX_TOKENS if emb else 512, stats["oversized"]))
    for path, err in stats["errors"][:5]:
        print("  [WARN] %s: %s" % (path, err))
    if getattr(args, "watch", False):
        if _add_watch_project(project):
            print("  MARKED high-stakes: '%s' -> re-embed signal now ACT (watch-projects.txt)" % project)
        else:
            print("  already high-stakes: '%s'" % project)
    _write_status_snapshot(con)
    con.close()
    return 0


def _snippet(text, maxlen=220):
    s = " ".join(text.split())
    return s if len(s) <= maxlen else s[:maxlen - 3] + "..."


def cmd_query(args):
    con = connect()
    q = args.query
    terms = re.findall(r"[A-Za-z0-9]+", q)
    if not terms:
        print("No searchable terms in query."); return 0
    fts = " OR ".join('"%s"' % t for t in terms)           # quote each term -> no FTS5 operator surprises
    proj = [args.project] if args.project else []

    # --- lexical (BM25) ranking ---
    try:
        lex = [r[0] for r in con.execute(
            "SELECT c.id, bm25(chunks_fts) rk FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid "
            "WHERE chunks_fts MATCH ?" + (" AND c.project=?" if args.project else "") +
            " ORDER BY rk LIMIT 50", [fts] + proj).fetchall()]
    except sqlite3.OperationalError as e:
        print("[ERROR] bad query syntax (%s). Try plain words or quote phrases." % e); return 1

    # --- semantic (vector cosine) ranking (unless forced lexical or embed layer unavailable) ---
    sem = []
    use_sem = (not getattr(args, "lexical", False)) and emb and emb.EMBED_AVAILABLE
    if use_sem:
        vrows = con.execute(
            "SELECT id, embedding FROM chunks WHERE embedding IS NOT NULL" +
            (" AND project=?" if args.project else ""), proj).fetchall()
        if vrows:
            import numpy as np
            mat = np.vstack([emb.from_blob(b) for _, b in vrows]).astype(np.float32)
            qv = emb.embed_query(q)
            order = np.argsort(-(mat @ qv))[:50]
            sem = [vrows[i][0] for i in order]

    # --- fuse: Reciprocal Rank Fusion (k=60) - combines exact-term (BM25) + semantic recall ---
    K = 60
    score = {}
    for rank, cid in enumerate(lex):
        score[cid] = score.get(cid, 0.0) + 1.0 / (K + rank)
    for rank, cid in enumerate(sem):
        score[cid] = score.get(cid, 0.0) + 1.0 / (K + rank)
    if not score:
        print("No matches for: %s" % q); return 0
    top = sorted(score, key=lambda c: -score[c])[:args.k]

    mode = ("hybrid (BM25 + vector)" if (lex and sem) else
            "vector only" if sem else
            "lexical only" + ("" if (emb and emb.EMBED_AVAILABLE) else " (semantic OFF - embed layer unavailable)"))
    print("Mnemosyne  '%s'  (%d hit%s, %s)" % (q, len(top), "" if len(top) == 1 else "s", mode))
    print("-" * 78)
    logged_top = []
    for cid in top:
        row = con.execute("SELECT project,source_path,anchor,text,source_mtime,ingested_at "
                          "FROM chunks WHERE id=?", (cid,)).fetchone()
        if not row:
            continue
        project, src, anchor, text, smtime, ing = row
        stale = ""
        try:
            if os.path.exists(src) and os.path.getmtime(src) > (smtime or 0) + 1:
                stale = "  [STALE - file changed since ingest; re-ingest to confirm]"
        except OSError:
            stale = "  [source missing]"
        print("* [%s] %s" % (project, src))
        print("    %s   ingested %s%s" % (anchor, (ing or "")[:10], stale))
        print("    %s" % _snippet(text))
        print("")
        logged_top.append({"project": project, "source": src, "anchor": anchor})
    # telemetry: record the query so bad-retrieval flags have something to point at (phase 2 measure-teeth)
    _log_event(QUERY_LOG, {"query": q, "mode": mode, "k": args.k, "hits": len(top),
                           "project": args.project or "", "top": logged_top[:3]})
    _write_status_snapshot(con)
    print("Retrieval is a CITATION to verify, not an answer - open the source before relying on it.")
    print("  (bad hit? run:  mnemosyne flag-last \"why it was wrong\"  - feeds the re-embed signal)")
    return 0


def cmd_flag(args):
    """Mark the MOST RECENT query as a bad retrieval. Your failing queries become the eval set, for free -
    the flag-rate drives the model-upgrade signal (see upgrade_signal / `status`)."""
    queries = _read_jsonl(QUERY_LOG)
    if not queries:
        print("[flag-last] no queries logged yet - run a query first."); return 1
    last = queries[-1]
    _log_event(FLAG_LOG, {"query": last.get("query", ""), "query_ts": last.get("ts", ""),
                          "reason": args.reason or "", "top": last.get("top", [])})
    print("[flag-last] flagged: %s" % (last.get("query", "")[:70]))
    if args.reason:
        print("            reason: %s" % args.reason)
    con = connect()
    level, why = upgrade_signal(con)
    print("            re-embed signal now: [%s] %s" % (level.upper(), why))
    _write_status_snapshot(con)
    return 0


def cmd_status(args):
    con = connect()
    nf = con.execute("SELECT COUNT(*) FROM files").fetchone()[0]
    nc = con.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    print("Mnemosyne status  (%s)" % DB_PATH)
    print("  files : %d" % nf)
    print("  chunks: %d" % nc)
    ne = con.execute("SELECT COUNT(*) FROM chunks WHERE embedding IS NOT NULL").fetchone()[0]
    semantic = "ON (%s)" % emb.MODEL_NAME if (emb and emb.EMBED_AVAILABLE) else "OFF - lexical only"
    print("  embedded: %d/%d chunks   semantic: %s" % (ne, nc, semantic))
    rows = con.execute("SELECT project,COUNT(*) FROM chunks GROUP BY project ORDER BY 2 DESC").fetchall()
    if rows:
        print("  by project:")
        for p, n in rows:
            last = con.execute("SELECT MAX(ingested_at) FROM chunks WHERE project=?", (p,)).fetchone()[0]
            print("    %-24s %5d chunks   last %s" % (p, n, (last or "")[:19]))
    # query telemetry + the re-embed signal (phase 2)
    rq = _recent(_read_jsonl(QUERY_LOG))
    rf = _recent(_read_jsonl(FLAG_LOG))
    print("  queries (last %dd): %d   flagged bad: %d" % (SIGNAL_WINDOW_DAYS, len(rq), len(rf)))
    level, why = upgrade_signal(con)
    print("  re-embed signal: [%s] %s" % (level.upper(), why))
    _write_status_snapshot(con)
    return 0


def cmd_forget(args):
    con = connect()
    if args.project:
        ids = [r[0] for r in con.execute("SELECT id FROM chunks WHERE project=?", (args.project,))]
        for cid in ids:
            con.execute("DELETE FROM chunks_fts WHERE rowid=?", (cid,))
        con.execute("DELETE FROM chunks WHERE project=?", (args.project,))
        con.execute("DELETE FROM files WHERE project=?", (args.project,))
        print("Forgot project '%s' (%d chunks)." % (args.project, len(ids)))
    elif args.path:
        _forget_file(con, os.path.abspath(args.path))
        print("Forgot: %s" % os.path.abspath(args.path))
    else:
        print("[ERROR] specify --project or --path"); return 1
    con.commit()
    return 0


def _ensure_semantic_runtime(cmd):
    """Self-heal the interpreter so semantic search actually runs.

    Embeddings live in the pinned venv (fastembed/bge-small). A bare `python` often resolves to some other
    venv WITHOUT fastembed, silently dropping to lexical-only - and on `ingest` that builds a half-embedded,
    inconsistent corpus. So: if fastembed is missing here but the pinned venv exists, RE-RUN this command
    under it (loop-guarded via MNEMO_REEXEC). If the venv is missing/broken too, degrade VISIBLY - warn for
    read commands, and REFUSE `ingest` rather than corrupt the corpus.
    """
    if emb and emb.EMBED_AVAILABLE:
        return
    here = os.path.dirname(os.path.abspath(__file__))
    venv_py = os.path.abspath(os.path.join(here, "..", ".venv", "Scripts", "python.exe"))
    already = os.environ.get("MNEMO_REEXEC") == "1"
    same = os.path.normcase(venv_py) == os.path.normcase(os.path.abspath(sys.executable))
    if not already and not same and os.path.isfile(venv_py):
        sys.stderr.write("[mnemosyne] semantic layer needs the pinned venv; re-running under it...\n")
        env = dict(os.environ); env["MNEMO_REEXEC"] = "1"
        import subprocess
        try:
            sys.exit(subprocess.run([venv_py, os.path.abspath(__file__)] + sys.argv[1:], env=env).returncode)
        except OSError as e:
            sys.stderr.write("[mnemosyne] re-exec failed: %s\n" % e)
    sys.stderr.write(
        "[mnemosyne] WARNING: semantic OFF - fastembed unavailable and the pinned venv (mnemosyne\\.venv)\n"
        "            is missing or lacks it. Rebuild: recreate .venv on Python 3.11 and\n"
        "            `.venv\\Scripts\\python -m pip install -r requirements.txt`.\n")
    if cmd == "ingest":
        sys.stderr.write("[mnemosyne] REFUSING lexical-only ingest (would build a half-embedded corpus). "
                         "Fix the venv, then re-run.\n")
        sys.exit(3)
    sys.stderr.write("[mnemosyne] proceeding LEXICAL-ONLY (read-only command).\n")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Mnemosyne - local memory (v1 lexical).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ingest"); p.add_argument("path")
    p.add_argument("--project"); p.add_argument("--allow-governed", action="store_true")
    p.add_argument("--watch", action="store_true",
                   help="mark this project HIGH-STAKES: indexing it flips the re-embed signal to ACT")
    p.set_defaults(fn=cmd_ingest)
    p = sub.add_parser("query"); p.add_argument("query"); p.add_argument("-k", type=int, default=6)
    p.add_argument("--project"); p.add_argument("--lexical", action="store_true"); p.set_defaults(fn=cmd_query)
    p = sub.add_parser("status"); p.set_defaults(fn=cmd_status)
    p = sub.add_parser("flag-last", help="mark the most recent query as a bad retrieval (feeds re-embed signal)")
    p.add_argument("reason", nargs="?", default=""); p.set_defaults(fn=cmd_flag)
    p = sub.add_parser("forget"); p.add_argument("--project"); p.add_argument("--path")
    p.set_defaults(fn=cmd_forget)
    args = ap.parse_args()
    _ensure_semantic_runtime(args.cmd)
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
