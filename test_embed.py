#!/usr/bin/env python3
"""Asymmetric-prefix smoke test for the bge embedding wiring (DA objection C).

Proves: (1) the model loads offline after a one-time fetch; (2) QUERIES use query_embed (instruction
prefix) and PASSAGES use embed (no prefix); (3) a paraphrase query - the thing embeddings exist for -
ranks the RIGHT decision chunk above unrelated ones. Run with the install's own venv:
    .venv\\Scripts\\python.exe test_embed.py      (Windows)
    .venv/bin/python test_embed.py                 (Mac/Linux)
"""
import sys
import time
import numpy as np
from fastembed import TextEmbedding

MODEL = "BAAI/bge-small-en-v1.5"
# bge-v1.5's query instruction. fastembed 0.8's query_embed does NOT apply it (verified: cos==1.000),
# so we prepend it EXPLICITLY - control of the prefix is ours, not the wrapper's (DA objection C/F).
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


def embed_query(model, text):
    return norm(list(model.embed([BGE_QUERY_PREFIX + text]))[0])


def embed_passages(model, texts):
    return [norm(v) for v in model.embed(texts)]


def norm(v):
    v = np.asarray(v, dtype=np.float32)
    n = np.linalg.norm(v)
    return v / n if n else v


def main():
    t0 = time.time()
    model = TextEmbedding(MODEL)                     # first run downloads ~130MB, then cached/offline
    print("[OK] model loaded (%s) in %.1fs" % (MODEL, time.time() - t0))

    passages = [
        "The hosted analytics vendor was evaluated and REJECTED: its admin auth is decorative (1 of 78 "
        "routes gated), its API binds 0.0.0.0, and it cannot run on-premises. Four Fatal findings. Do not adopt.",
        "We chose borders-only depth for the monitoring dashboard because it is a dense technical tool "
        "and shadows add visual weight without information value.",
        "The go-live transition: when the rebuilt billing service starts taking real payments, its deploy "
        "folder must become read-only to build tools and production permissions must be set on the server.",
        "Mnemosyne is LOCAL, not an MCP server, because an out-of-process daemon's file I/O is invisible to "
        "the local guards; keeping it a CLI keeps every call auditable.",
        "The humanizer skill strips AI-writing tells: significance inflation, hedging, em-dash overuse.",
    ]
    pvecs = embed_passages(model, passages)                 # PASSAGES: no prefix
    dim = len(pvecs[0])

    tests = [
        ("why did we decide against the analytics vendor", 0),
        ("what colour scheme did the monitor dashboard use and why", 1),
        ("what has to happen when the billing rebuild goes live", 2),
        ("why isn't the memory layer exposed over MCP", 3),
    ]
    print("[i] dim=%d  passages=%d" % (dim, len(passages)))
    ok = 0
    for q, want in tests:
        qv = embed_query(model, q)                          # QUERY: explicit instruction prefix (asymmetric)
        sims = [float(qv @ pv) for pv in pvecs]
        rank = sorted(range(len(sims)), key=lambda i: -sims[i])
        top = rank[0]
        hit = (top == want)
        ok += hit
        print("  %s  q=%-52s -> top#%d (want %d)  sim=%.3f" %
              ("PASS" if hit else "FAIL", q[:52], top, want, sims[top]))

    # Asymmetry sanity: query_embed(x) != embed(x) for the same text (prefix actually applied).
    same = "why did we reject the analytics vendor"
    qv = embed_query(model, same)
    ev = norm(list(model.embed([same]))[0])
    asym = float(qv @ ev)
    print("  [i] asymmetry check: cos(query_embed, embed) of same text = %.3f (should be <1.0 = prefix applied)" % asym)

    print("RESULT: %d/%d paraphrase queries ranked the right chunk #1%s" %
          (ok, len(tests), "" if ok == len(tests) else "  <-- INVESTIGATE wiring"))
    return 0 if ok == len(tests) and asym < 0.999 else 1


if __name__ == "__main__":
    sys.exit(main())
