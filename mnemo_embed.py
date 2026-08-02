#!/usr/bin/env python3
"""Local embedding layer for Mnemosyne (fastembed / bge-small-en-v1.5, 384-dim, offline).

Lazy + degrade-visibly: if fastembed isn't importable (e.g. run under a python without it), EMBED_AVAILABLE
is False and Mnemosyne falls back to lexical-only, saying so. The bge query prefix is applied EXPLICITLY
here (fastembed's query_embed does NOT apply it - verified), so query/passage asymmetry is ours to control
and is covered by test_embed.py. Console/log strings are ASCII (Rule B).
"""
import numpy as np

MODEL_NAME = "BAAI/bge-small-en-v1.5"
DIM = 384
MAX_TOKENS = 512                         # bge-small hard cap; longer input is silently truncated
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

try:
    from fastembed import TextEmbedding
    EMBED_AVAILABLE = True
except Exception:
    EMBED_AVAILABLE = False

_model = None


def get_model():
    global _model
    if not EMBED_AVAILABLE:
        return None
    if _model is None:
        _model = TextEmbedding(MODEL_NAME)   # first ever call downloads ~130MB, then cached/offline
    return _model


def _norm(v):
    v = np.asarray(v, dtype=np.float32)
    n = np.linalg.norm(v)
    return v / n if n else v


def approx_tokens(text):
    """Cheap token estimate (~3.5 chars/token, English). Used to WARN on >MAX_TOKENS truncation."""
    return int(len(text) / 3.5)


def embed_passages(texts):
    """Return an (N, DIM) float32 matrix of L2-normalized passage embeddings (no prefix)."""
    m = get_model()
    if m is None:
        return None
    return np.vstack([_norm(v) for v in m.embed(list(texts))]).astype(np.float32)


def embed_query(text):
    """Return a (DIM,) float32 L2-normalized query embedding WITH the bge instruction prefix."""
    m = get_model()
    if m is None:
        return None
    return _norm(list(m.embed([BGE_QUERY_PREFIX + text]))[0])


def to_blob(vec):
    return np.asarray(vec, dtype=np.float32).tobytes()


def from_blob(blob):
    return np.frombuffer(blob, dtype=np.float32) if blob else None
