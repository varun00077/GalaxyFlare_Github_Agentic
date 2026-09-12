"""Tiny BM25 retrieval over playbook / advisory documents.

Deliberately dependency-free: the hackathon brief says vector DBs are optional, and
keyword retrieval is enough for a KB of a few dozen documents. Swap for embeddings
behind the same `search()` signature if the KB grows.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

_TOKEN = re.compile(r"[a-z0-9][a-z0-9.\-]*")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


class BM25Index:
    def __init__(self, docs: list[dict[str, Any]], k1: float = 1.4, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self._tf: list[Counter] = []
        self._len: list[int] = []
        df: Counter = Counter()
        for d in docs:
            toks = tokenize(self._text(d))
            tf = Counter(toks)
            self._tf.append(tf)
            self._len.append(len(toks))
            df.update(tf.keys())
        n = max(len(docs), 1)
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self._avg = (sum(self._len) / n) if docs else 0.0

    @staticmethod
    def _text(d: dict[str, Any]) -> str:
        # Tags are repeated so they weigh more than body text.
        return " ".join([d.get("title", ""), " ".join(d.get("tags", [])) * 3, d.get("text", "")])

    def search(self, query: str, k: int = 3) -> list[tuple[float, dict[str, Any]]]:
        q = tokenize(query)
        scored = []
        for i, d in enumerate(self.docs):
            s = 0.0
            tf = self._tf[i]
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                denom = f + self.k1 * (1 - self.b + self.b * self._len[i] / (self._avg or 1))
                s += self._idf.get(t, 0.0) * f * (self.k1 + 1) / denom
            if s > 0:
                scored.append((s, d))
        scored.sort(key=lambda x: -x[0])
        return scored[:k]
