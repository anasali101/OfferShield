"""Feature B: document fingerprinting and similarity.

Only SHA-256 file fingerprints and hashed word n-grams are persisted. The
document text itself is never written to the database.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from rapidfuzz import fuzz

from services import storage

SHINGLE_SIZE = 5
MAX_SHINGLES = 4000


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_shingles(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", (text or "").lower())
    if not words:
        return []
    if len(words) < SHINGLE_SIZE:
        grams = [" ".join(words)]
    else:
        grams = [" ".join(words[i:i + SHINGLE_SIZE]) for i in range(len(words) - SHINGLE_SIZE + 1)]
    hashed = sorted({hashlib.sha256(gram.encode("utf-8")).hexdigest()[:12] for gram in grams})
    if len(hashed) > MAX_SHINGLES:
        step = len(hashed) / MAX_SHINGLES
        hashed = [hashed[int(i * step)] for i in range(MAX_SHINGLES)]
    return hashed


def compare_shingles(a: list[str], b: list[str]) -> dict:
    if not a or not b:
        return {"score": 0.0, "jaccard": 0.0, "fuzzy": 0.0}
    set_a, set_b = set(a), set(b)
    union = set_a | set_b
    jaccard = len(set_a & set_b) / len(union) if union else 0.0
    fuzzy = fuzz.token_set_ratio(" ".join(sorted(set_a)), " ".join(sorted(set_b))) / 100.0
    return {
        "score": round(max(jaccard, fuzzy), 4),
        "jaccard": round(jaccard, 4),
        "fuzzy": round(fuzzy, 4),
    }


def find_similar_documents(
    db_path,
    shingles: list[str],
    exclude_fingerprint: str | None = None,
    min_score: float = 0.6,
    limit: int = 500,
) -> list[dict]:
    if not shingles:
        return []
    matches = []
    for entry in storage.get_document_signatures(db_path, limit=limit):
        if exclude_fingerprint and entry["fingerprint"] == exclude_fingerprint:
            continue
        comparison = compare_shingles(shingles, entry["shingles"])
        if comparison["score"] >= min_score:
            matches.append(
                {
                    "fingerprint": entry["fingerprint"],
                    "created_at": entry["created_at"],
                    **comparison,
                }
            )
    matches.sort(key=lambda item: item["score"], reverse=True)
    return matches[:3]


def index_document(db_path, fingerprint: str, shingles: list[str]) -> None:
    if shingles:
        storage.add_document_signature(db_path, fingerprint, shingles)


def fingerprint_exists(db_path, fingerprint: str) -> bool:
    return storage.document_fingerprint_exists(db_path, fingerprint)
