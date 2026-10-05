from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import Callable, Iterable

from .bit_utils import int_to_bits, validate_binary
from .cipher import encrypt_block


@dataclass(frozen=True)
class BruteForceResult:
    candidate_keys: list[str]
    tested_keys: int
    elapsed_seconds: float
    started_at: str
    finished_at: str


def _normalize_pairs(
    known_pairs: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    normalized = []
    for index, (plaintext, ciphertext) in enumerate(known_pairs, start=1):
        p = validate_binary(plaintext, 8, f"Plaintext #{index}")
        c = validate_binary(ciphertext, 8, f"Ciphertext #{index}")
        normalized.append((p, c))
    if not normalized:
        raise ValueError("At least one known plaintext/ciphertext pair is required.")
    return normalized


def brute_force(
    known_pairs: Iterable[tuple[str, str]],
    progress_callback: Callable[[int], None] | None = None,
) -> BruteForceResult:
    """Return every key satisfying all pairs, rather than stopping at a match."""
    pairs = _normalize_pairs(known_pairs)

    started_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    started = perf_counter()

    candidates: list[str] = []
    for key_value in range(1024):
        # Additional pairs filter candidates; equivalent keys can still remain.
        key = int_to_bits(key_value, 10)
        if all(encrypt_block(plaintext, key) == ciphertext for plaintext, ciphertext in pairs):
            candidates.append(key)

        if progress_callback and (key_value + 1) % 32 == 0:
            progress_callback(round((key_value + 1) * 100 / 1024))

    elapsed = perf_counter() - started
    finished_at = datetime.now().astimezone().isoformat(timespec="milliseconds")

    if progress_callback:
        progress_callback(100)

    return BruteForceResult(
        candidate_keys=candidates,
        tested_keys=1024,
        elapsed_seconds=elapsed,
        started_at=started_at,
        finished_at=finished_at,
    )
