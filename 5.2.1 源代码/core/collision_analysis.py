from dataclasses import dataclass
from time import perf_counter
from typing import Callable

from .bit_utils import int_to_bits, validate_binary
from .cipher import encrypt_block


@dataclass(frozen=True)
class PlaintextCollisionResult:
    plaintext: str
    ciphertext_to_keys: dict[str, list[str]]
    distinct_ciphertexts: int
    collision_ciphertexts: int
    max_keys_for_one_ciphertext: int


@dataclass(frozen=True)
class AllPlaintextsSummary:
    total_plaintexts: int
    total_encryptions: int
    plaintexts_with_collisions: int
    min_distinct_ciphertexts: int
    max_distinct_ciphertexts: int
    average_distinct_ciphertexts: float
    global_max_keys_for_one_ciphertext: int
    elapsed_seconds: float
    per_plaintext: list[dict]


def analyze_plaintext(plaintext: str) -> PlaintextCollisionResult:
    """Group all 1024 keys by ciphertext for one fixed plaintext."""
    plaintext = validate_binary(plaintext, 8, "Plaintext")

    mapping: dict[str, list[str]] = {}
    for key_value in range(1024):
        key = int_to_bits(key_value, 10)
        ciphertext = encrypt_block(plaintext, key)
        mapping.setdefault(ciphertext, []).append(key)

    # Count ciphertext groups containing multiple keys, not the keys themselves.
    collision_count = sum(1 for keys in mapping.values() if len(keys) > 1)
    max_bucket = max((len(keys) for keys in mapping.values()), default=0)

    return PlaintextCollisionResult(
        plaintext=plaintext,
        ciphertext_to_keys=dict(sorted(mapping.items())),
        distinct_ciphertexts=len(mapping),
        collision_ciphertexts=collision_count,
        max_keys_for_one_ciphertext=max_bucket,
    )


def analyze_all_plaintexts(
    progress_callback: Callable[[int], None] | None = None,
) -> AllPlaintextsSummary:
    """Enumerate every plaintext/key combination, collecting per-plaintext counts."""
    started = perf_counter()

    rows: list[dict] = []
    for plaintext_value in range(256):
        plaintext = int_to_bits(plaintext_value, 8)
        result = analyze_plaintext(plaintext)
        rows.append(
            {
                "plaintext": plaintext,
                "distinct_ciphertexts": result.distinct_ciphertexts,
                "collision_ciphertexts": result.collision_ciphertexts,
                "max_keys_for_one_ciphertext": result.max_keys_for_one_ciphertext,
            }
        )
        if progress_callback and (plaintext_value + 1) % 4 == 0:
            progress_callback(round((plaintext_value + 1) * 100 / 256))

    distinct_counts = [row["distinct_ciphertexts"] for row in rows]
    max_bucket_sizes = [row["max_keys_for_one_ciphertext"] for row in rows]

    elapsed = perf_counter() - started
    if progress_callback:
        progress_callback(100)

    return AllPlaintextsSummary(
        total_plaintexts=256,
        total_encryptions=256 * 1024,
        plaintexts_with_collisions=sum(
            1 for row in rows if row["collision_ciphertexts"] > 0
        ),
        min_distinct_ciphertexts=min(distinct_counts),
        max_distinct_ciphertexts=max(distinct_counts),
        average_distinct_ciphertexts=sum(distinct_counts) / len(distinct_counts),
        global_max_keys_for_one_ciphertext=max(max_bucket_sizes),
        elapsed_seconds=elapsed,
        per_plaintext=rows,
    )
