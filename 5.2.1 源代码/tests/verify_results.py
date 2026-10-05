"""Verify core results and boundaries; this is not cross-group testing."""
from dataclasses import asdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.cipher import encrypt_block, decrypt_block, encrypt_block_with_trace
from core.key_schedule import generate_subkeys
from core.text_cipher import (
    encrypt_text_ascii, decrypt_text_ascii, bytes_to_hex, hex_to_bytes,
    encrypt_bytes, decrypt_bytes,
)
from core.brute_force import brute_force
from core.collision_analysis import analyze_plaintext, analyze_all_plaintexts
from verification_io import output_path, save_record, require


def main() -> None:
    destination = output_path("core_results")
    key = "1010000010"
    vectors = [
        ("10101010", key, "00001001"), ("11010111", key, "11101000"),
        ("00000000", "0000000000", "11110000"), ("11111111", "1111111111", "00001111"),
        ("00000000", "1111111111", "11101011"), ("11111111", "0000000000", "00010100"),
        ("01010101", key, "00000101"),
    ]
    rows = []
    for plaintext, original_key, expected in vectors:
        actual = encrypt_block(plaintext, original_key)
        recovered = decrypt_block(expected, original_key)
        require(actual == expected and recovered == plaintext, "Basic vector mismatch")
        rows.append(dict(plaintext=plaintext, key=original_key, ciphertext=actual,
                         recovered=recovered, passed=True))
    encrypted = encrypt_text_ascii("Hello SDES!", key)
    require(bytes_to_hex(encrypted) == "E4 5C 89 89 AB C2 CB 9B 30 CB AD", "ASCII ciphertext")
    require(decrypt_text_ascii(encrypted, key) == "Hello SDES!", "ASCII recovery")
    ascii_text = "".join(chr(value) for value in range(128))
    require(decrypt_text_ascii(encrypt_text_ascii(ascii_text, key), key) == ascii_text, "All ASCII")
    raw_bytes = bytes(range(256))
    require(decrypt_bytes(encrypt_bytes(raw_bytes, key), key) == raw_bytes, "All bytes")
    error_cases = [
        ("short_and_nonbinary", lambda: encrypt_block("10102", key)),
        ("nonbinary_8bit", lambda: encrypt_block("10102111", key)),
        ("short_block", lambda: encrypt_block("1010", key)),
        ("long_block", lambda: encrypt_block("101010101", key)),
        ("short_key", lambda: encrypt_block("10101010", "10101")),
        ("long_key", lambda: encrypt_block("10101010", key + "0")),
        ("empty_block", lambda: encrypt_block("", key)),
        ("non_ascii", lambda: encrypt_text_ascii("你好", key)),
        ("bad_hex", lambda: hex_to_bytes("G4")),
        ("odd_hex", lambda: hex_to_bytes("A")),
        ("empty_encrypt_bad_key", lambda: encrypt_bytes(b"", "bad")),
        ("empty_decrypt_bad_key", lambda: decrypt_bytes(b"", "bad")),
        ("empty_text_encrypt_bad_key", lambda: encrypt_text_ascii("", "bad")),
        ("empty_text_decrypt_bad_key", lambda: decrypt_text_ascii(b"", "bad")),
        ("empty_pairs", lambda: brute_force([])),
    ]
    errors = []
    for label, operation in error_cases:
        try:
            operation()
        except ValueError as error:
            errors.append(dict(case=label, message=str(error), passed=True))
        else:
            raise AssertionError(f"Expected ValueError: {label}")
    require(encrypt_bytes(b"", key) == decrypt_bytes(b"", key) == b"", "Valid empty bytes")
    require(encrypt_text_ascii("", key) == b"" and decrypt_text_ascii(b"", key) == "", "Valid empty text")
    single = brute_force([("10101010", "00001001")])
    double = brute_force([("10101010", "00001001"), ("11010111", "11101000")])
    require(single.candidate_keys == ["0001110011", "0101110011", key, "1110000010"], "Single candidates")
    require(double.candidate_keys == [key, "1110000010"], "Double candidates")
    require(generate_subkeys(key) == generate_subkeys("1110000010") == ("10100100", "10010010"), "Equivalent keys")
    for value in range(256):
        plaintext = f"{value:08b}"
        require(encrypt_block(plaintext, key) == encrypt_block(plaintext, "1110000010"), "Equivalent output")
    progress = []
    none = brute_force([("00000000", "00000000"), ("00000000", "11111111")], progress.append)
    require(none.candidate_keys == [] and none.tested_keys == 1024 and progress[-1] == 100, "No candidates")
    one = analyze_plaintext("10101010")
    full = analyze_all_plaintexts()
    require((one.distinct_ciphertexts, one.collision_ciphertexts, one.max_keys_for_one_ciphertext)
            == (254, 254, 8), "Single collision statistics")
    require((full.total_encryptions, full.plaintexts_with_collisions, full.min_distinct_ciphertexts,
             full.max_distinct_ciphertexts, full.global_max_keys_for_one_ciphertext)
            == (262144, 256, 254, 254, 8), "Full collision statistics")
    save_record(destination, dict(
        status="PASS", scope="Core regression; not manual GUI or cross-group testing.",
        basic=rows, trace=encrypt_block_with_trace("10101010", key)[1],
        text_hex=bytes_to_hex(encrypted), input_errors=errors,
        ascii_codepoints=128, byte_values=256, empty_input_key_validation="PASS",
        single_pair=asdict(single), two_pairs=asdict(double),
        single_plaintext={name: value for name, value in asdict(one).items() if name != "ciphertext_to_keys"},
        full_space=asdict(full), equivalent_keys_confirmed_for_all_256_plaintexts=True,
    ))
    print("PASS: vectors, 15 invalid-input cases, ASCII/bytes, key validation, brute force, collision space.")


if __name__ == "__main__":
    main()
