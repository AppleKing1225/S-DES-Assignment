import re

from .bit_utils import validate_binary
from .cipher import decrypt_block, encrypt_block


def encrypt_bytes(data: bytes, key: str) -> bytes:
    """Encrypt each byte independently; validate the key even for empty data."""
    key = validate_binary(key, 10, "Key")
    output = bytearray()
    for value in data:
        encrypted_bits = encrypt_block(format(value, "08b"), key)
        output.append(int(encrypted_bits, 2))
    return bytes(output)


def decrypt_bytes(data: bytes, key: str) -> bytes:
    """Decrypt byte blocks without padding, including an empty valid message."""
    key = validate_binary(key, 10, "Key")
    output = bytearray()
    for value in data:
        decrypted_bits = decrypt_block(format(value, "08b"), key)
        output.append(int(decrypted_bits, 2))
    return bytes(output)


def encrypt_text_ascii(text: str, key: str) -> bytes:
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Text mode follows the assignment's ASCII requirement; use ASCII characters only.") from exc
    return encrypt_bytes(raw, key)


def decrypt_text_ascii(ciphertext: bytes, key: str) -> str:
    raw = decrypt_bytes(ciphertext, key)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted bytes are not valid ASCII for the supplied key/ciphertext.") from exc


def bytes_to_hex(data: bytes) -> str:
    return " ".join(f"{value:02X}" for value in data)


def bytes_to_binary(data: bytes) -> str:
    return " ".join(f"{value:08b}" for value in data)


def hex_to_bytes(text: str) -> bytes:
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return b""
    if len(compact) % 2 != 0:
        raise ValueError("Hex ciphertext must contain an even number of hexadecimal digits.")
    if re.search(r"[^0-9A-Fa-f]", compact):
        raise ValueError("Hex ciphertext may contain only hexadecimal digits and whitespace.")
    return bytes.fromhex(compact)
