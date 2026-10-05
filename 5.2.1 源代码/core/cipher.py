from .bit_utils import permute, validate_binary, xor_bits
from .constants import EP, IP, IP_INV, SBOX1, SBOX2, SP
from .key_schedule import generate_subkeys, generate_subkeys_with_trace


def sbox_lookup(bits: str, sbox: tuple[tuple[int, ...], ...]) -> str:
    """Use the outer bits as the row and the inner bits as the column."""
    bits = validate_binary(bits, 4, "S-Box input")
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1] + bits[2], 2)
    value = sbox[row][column]
    return format(value, "02b")


def round_function(right_half: str, subkey: str) -> str:
    """Expand R, XOR the subkey, apply the two S-boxes, then permute with SP."""
    right_half = validate_binary(right_half, 4, "Right half")
    subkey = validate_binary(subkey, 8, "Subkey")

    expanded = permute(right_half, EP)
    mixed = xor_bits(expanded, subkey)
    left4, right4 = mixed[:4], mixed[4:]
    s1_output = sbox_lookup(left4, SBOX1)
    s2_output = sbox_lookup(right4, SBOX2)
    return permute(s1_output + s2_output, SP)


def round_function_with_trace(right_half: str, subkey: str) -> tuple[str, dict]:
    right_half = validate_binary(right_half, 4, "Right half")
    subkey = validate_binary(subkey, 8, "Subkey")

    expanded = permute(right_half, EP)
    mixed = xor_bits(expanded, subkey)
    left4, right4 = mixed[:4], mixed[4:]

    s1_output = sbox_lookup(left4, SBOX1)
    s2_output = sbox_lookup(right4, SBOX2)
    combined = s1_output + s2_output
    sp_output = permute(combined, SP)

    return sp_output, {
        "right_half": right_half,
        "subkey": subkey,
        "ep": expanded,
        "ep_xor_key": mixed,
        "sbox1_input": left4,
        "sbox1_output": s1_output,
        "sbox2_input": right4,
        "sbox2_output": s2_output,
        "sbox_combined": combined,
        "sp": sp_output,
    }


def fk(bits: str, subkey: str) -> str:
    """One Feistel step changes the left half while preserving the right half."""
    bits = validate_binary(bits, 8, "Round input")
    left, right = bits[:4], bits[4:]
    new_left = xor_bits(left, round_function(right, subkey))
    return new_left + right


def fk_with_trace(bits: str, subkey: str) -> tuple[str, dict]:
    bits = validate_binary(bits, 8, "Round input")
    left, right = bits[:4], bits[4:]

    f_output, f_trace = round_function_with_trace(right, subkey)
    new_left = xor_bits(left, f_output)
    output = new_left + right

    return output, {
        "input": bits,
        "left": left,
        "right": right,
        "f": f_trace,
        "left_xor_f": new_left,
        "output": output,
    }


def switch_halves(bits: str) -> str:
    bits = validate_binary(bits, 8, "Switch input")
    return bits[4:] + bits[:4]


def _crypt_block(block: str, first_subkey: str, second_subkey: str) -> str:
    # SW occurs only between rounds; IP_INV then restores the bit positions.
    state = permute(block, IP)
    state = fk(state, first_subkey)
    state = switch_halves(state)
    state = fk(state, second_subkey)
    return permute(state, IP_INV)


def encrypt_block(plaintext: str, key: str) -> str:
    plaintext = validate_binary(plaintext, 8, "Plaintext")
    key = validate_binary(key, 10, "Key")
    k1, k2 = generate_subkeys(key)
    return _crypt_block(plaintext, k1, k2)


def decrypt_block(ciphertext: str, key: str) -> str:
    """Invert encryption by reusing the Feistel network with reversed subkeys."""
    ciphertext = validate_binary(ciphertext, 8, "Ciphertext")
    key = validate_binary(key, 10, "Key")
    k1, k2 = generate_subkeys(key)
    return _crypt_block(ciphertext, k2, k1)


def _crypt_block_with_trace(
    block: str,
    key: str,
    first_subkey_name: str,
    second_subkey_name: str,
) -> tuple[str, dict]:
    block = validate_binary(block, 8, "Input block")
    key = validate_binary(key, 10, "Key")

    k1, k2, key_trace = generate_subkeys_with_trace(key)
    subkeys = {"K1": k1, "K2": k2}
    first_subkey = subkeys[first_subkey_name]
    second_subkey = subkeys[second_subkey_name]

    ip_output = permute(block, IP)
    round1_output, round1_trace = fk_with_trace(ip_output, first_subkey)
    switched = switch_halves(round1_output)
    round2_output, round2_trace = fk_with_trace(switched, second_subkey)
    final_output = permute(round2_output, IP_INV)

    trace = {
        "input": block,
        "key_schedule": key_trace,
        "ip": ip_output,
        "round1_key": first_subkey_name,
        "round1": round1_trace,
        "sw": switched,
        "round2_key": second_subkey_name,
        "round2": round2_trace,
        "ip_inv": final_output,
    }
    return final_output, trace


def encrypt_block_with_trace(plaintext: str, key: str) -> tuple[str, dict]:
    plaintext = validate_binary(plaintext, 8, "Plaintext")
    return _crypt_block_with_trace(plaintext, key, "K1", "K2")


def decrypt_block_with_trace(ciphertext: str, key: str) -> tuple[str, dict]:
    ciphertext = validate_binary(ciphertext, 8, "Ciphertext")
    return _crypt_block_with_trace(ciphertext, key, "K2", "K1")
