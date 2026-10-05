def validate_binary(value: str, length: int, label: str) -> str:
    value = value.strip()
    if len(value) != length:
        raise ValueError(f"{label} must contain exactly {length} bits.")
    if any(ch not in "01" for ch in value):
        raise ValueError(f"{label} must contain only 0 and 1.")
    return value


def permute(bits: str, table: tuple[int, ...]) -> str:
    if not table:
        return ""
    if min(table) < 1 or max(table) > len(bits):
        raise ValueError("Permutation table contains an out-of-range position.")
    return "".join(bits[position - 1] for position in table)


def xor_bits(left: str, right: str) -> str:
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length.")
    if any(ch not in "01" for ch in left + right):
        raise ValueError("XOR operands must be binary strings.")
    return "".join("0" if a == b else "1" for a, b in zip(left, right))


def left_rotate(bits: str, amount: int) -> str:
    if not bits:
        raise ValueError("Cannot rotate an empty bit string.")
    amount %= len(bits)
    return bits[amount:] + bits[:amount]


def int_to_bits(value: int, width: int) -> str:
    if value < 0 or value >= (1 << width):
        raise ValueError(f"Value {value} does not fit in {width} bits.")
    return format(value, f"0{width}b")


def bits_to_int(bits: str) -> int:
    if not bits or any(ch not in "01" for ch in bits):
        raise ValueError("Expected a non-empty binary string.")
    return int(bits, 2)
