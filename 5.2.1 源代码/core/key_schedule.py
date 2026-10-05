from .bit_utils import left_rotate, permute, validate_binary
from .constants import P10, P8


def generate_subkeys(key: str) -> tuple[str, str]:
    """Generate K1 and K2 exactly from the homework formula.

    k_i = P8(Shift^i(P10(K))), i = 1, 2

    The two 5-bit halves obtained after P10 are therefore rotated by one
    position for K1 and by two positions for K2.
    """
    key = validate_binary(key, 10, "Key")

    p10_output = permute(key, P10)
    left, right = p10_output[:5], p10_output[5:]

    shift1 = left_rotate(left, 1) + left_rotate(right, 1)
    shift2 = left_rotate(left, 2) + left_rotate(right, 2)

    return permute(shift1, P8), permute(shift2, P8)


def generate_subkeys_with_trace(key: str) -> tuple[str, str, dict]:
    key = validate_binary(key, 10, "Key")

    p10_output = permute(key, P10)
    left, right = p10_output[:5], p10_output[5:]

    left1, right1 = left_rotate(left, 1), left_rotate(right, 1)
    left2, right2 = left_rotate(left, 2), left_rotate(right, 2)

    shift1 = left1 + right1
    shift2 = left2 + right2

    k1 = permute(shift1, P8)
    k2 = permute(shift2, P8)

    trace = {
        "original_key": key,
        "p10": p10_output,
        "p10_left": left,
        "p10_right": right,
        "left_shift_1": shift1,
        "left_shift_2": shift2,
        "k1": k1,
        "k2": k2,
    }
    return k1, k2, trace
