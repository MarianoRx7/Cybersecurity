"""Hashcash-style proof of work: cheap for one signup, expensive at scale."""
import hashlib
import itertools

MAX_SOLUTION_LEN = 32


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits


def verify_pow(nonce: str, solution: str, bits: int) -> bool:
    if not isinstance(solution, str) or not solution or len(solution) > MAX_SOLUTION_LEN:
        return False
    digest = hashlib.sha256(f"{nonce}:{solution}".encode()).digest()
    return leading_zero_bits(digest) >= bits


def solve_pow(nonce: str, bits: int) -> str:
    """Reference solver (the browser does the same thing in JS)."""
    for counter in itertools.count():
        if verify_pow(nonce, str(counter), bits):
            return str(counter)
    raise AssertionError("unreachable")
