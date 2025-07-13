# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: MIT

import base64
import struct
import secrets
from typing import Optional, Tuple

VERSION = "s"

# Initialize constants for modular arithmetic (matching Go implementation)
# mod = 2^1279 - 1
# exp = 2^1277
MOD = (1 << 1279) - 1
EXP = 1 << 1277
ONE = 1
TWO = 2


class Challenge:
    """ctfpow Challenge implementation"""

    def __init__(self, difficulty: int, x: int):
        self.d = difficulty
        self.x = x

    def __str__(self) -> str:
        """Encode the challenge in ctfpow format"""
        # Encode difficulty as 4-byte big-endian
        d_bytes = struct.pack(">I", self.d)
        d_b64 = base64.b64encode(d_bytes).decode("ascii")

        # Encode x as bytes
        x_bytes = (
            self.x.to_bytes((self.x.bit_length() + 7) // 8, "big")
            if self.x > 0
            else b"\x00"
        )
        x_b64 = base64.b64encode(x_bytes).decode("ascii")

        return f"{VERSION}.{d_b64}.{x_b64}"

    def solve(self) -> str:
        """Solve the challenge and return solution proof"""
        x = int(self.x)  # Copy to avoid mutation

        for i in range(self.d):
            x = pow(x, EXP, MOD)
            x = x ^ ONE

        # Encode solution
        y_bytes = x.to_bytes((x.bit_length() + 7) // 8, "big") if x > 0 else b"\x00"
        y_b64 = base64.b64encode(y_bytes).decode("ascii")

        return f"{VERSION}.{y_b64}"

    def check(self, solution: str) -> Tuple[bool, Optional[str]]:
        """Check if solution is valid"""
        y = _decode_solution(solution)
        if y is None:
            return False, "invalid solution format"

        # Reverse the solve operation
        for i in range(self.d):
            y = y ^ ONE
            y = pow(y, TWO, MOD)

        x = int(self.x)  # Copy to avoid mutation

        # Check if y matches x or its complement in the field
        if x == y:
            return True, None

        x_complement = MOD - self.x
        if x_complement == y:
            return True, None

        return False, "solution does not match challenge"


def generate_challenge(difficulty: int) -> Challenge:
    """Generate a new random challenge"""
    # Generate 16 random bytes (128 bits)
    random_bytes = secrets.token_bytes(16)
    x = int.from_bytes(random_bytes, "big")

    return Challenge(difficulty, x)


def decode_challenge(challenge_str: str) -> Optional[Challenge]:
    """Decode a challenge string into a Challenge object"""
    try:
        # Must have exactly two dots (i.e., three parts)
        if challenge_str.count(".") != 2:
            return None
        parts = challenge_str.split(".", 2)
        if len(parts) != 3 or parts[0] != VERSION:
            return None

        # Decode difficulty
        d_bytes = base64.b64decode(parts[1])
        if len(d_bytes) > 4:
            return None

        # Pad with zeros if needed
        d_bytes = d_bytes.rjust(4, b"\x00")
        difficulty = struct.unpack(">I", d_bytes)[0]

        # Decode x
        x_bytes = base64.b64decode(parts[2])
        x = int.from_bytes(x_bytes, "big") if x_bytes else 0

        return Challenge(difficulty, x)

    except Exception:
        return None


def _decode_solution(solution_str: str) -> Optional[int]:
    """Decode a solution string into an int"""
    try:
        parts = solution_str.split(".", 1)
        if len(parts) != 2 or parts[0] != VERSION:
            return None

        y_bytes = base64.b64decode(parts[1])
        return int.from_bytes(y_bytes, "big") if y_bytes else 0

    except Exception:
        return None


def verify_solution(challenge_str: str, solution_str: str) -> bool:
    """Verify a solution against a challenge string"""
    challenge = decode_challenge(challenge_str)
    if challenge is None:
        return False

    valid, _ = challenge.check(solution_str)
    return valid


def solve_challenge(challenge_str: str) -> Optional[str]:
    """Solve a challenge given its string representation"""
    challenge = decode_challenge(challenge_str)
    if challenge is None:
        return None

    return challenge.solve()
