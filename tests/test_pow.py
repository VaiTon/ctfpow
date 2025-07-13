# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: MIT

import base64
import struct
import gmpy2
import sys
import os
import pytest

from unittest.mock import patch

# Add src directory to path for importing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ctfpow.pow import (
    Challenge, generate_challenge, decode_challenge, create_challenge,
    verify_solution, solve_challenge, _decode_solution,
    VERSION, MOD, EXP, ONE, TWO
)

# --- CONSTANTS ---

def test_version():
    assert VERSION == "s"

def test_mod_value():
    expected_mod = gmpy2.mpz((1 << 1279) - 1)
    assert MOD == expected_mod

def test_exp_value():
    expected_exp = gmpy2.mpz(1 << 1277)
    assert EXP == expected_exp

def test_one_two_values():
    assert ONE == gmpy2.mpz(1)
    assert TWO == gmpy2.mpz(2)

# --- CHALLENGE CLASS ---

@pytest.fixture
def challenge():
    return Challenge(5, gmpy2.mpz(12345))

def test_challenge_init(challenge):
    assert challenge.d == 5
    assert challenge.x == gmpy2.mpz(12345)

def test_challenge_str(challenge):
    challenge_str = str(challenge)
    parts = challenge_str.split('.')
    assert len(parts) == 3
    assert parts[0] == VERSION

    d_bytes = base64.b64decode(parts[1])
    d_bytes = d_bytes.rjust(4, b'\x00')
    decoded_difficulty = struct.unpack('>I', d_bytes)[0]
    assert decoded_difficulty == challenge.d

    x_bytes = base64.b64decode(parts[2])
    decoded_x = gmpy2.mpz.from_bytes(x_bytes, 'big')
    assert decoded_x == challenge.x

def test_challenge_str_zero_x():
    challenge = Challenge(1, gmpy2.mpz(0))
    challenge_str = str(challenge)
    parts = challenge_str.split('.')
    x_bytes = base64.b64decode(parts[2])
    assert x_bytes == b'\x00'

def test_solve_and_check_basic():
    low_difficulty_challenge = Challenge(1, gmpy2.mpz(100))
    solution = low_difficulty_challenge.solve()
    assert solution.startswith(VERSION + '.')
    valid, error = low_difficulty_challenge.check(solution)
    assert valid
    assert error is None

def test_solve_and_check_zero_difficulty():
    challenge = Challenge(0, gmpy2.mpz(12345))
    solution = challenge.solve()
    valid, error = challenge.check(solution)
    assert valid
    assert error is None

@pytest.mark.parametrize("invalid_solution", [
    "invalid",
    "wrong.format",
    "t.invalidversion",
    "",
    "s.",
    "s.invalid_base64",
])
def test_check_invalid_solution_format(challenge, invalid_solution):
    valid, error = challenge.check(invalid_solution)
    assert not valid
    assert error is not None

def test_check_wrong_solution(challenge):
    wrong_y = gmpy2.mpz(999999)
    y_bytes = wrong_y.to_bytes((wrong_y.bit_length() + 7) // 8, 'big')
    wrong_solution = f"{VERSION}.{base64.b64encode(y_bytes).decode('ascii')}"
    valid, error = challenge.check(wrong_solution)
    assert not valid
    assert error == "solution does not match challenge"

# --- GENERATE CHALLENGE ---

def test_generate_challenge():
    difficulty = 3
    challenge = generate_challenge(difficulty)
    assert isinstance(challenge, Challenge)
    assert challenge.d == difficulty
    assert isinstance(challenge.x, gmpy2.mpz)
    assert 0 <= challenge.x.bit_length() <= 128

def test_create_challenge():
    difficulty = 2
    challenge = create_challenge(difficulty)
    assert isinstance(challenge, Challenge)
    assert challenge.d == difficulty

def test_generate_challenge_deterministic(monkeypatch):
    test_bytes = b'\x01\x02\x03\x04' + b'\x00' * 12
    monkeypatch.setattr("secrets.token_bytes", lambda n: test_bytes)
    challenge = generate_challenge(5)
    expected_x = gmpy2.mpz.from_bytes(test_bytes, 'big')
    assert challenge.x == expected_x
    assert challenge.d == 5

# --- DECODE CHALLENGE ---

def test_decode_challenge_valid():
    original_challenge = Challenge(3, gmpy2.mpz(54321))
    challenge_str = str(original_challenge)
    decoded_challenge = decode_challenge(challenge_str)
    assert decoded_challenge is not None
    assert decoded_challenge.d == original_challenge.d
    assert decoded_challenge.x == original_challenge.x

@pytest.mark.parametrize("invalid_challenge", [
    "invalid",
    "wrong.format",
    "t.wrong.version",
    "",
    "s.only.one.extra",
    "s.",
    "s.valid_difficulty",
])
def test_decode_challenge_invalid_format(invalid_challenge):
    result = decode_challenge(invalid_challenge)
    assert result is None

def test_decode_challenge_invalid_base64():
    invalid_b64_challenge = f"{VERSION}.invalid_base64.invalid_base64"
    result = decode_challenge(invalid_b64_challenge)
    assert result is None

def test_decode_challenge_oversized_difficulty():
    oversized_d_bytes = b'\x00\x00\x00\x00\x01'
    d_b64 = base64.b64encode(oversized_d_bytes).decode('ascii')
    x_b64 = base64.b64encode(b'\x01').decode('ascii')
    invalid_challenge = f"{VERSION}.{d_b64}.{x_b64}"
    result = decode_challenge(invalid_challenge)
    assert result is None

def test_decode_challenge_zero_x():
    challenge = Challenge(1, gmpy2.mpz(0))
    challenge_str = str(challenge)
    decoded = decode_challenge(challenge_str)
    assert decoded is not None
    assert decoded.x == gmpy2.mpz(0)

# --- DECODE SOLUTION ---

def test_decode_solution_valid():
    test_y = gmpy2.mpz(98765)
    y_bytes = test_y.to_bytes((test_y.bit_length() + 7) // 8, 'big')
    solution_str = f"{VERSION}.{base64.b64encode(y_bytes).decode('ascii')}"
    decoded_y = _decode_solution(solution_str)
    assert decoded_y == test_y

def test_decode_solution_zero():
    sol = base64.b64encode(b'\x00').decode('ascii')
    solution_str = f"{VERSION}.{sol}"
    decoded_y = _decode_solution(solution_str)
    assert decoded_y == gmpy2.mpz(0)

@pytest.mark.parametrize("invalid_solution,expected", [
    ("invalid", None),
    ("wrong.version.extra", None),
    ("t.wrong_version", None),
    ("", None),
    ("s.", gmpy2.mpz(0)),  # Accept as valid, expect 0
    ("s.invalid_base64", None),
])
def test_decode_solution_invalid_format(invalid_solution, expected):
    result = _decode_solution(invalid_solution)
    assert result == expected

# --- CONVENIENCE FUNCTIONS ---

def test_verify_solution_valid():
    challenge = generate_challenge(1)
    challenge_str = str(challenge)
    solution_str = challenge.solve()
    result = verify_solution(challenge_str, solution_str)
    assert result

def test_verify_solution_invalid_challenge():
    result = verify_solution("invalid_challenge", "any_solution")
    assert not result

def test_verify_solution_invalid_solution():
    challenge = generate_challenge(1)
    challenge_str = str(challenge)
    result = verify_solution(challenge_str, "invalid_solution")
    assert not result

def test_solve_challenge_valid():
    challenge = generate_challenge(1)
    challenge_str = str(challenge)
    solution = solve_challenge(challenge_str)
    assert solution is not None
    assert solution.startswith(VERSION + '.')
    assert verify_solution(challenge_str, solution)

def test_solve_challenge_invalid():
    result = solve_challenge("invalid_challenge")
    assert result is None

# --- END-TO-END INTEGRATION ---

def test_full_workflow_low_difficulty():
    difficulty = 1
    challenge = generate_challenge(difficulty)
    challenge_str = str(challenge)
    decoded_challenge = decode_challenge(challenge_str)
    assert decoded_challenge is not None
    assert decoded_challenge.d == difficulty
    solution = decoded_challenge.solve()
    valid, error = decoded_challenge.check(solution)
    assert valid
    assert error is None
    assert verify_solution(challenge_str, solution)
    convenience_solution = solve_challenge(challenge_str)
    assert verify_solution(challenge_str, convenience_solution)

@pytest.mark.parametrize("difficulty", [0, 1, 2])
def test_multiple_challenges_different_difficulties(difficulty):
    challenge = generate_challenge(difficulty)
    solution = challenge.solve()
    valid, error = challenge.check(solution)
    assert valid
    assert error is None

def test_challenge_solution_persistence():
    original_challenge = generate_challenge(1)
    challenge_str = str(original_challenge)
    solution_str = original_challenge.solve()
    persisted_challenge_str = challenge_str
    persisted_solution_str = solution_str
    restored_challenge = decode_challenge(persisted_challenge_str)
    assert restored_challenge is not None
    valid, error = restored_challenge.check(persisted_solution_str)
    assert valid
    assert error is None
