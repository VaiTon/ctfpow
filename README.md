<!--
SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>

SPDX-License-Identifier: MIT
-->

# ctfpow

A Python implementation of the [redpwn Proof-of-Work (PoW) challenge](https://github.com/redpwn/pow).

This package provides a library and CLI for generating, solving, and verifying redpwn-style PoW challenges, commonly used in CTFs and security competitions.

> **Reference:** This project is based on and compatible with the original [redpwn/pow](https://github.com/redpwn/pow) implementation and uses the same challenge/solution format.

---

## Features

- Fully compatible with the redpwn PoW challenge format.
- Generate new challenges with configurable difficulty.
- Solve and verify challenges programmatically or via CLI.
- MIT licensed and tested with `pytest`.
- Python 3.11+.

---

## Installation

Install with [uv](https://github.com/astral-sh/uv), [pip](https://pip.pypa.io/), or your preferred tool:

```sh
uv pip install .
# or
pip install .
```

**Dependencies:**

- [gmpy2](https://pypi.org/project/gmpy2/) (for fast modular arithmetic)
- [pytest](https://pypi.org/project/pytest/) (for testing, optional)

---

## Usage

### CLI

After installation, the `ctfpow` command is available:

```sh
ctfpow --help
```

#### Create a new challenge

```sh
ctfpow create -d 3
# Output: s.<base64-difficulty>.<base64-x>
```

#### Solve a challenge

```sh
ctfpow solve "s.<base64-difficulty>.<base64-x>"
# Output: s.<base64-solution>
```

#### Verify a solution

```sh
ctfpow verify "s.<base64-difficulty>.<base64-x>" "s.<base64-solution>"
# Output: Valid solution. (exit code 0) or Invalid solution. (exit code 1)
```

#### Show challenge info

```sh
ctfpow info "s.<base64-difficulty>.<base64-x>"
# Output: Difficulty and x value
```

---

### Python API

```python
from ctfpow import (
    generate_challenge, decode_challenge, solve_challenge,
    verify_solution, Challenge
)

# Generate a challenge
challenge = generate_challenge(difficulty=3)
challenge_str = str(challenge)

# Solve a challenge
solution_str = challenge.solve()

# Verify a solution
valid, error = challenge.check(solution_str)
assert valid

# Decode from string
decoded = decode_challenge(challenge_str)
assert decoded.d == challenge.d

# Convenience functions
assert verify_solution(challenge_str, solution_str)
solved = solve_challenge(challenge_str)
```

---

## Testing

Run all tests with:

```sh
uv test
# or
pytest
```

All tests are located in `tests/` and use `pytest` style.

---

## License

This project is licensed under the MIT License.

See the [LICENSE](./LICENSE) or the SPDX headers in each file.

---

## Credits

- **Author:** Eyad Issa (VaiTon) <eyadlorenzo@gmail.com>
- **Original redpwn PoW:** https://github.com/redpwn/pow
- **Python implementation:** https://github.com/VaiTon/ctfpow

---

## Changelog

- 0.1.0: Initial release with CLI and Python API.

---

## Security

If you find a security issue, please open an issue or contact the author directly.

---