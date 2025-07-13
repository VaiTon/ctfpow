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

## CLI Installation

This package provides a command-line interface (CLI) for easy interaction with the PoW challenges. You can create, solve, verify, and inspect challenges directly from your terminal.

```shell
uv tool install git+https://github.com/VaiTon/ctfpow
```

## Installation

Install with [uv](https://github.com/astral-sh/uv), [pip](https://pip.pypa.io/), or your preferred tool:

```sh
uv add git+https://github.com/VaiTon/ctfpow
```

## Dependencies

- [gmpy2](https://gmpy2.readthedocs.io/en/latest/)

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
uv run pytest
```

## License

This project is licensed under the MIT License.

See the [LICENSE](./LICENSE) or the SPDX headers in each file.

## Credits

- **Original redpwn PoW:** https://github.com/redpwn/pow
