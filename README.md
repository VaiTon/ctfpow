<!--
SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>

SPDX-License-Identifier: MIT
-->

# ctfpow

A full Python implementation of the [redpwn Proof-of-Work (PoW) challenge](https://github.com/redpwn/pow).

It creates, solves, and verifies challenges that have the same challenge / solution format as the original redpwn PoW implementation.

This package provides a library to be used in CTF challenges or other applications requiring a PoW mechanism, along with a command-line interface (CLI) for easy interaction.

---

## Intended usage

Although this package can be used to solve challenges, its primary purpose is to create and verify them within Python-based environments, given the slower performance of arbitrary-precision arithmetic in Python.

We recommend using the [original redpwn PoW CLI](https://github.com/redpwn/pow) to solve challenges in a more performant way, especially for high difficulty levels.

## Features

- Fully compatible with the redpwn PoW challenge format.
- Generate new challenges with configurable difficulty.
- Solve and verify challenges programmatically or via CLI.
- MIT licensed and tested with `pytest`.
- No external dependencies.

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

## Usage

### Python API

```python
from ctfpow import (
    create_challenge, decode_challenge, solve_challenge,
    verify_solution, Challenge
)

# Generate a challenge
challenge = create_challenge(3) # 3: Difficulty level
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

## Testing

Run all tests with:

```sh
uv run pytest
# or, with coverage
uv run pytest --cov
```

---

## License

This project complies with the REUSE 3.3 specification. Unless otherwise noted, the code in this repository is licensed under the MIT License.

## Credits

- **Original redpwn PoW:** https://github.com/redpwn/pow
