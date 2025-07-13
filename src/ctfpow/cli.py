# SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
#
# SPDX-License-Identifier: MIT

import argparse
import sys
from ctfpow.pow import (
    generate_challenge,
    decode_challenge,
    solve_challenge,
    verify_solution,
    Challenge,
)

def cmd_create(args):
    """Create a new challenge and print its string representation."""
    challenge = generate_challenge(args.difficulty)
    print(str(challenge))

def cmd_solve(args):
    """Solve a challenge string and print the solution."""
    solution = solve_challenge(args.challenge)
    if solution is None:
        print("Invalid challenge string.", file=sys.stderr)
        sys.exit(1)
    print(solution)

def cmd_verify(args):
    """Verify a solution against a challenge string."""
    valid = verify_solution(args.challenge, args.solution)
    if valid:
        print("Valid solution.")
        sys.exit(0)
    else:
        print("Invalid solution.", file=sys.stderr)
        sys.exit(1)

def cmd_info(args):
    """Show info about a challenge string."""
    challenge = decode_challenge(args.challenge)
    if challenge is None:
        print("Invalid challenge string.", file=sys.stderr)
        sys.exit(1)
    print(f"Difficulty: {challenge.d}")
    print(f"x: {challenge.x}")

def main():
    parser = argparse.ArgumentParser(
        description="redpow: CLI for redpwn PoW challenge utilities"
    )
    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", required=True
    )

    # create
    parser_create = subparsers.add_parser(
        "create", help="Create a new challenge"
    )
    parser_create.add_argument(
        "-d", "--difficulty", type=int, required=True, help="Challenge difficulty"
    )
    parser_create.set_defaults(func=cmd_create)

    # solve
    parser_solve = subparsers.add_parser(
        "solve", help="Solve a challenge string"
    )
    parser_solve.add_argument(
        "challenge", type=str, help="Challenge string"
    )
    parser_solve.set_defaults(func=cmd_solve)

    # verify
    parser_verify = subparsers.add_parser(
        "verify", help="Verify a solution against a challenge"
    )
    parser_verify.add_argument(
        "challenge", type=str, help="Challenge string"
    )
    parser_verify.add_argument(
        "solution", type=str, help="Solution string"
    )
    parser_verify.set_defaults(func=cmd_verify)

    # info
    parser_info = subparsers.add_parser(
        "info", help="Show info about a challenge string"
    )
    parser_info.add_argument(
        "challenge", type=str, help="Challenge string"
    )
    parser_info.set_defaults(func=cmd_info)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
