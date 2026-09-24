"""The ``colgov`` command-line tool.

    colgov keygen                          print a new master key (base64)
    colgov classify data.csv               suggest labels for each column
    colgov review data.csv -c catalog.yaml --by NAME
                                           decide labels interactively
    colgov plan data.csv -p policy.yaml -c catalog.yaml --role R
                                           show what a role would see, and why
    colgov apply data.csv -p policy.yaml -c catalog.yaml --role R -o out.csv
                                           write the role's view of the data
    colgov detokenize -p ... -c ... --role R --column C --actor NAME
                      --purpose WHY --audit audit.jsonl < tokens.txt
                                           reverse tokens, if the role may
    colgov audit verify audit.jsonl        check an audit log's hash chain

CSV files are read as text. An empty cell is a null. The master key is read
from the ``COLGOV_MASTER_KEY`` environment variable (base64), or from a file
given with ``--key-file``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import os
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

import colgov
from colgov.audit import AuditLogError, JsonlAuditLog, verify_audit_log
from colgov.policy import Policy, PolicyError
from colgov.review import Catalog, CatalogError
from colgov.risk import LowCardinalityError
from colgov.rules import PUBLIC, RulePack, RulePackError
from colgov.tokenization import InvalidToken, Tokenizer

KEY_ENV = "COLGOV_MASTER_KEY"

_ERRORS = (
    AuditLogError,
    CatalogError,
    InvalidToken,
    LowCardinalityError,
    OSError,
    PolicyError,
    RulePackError,
    UnicodeDecodeError,
)


class CliError(Exception):
    """A user-facing error: printed without a traceback, exit status 1."""


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"colgov: error: {exc}", file=sys.stderr)
    except _ERRORS as exc:
        print(f"colgov: error: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130
    return 1


# --- commands -------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    print(base64.b64encode(Tokenizer.generate_key()).decode("ascii"))
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    header, table = _read_csv(args.data)
    suggestions = _pack(args.pack).classify(table, sample_size=args.sample_size)
    for column in header:
        found = suggestions[column]
        if not found:
            print(f"{column}: (no suggestion)")
            continue
        for i, s in enumerate(found):
            prefix = f"{column}:" if i == 0 else " " * (len(column) + 1)
            print(f"{prefix} {s.label} ({s.confidence:.2f}) [{', '.join(s.rule_ids)}]")
    return 0


def cmd_review(
    args: argparse.Namespace,
    ask: Callable[[str], str] = input,
    out: TextIO | None = None,
) -> int:
    out = out or sys.stdout
    if not args.by.strip():
        raise CliError("--by must name the reviewer")
    pack = _pack(args.pack)
    header, table = _read_csv(args.data)
    catalog = Catalog.load(args.catalog) if os.path.exists(args.catalog) else Catalog()
    pending = catalog.pending(header)
    if not pending:
        print("Every column has a decision. Nothing to review.", file=out)
        return 0
    suggestions = pack.classify({c: table[c] for c in pending}, sample_size=args.sample_size)
    labels = sorted(pack.labels)

    decided = 0
    for n, column in enumerate(pending, start=1):
        found = suggestions[column]
        print(f"\n[{n}/{len(pending)}] {column}", file=out)
        if found:
            for i, s in enumerate(found, start=1):
                print(f"  {i}) {s.label} ({s.confidence:.2f})", file=out)
                for line in s.evidence:
                    print(f"       {line}", file=out)
        else:
            print("  no suggestions", file=out)
        choices = f"1-{len(found)} accept · " if found else ""
        prompt = f"  {choices}p public · l LABEL · s skip · q quit > "
        while True:
            try:
                answer = ask(prompt).strip()
            except EOFError:
                answer = "q"
            if answer == "q":
                print(f"\nSaved {decided} decision(s) to {args.catalog}.", file=out)
                return 0
            if answer == "s":
                break
            if answer == "p":
                catalog.decide(column, PUBLIC, by=args.by)
            elif answer.isdigit() and 1 <= int(answer) <= len(found):
                catalog.accept(found[int(answer) - 1], by=args.by)
            elif answer.startswith("l ") and answer[2:].strip() in pack.labels:
                catalog.decide(column, answer[2:].strip(), by=args.by)
            else:
                print(f"  ? labels in this pack: {', '.join(labels)}", file=out)
                continue
            catalog.save(args.catalog)  # after every decision, so nothing is lost
            decided += 1
            break

    remaining = len(catalog.pending(header))
    print(f"\nSaved {decided} decision(s) to {args.catalog}. {remaining} column(s) still pending.", file=out)
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    header, _ = _read_csv(args.data, header_only=True)
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    width = max(len(c) for c in header)
    for r in policy.plan(args.role, header, catalog):
        print(f"{r.column:<{width}}  {r.treatment.value:<8}  {r.reason}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    if args.audit and not args.actor:
        raise CliError("--audit needs --actor")
    header, table = _read_csv(args.data)
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    needs_key = any(r.treatment.value == "tokenize" for r in policy.plan(args.role, header, catalog))
    view = policy.apply(
        table,
        role=args.role,
        catalog=catalog,
        tokenizer=_tokenizer(args) if needs_key else None,
        min_distinct=args.min_distinct,
        audit=JsonlAuditLog(args.audit) if args.audit else None,
        actor=args.actor,
    )
    _write_csv(args.output, view)
    denied = [c for c in header if c not in view]
    if denied:
        print(f"colgov: left out {len(denied)} column(s): {', '.join(denied)}", file=sys.stderr)
    return 0


def cmd_detokenize(args: argparse.Namespace) -> int:
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    source = sys.stdin if args.tokens == "-" else open(args.tokens, encoding="utf-8")
    with source:
        tokens = [line.strip() or None for line in source]
    plaintext = policy.detokenize(
        tokens,
        column=args.column,
        role=args.role,
        catalog=catalog,
        tokenizer=_tokenizer(args),
        actor=args.actor,
        purpose=args.purpose,
        audit=JsonlAuditLog(args.audit),
    )
    for value in plaintext:
        print("" if value is None else value)
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    count = verify_audit_log(args.log)
    print(f"OK: {count} event(s), hash chain intact")
    return 0


# --- helpers --------------------------------------------------------------------


def _pack(spec: str) -> RulePack:
    return RulePack.load(spec) if os.path.exists(spec) else RulePack.builtin(spec)


def _read_csv(path: str, *, header_only: bool = False) -> tuple[list[str], dict[str, list[str | None]]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            raise CliError(f"{path}: no header row")
        if len(set(header)) != len(header) or not all(header):
            raise CliError(f"{path}: column names must be unique and non-empty")
        table: dict[str, list[str | None]] = {c: [] for c in header}
        if header_only:
            return header, table
        for lineno, row in enumerate(reader, start=2):
            if len(row) != len(header):
                raise CliError(f"{path}, line {lineno}: expected {len(header)} fields, got {len(row)}")
            for column, value in zip(header, row):
                table[column].append(value if value != "" else None)
    return header, table


def _write_csv(path: str, view: dict[str, list]) -> None:
    out = sys.stdout if path == "-" else open(path, "w", newline="", encoding="utf-8")
    try:
        writer = csv.writer(out)
        writer.writerow(view.keys())
        for row in zip(*view.values()):
            writer.writerow("" if v is None else v for v in row)
    finally:
        if out is not sys.stdout:
            out.close()


def _tokenizer(args: argparse.Namespace) -> Tokenizer:
    if args.key_file:
        with open(args.key_file, encoding="ascii") as f:
            encoded, source = f.read(), args.key_file
    else:
        encoded, source = os.environ.get(KEY_ENV, ""), KEY_ENV
        if not encoded:
            raise CliError(f"no master key: set {KEY_ENV} or pass --key-file (create one with 'colgov keygen')")
    try:
        key = base64.b64decode(encoded.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise CliError(f"{source}: master key is not valid base64") from None
    try:
        return Tokenizer(key)
    except ValueError as exc:
        raise CliError(f"{source}: {exc}") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="colgov",
        description="Classify, review and govern PII columns in tabular data.",
    )
    parser.add_argument("--version", action="version", version=f"colgov {colgov.__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def add(name: str, func: Callable[[argparse.Namespace], int], help: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help, description=help)
        p.set_defaults(func=func)
        return p

    def pack_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--pack", default="core", help="built-in pack name or path to a YAML pack (default: core)")
        p.add_argument("--sample-size", type=int, default=1000, help="values sampled per column (default: 1000)")

    def policy_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("-p", "--policy", required=True, help="policy YAML file")
        p.add_argument("-c", "--catalog", required=True, help="catalog YAML file")
        p.add_argument("--role", required=True, help="role to resolve for")

    def key_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--key-file", help=f"file holding the base64 master key (default: ${KEY_ENV})")

    add("keygen", cmd_keygen, "print a new random master key, base64-encoded")

    p = add("classify", cmd_classify, "suggest labels for each column of a CSV file")
    p.add_argument("data", help="CSV file with a header row")
    pack_args(p)

    p = add("review", cmd_review, "decide each unreviewed column's label, interactively")
    p.add_argument("data", help="CSV file with a header row")
    p.add_argument("-c", "--catalog", required=True, help="catalog YAML file (created if missing)")
    p.add_argument("--by", required=True, help="your name, recorded with each decision")
    pack_args(p)

    p = add("plan", cmd_plan, "show how each column would be treated for a role, and why")
    p.add_argument("data", help="CSV file (only the header row is read)")
    policy_args(p)

    p = add("apply", cmd_apply, "write the view of a CSV file that a role may see")
    p.add_argument("data", help="CSV file with a header row")
    policy_args(p)
    key_args(p)
    p.add_argument("-o", "--output", default="-", help="output CSV file (default: stdout)")
    p.add_argument("--min-distinct", type=int, default=colgov.DEFAULT_MIN_DISTINCT,
                   help="refuse to tokenize columns with fewer distinct values (default: %(default)s)")
    p.add_argument("--audit", help="append a record of this view to a JSONL audit log")
    p.add_argument("--actor", help="who is running this (required with --audit)")

    p = add("detokenize", cmd_detokenize, "turn tokens back into plaintext, if the role may see the column in clear")
    policy_args(p)
    key_args(p)
    p.add_argument("--column", required=True, help="column the tokens came from")
    p.add_argument("--actor", required=True, help="who is asking")
    p.add_argument("--purpose", required=True, help="why, e.g. a ticket number")
    p.add_argument("--audit", required=True, help="JSONL audit log to append to")
    p.add_argument("tokens", nargs="?", default="-", help="file with one token per line (default: stdin)")

    audit = sub.add_parser("audit", help="audit log tools", description="audit log tools")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True, metavar="COMMAND")
    p = audit_sub.add_parser("verify", help="check an audit log's hash chain")
    p.add_argument("log", help="JSONL audit log")
    p.set_defaults(func=cmd_audit_verify)

    return parser


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
