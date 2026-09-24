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
    colgov retokenize data.csv --columns a,b -o out.csv
                                           re-issue tokens under the primary key
    colgov audit verify audit.jsonl        check an audit log's hash chain

CSV files are read as text. An empty cell is a null. ``--table`` names the
table whose catalog decisions apply (default: decisions made without one).

Keys come from the ``COLGOV_MASTER_KEY`` environment variable or a file
given with ``--key-file``. Either holds a keyring: one key spec per line (or
comma-separated), primary first, older keys after it. A key spec is a
base64 key, or ``aws-kms:<blob>`` for a key protected by AWS KMS (see
``colgov keygen --aws-kms-key-id``).
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import csv
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from typing import TextIO

import colgov
from colgov.audit import AuditLogError, JsonlAuditLog, verify_audit_log
from colgov.keys import KeySpecError, generate_aws_kms_key, load_keyring
from colgov.policy import Policy, PolicyError, Treatment, record_view, summarize
from colgov.review import Catalog, CatalogError
from colgov.risk import ColumnRisk, LowCardinalityError
from colgov.rules import PUBLIC, RulePack, RulePackError
from colgov.tokenization import InvalidToken, Tokenizer

KEY_ENV = "COLGOV_MASTER_KEY"

_ERRORS = (
    AuditLogError,
    CatalogError,
    InvalidToken,
    KeySpecError,
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
        status: int = args.func(args)
        return status
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
    if args.aws_kms_key_id:
        _, spec = generate_aws_kms_key(args.aws_kms_key_id)
        print(spec)
    else:
        print(base64.b64encode(Tokenizer.generate_key()).decode("ascii"))
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    header, data = _read_csv(args.data, limit=args.sample_size)
    suggestions = _pack(args.pack).classify(data, sample_size=args.sample_size)
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
    header, data = _read_csv(args.data, limit=args.sample_size)
    catalog = Catalog.load(args.catalog) if os.path.exists(args.catalog) else Catalog()
    pending = catalog.pending(header, table=args.table)
    if not pending:
        print("Every column has a decision. Nothing to review.", file=out)
        return 0
    suggestions = pack.classify({c: data[c] for c in pending}, sample_size=args.sample_size)
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
                catalog.decide(column, PUBLIC, by=args.by, table=args.table)
            elif answer.isdigit() and 1 <= int(answer) <= len(found):
                catalog.accept(found[int(answer) - 1], by=args.by, table=args.table)
            elif answer.startswith("l ") and answer[2:].strip() in pack.labels:
                catalog.decide(column, answer[2:].strip(), by=args.by, table=args.table)
            else:
                print(f"  ? labels in this pack: {', '.join(labels)}", file=out)
                continue
            catalog.save(args.catalog)  # after every decision, so nothing is lost
            decided += 1
            break

    remaining = len(catalog.pending(header, table=args.table))
    print(f"\nSaved {decided} decision(s) to {args.catalog}. {remaining} column(s) still pending.", file=out)
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    header = _read_header(args.data)
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    width = max(len(c) for c in header)
    for r in policy.plan(args.role, header, catalog, table=args.table):
        detok = "  (may detokenize)" if policy.may_detokenize(args.role, r.column, catalog, table=args.table)[0] else ""
        print(f"{r.column:<{width}}  {r.treatment.value:<8}  {r.reason}{detok}")
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Stream the role's view: one pass to check, one pass to write.

    Memory stays bounded whatever the file size: the first pass counts
    rows and distinct values (stopping at --min-distinct per column), and
    the second tokenizes row by row.
    """
    if args.audit and not args.actor:
        raise CliError("--audit needs --actor")
    header = _read_header(args.data)
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    plan = policy.plan(args.role, header, catalog, table=args.table)
    tokenized = [r for r in plan if r.treatment is Treatment.TOKENIZE]
    tokenizer = _tokenizer(args) if tokenized else None
    audit = JsonlAuditLog(args.audit) if args.audit else None
    try:
        n_rows = _check_rows_and_cardinality(args.data, header, [r.column for r in tokenized], args.min_distinct)
    except (CliError, LowCardinalityError) as exc:
        if audit is not None:
            record_view(audit, args.actor, args.role, plan, "error", str(exc), 0)
        raise
    if audit is not None:  # recorded before any output is written
        record_view(audit, args.actor, args.role, plan, "allowed", summarize(plan), n_rows)

    visible = [(header.index(r.column), r) for r in plan if r.treatment is not Treatment.DENY]
    with _output(args.output) as out:
        writer = csv.writer(out)
        writer.writerow(r.column for _, r in visible)
        for _, row in _iter_rows(args.data, header):
            out_row = []
            for i, r in visible:
                value = row[i]
                if r.treatment is Treatment.TOKENIZE and value is not None:
                    value = tokenizer.tokenize(value, column=r.domain or r.column)  # type: ignore[union-attr]
                out_row.append("" if value is None else value)
            writer.writerow(out_row)
    denied = [r.column for r in plan if r.treatment is Treatment.DENY]
    if denied:
        print(f"colgov: left out {len(denied)} column(s): {', '.join(denied)}", file=sys.stderr)
    return 0


def cmd_detokenize(args: argparse.Namespace) -> int:
    policy, catalog = Policy.load(args.policy), Catalog.load(args.catalog)
    if args.tokens == "-":
        tokens = [line.strip() or None for line in sys.stdin]
    else:
        with open(args.tokens, encoding="utf-8") as f:
            tokens = [line.strip() or None for line in f]
    plaintext = policy.detokenize(
        tokens,
        column=args.column,
        table=args.table,
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


def cmd_retokenize(args: argparse.Namespace) -> int:
    header = _read_header(args.data)
    columns = [c.strip() for c in args.columns.split(",") if c.strip()]
    missing = [c for c in columns if c not in header]
    if not columns or missing:
        detail = f"; not found: {', '.join(missing)}" if missing else ""
        raise CliError(f"--columns must name columns of {args.data}{detail}")
    catalog = Catalog.load(args.catalog) if args.catalog else None
    tokenizer = _tokenizer(args)
    targets = []
    for column in columns:
        decision = catalog.get(column, table=args.table) if catalog else None
        targets.append((header.index(column), decision.token_domain if decision else column))
    changed = 0
    with _output(args.output) as out:
        writer = csv.writer(out)
        writer.writerow(header)
        for _, row in _iter_rows(args.data, header):
            for i, domain in targets:
                new = tokenizer.retokenize(row[i], column=domain)
                changed += new != row[i]
                row[i] = new
            writer.writerow("" if v is None else v for v in row)
    print(f"colgov: re-issued {changed} token(s) under key {tokenizer.keyring.primary_id}", file=sys.stderr)
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    count = verify_audit_log(args.log)
    print(f"OK: {count} event(s), hash chain intact")
    return 0


# --- helpers --------------------------------------------------------------------


def _pack(spec: str) -> RulePack:
    return RulePack.load(spec) if os.path.exists(spec) else RulePack.builtin(spec)


def _read_header(path: str) -> list[str]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        header = next(csv.reader(f), None)
    if not header:
        raise CliError(f"{path}: no header row")
    if len(set(header)) != len(header) or not all(header):
        raise CliError(f"{path}: column names must be unique and non-empty")
    return header


def _iter_rows(path: str, header: list[str]) -> Iterator[tuple[int, list[str | None]]]:
    """Yield (line number, values) for each data row; empty cells are None."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        next(reader, None)
        for lineno, row in enumerate(reader, start=2):
            if len(row) != len(header):
                raise CliError(f"{path}, line {lineno}: expected {len(header)} fields, got {len(row)}")
            yield lineno, [v if v != "" else None for v in row]


def _read_csv(path: str, *, limit: int | None = None) -> tuple[list[str], dict[str, list[str | None]]]:
    """Read a CSV file (or its first ``limit`` rows) into columns."""
    header = _read_header(path)
    data: dict[str, list[str | None]] = {c: [] for c in header}
    for n, (_, row) in enumerate(_iter_rows(path, header)):
        if limit is not None and n >= limit:
            break
        for column, value in zip(header, row, strict=True):
            data[column].append(value)
    return header, data


def _check_rows_and_cardinality(path: str, header: list[str], columns: list[str], min_distinct: int) -> int:
    """First pass of apply: validate every row, count rows, refuse low-cardinality columns.

    Distinct values are tracked only until a column reaches ``min_distinct``,
    so memory stays bounded. A column that never does has been tracked in
    full, so its reported profile is exact.
    """
    positions = [(c, header.index(c)) for c in columns]
    counts: dict[str, Counter[str]] = {c: Counter() for c in columns}
    nulls = dict.fromkeys(columns, 0)
    open_columns = set(columns)
    n_rows = 0
    for _, row in _iter_rows(path, header):
        n_rows += 1
        for column, i in positions:
            value = row[i]
            if value is None:
                nulls[column] += 1
            elif column in open_columns:
                counts[column][value] += 1
                if len(counts[column]) >= min_distinct:
                    open_columns.discard(column)
    for column in columns:
        if column in open_columns and counts[column]:
            freq = counts[column]
            risk = ColumnRisk(
                n_rows=n_rows,
                n_null=nulls[column],
                n_distinct=len(freq),
                min_frequency=min(freq.values()),
                top_share=max(freq.values()) / (n_rows - nulls[column]),
            )
            raise LowCardinalityError(column, risk, min_distinct)
    return n_rows


@contextlib.contextmanager
def _output(path: str) -> Iterator[TextIO]:
    """Write to stdout, or to ``path`` atomically: a temp file renamed on success."""
    if path == "-":
        yield sys.stdout
        return
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".colgov-", suffix=".csv.tmp")
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            yield f
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _tokenizer(args: argparse.Namespace) -> Tokenizer:
    if args.key_file:
        with open(args.key_file, encoding="utf-8") as f:
            text, source = f.read(), args.key_file
    else:
        text, source = os.environ.get(KEY_ENV, ""), KEY_ENV
        if not text.strip():
            raise CliError(f"no master key: set {KEY_ENV} or pass --key-file (create one with 'colgov keygen')")
    try:
        return Tokenizer(load_keyring(text))
    except KeySpecError as exc:
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
        p.add_argument("--key-file", help=f"keyring file: key specs, primary first (default: ${KEY_ENV})")

    def table_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument("--table", help="table whose catalog decisions apply (default: decisions made without a table)")

    p = add("keygen", cmd_keygen, "print a new master key spec (base64, or aws-kms:... with --aws-kms-key-id)")
    p.add_argument("--aws-kms-key-id", help="protect the new key with this AWS KMS key (id, ARN or alias/...)")

    p = add("classify", cmd_classify, "suggest labels for each column of a CSV file")
    p.add_argument("data", help="CSV file with a header row")
    pack_args(p)

    p = add("review", cmd_review, "decide each unreviewed column's label, interactively")
    p.add_argument("data", help="CSV file with a header row")
    p.add_argument("-c", "--catalog", required=True, help="catalog YAML file (created if missing)")
    p.add_argument("--by", required=True, help="your name, recorded with each decision")
    table_arg(p)
    pack_args(p)

    p = add("plan", cmd_plan, "show how each column would be treated for a role, and why")
    p.add_argument("data", help="CSV file (only the header row is read)")
    policy_args(p)
    table_arg(p)

    p = add("apply", cmd_apply, "write the view of a CSV file that a role may see")
    p.add_argument("data", help="CSV file with a header row")
    policy_args(p)
    table_arg(p)
    key_args(p)
    p.add_argument("-o", "--output", default="-", help="output CSV file (default: stdout)")
    p.add_argument(
        "--min-distinct",
        type=int,
        default=colgov.DEFAULT_MIN_DISTINCT,
        help="refuse to tokenize columns with fewer distinct values (default: %(default)s)",
    )
    p.add_argument("--audit", help="append a record of this view to a JSONL audit log")
    p.add_argument("--actor", help="who is running this (required with --audit)")

    p = add("detokenize", cmd_detokenize, "turn tokens back into plaintext, if the role has a detokenize grant")
    policy_args(p)
    table_arg(p)
    key_args(p)
    p.add_argument("--column", required=True, help="column the tokens came from")
    p.add_argument("--actor", required=True, help="who is asking")
    p.add_argument("--purpose", required=True, help="why, e.g. a ticket number")
    p.add_argument("--audit", required=True, help="JSONL audit log to append to")
    p.add_argument("tokens", nargs="?", default="-", help="file with one token per line (default: stdin)")

    p = add("retokenize", cmd_retokenize, "re-issue tokens in a CSV file under the primary key (after rotating keys)")
    p.add_argument("data", help="CSV file with a header row")
    p.add_argument("--columns", required=True, help="comma-separated tokenized columns to migrate")
    p.add_argument("-c", "--catalog", help="catalog YAML, to use each column's token domain (default: column name)")
    table_arg(p)
    key_args(p)
    p.add_argument("-o", "--output", default="-", help="output CSV file (default: stdout)")

    audit = sub.add_parser("audit", help="audit log tools", description="audit log tools")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True, metavar="COMMAND")
    p = audit_sub.add_parser("verify", help="check an audit log's hash chain")
    p.add_argument("log", help="JSONL audit log")
    p.set_defaults(func=cmd_audit_verify)

    return parser


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
