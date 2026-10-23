<p align="center">
  <img src="https://raw.githubusercontent.com/chowkuanlaw/colgov/main/docs/assets/logo-256.png" width="128" height="128" alt="colgov logo: a table whose middle column is locked">
</p>

# colgov

**Deterministic, reversible tokenization and fail-closed access policy for tabular PII.**

Tokenize a column and it stays joinable. Same plaintext, same token — every
time, across tables and across runs — so `JOIN`, `GROUP BY` and
`COUNT(DISTINCT)` keep working on data nobody can read.

> **Status: stable (`1.1.0`).** The public API and file formats follow
> Semantic Versioning: see the [stability policy](https://github.com/chowkuanlaw/colgov/blob/main/docs/stability.md).
> The cryptographic design has not yet had an independent review. Read the
> [threat model](https://github.com/chowkuanlaw/colgov/blob/main/docs/threat-model.md) before relying on it. See [CHANGELOG.md](https://github.com/chowkuanlaw/colgov/blob/main/CHANGELOG.md).

## The problem

Encrypting a column normally destroys its analytical value. Standard
authenticated encryption uses a random IV, so the same email address becomes
different ciphertext every time it is encrypted — correct for protecting text,
useless for a warehouse:

```python
encrypt("ada@example.com")   # 'Yk2p...'
encrypt("ada@example.com")   # 'Qm9x...'  ← different every call
```

Join two tables on that column and you get zero rows back.

## The approach

`colgov` uses AES-SIV (RFC 5297), a deterministic authenticated encryption
mode. The same input always produces the same token, and the original value is
recoverable with the key:

```python
t.tokenize("ada@example.com", column="email")   # 'dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ'
t.tokenize("ada@example.com", column="email")   # 'dEmr4UrbAT3YC8v2o0S4Uuf_L06ueUs51KdWaw0Y8YQ'  ← stable
```

Determinism is a deliberate trade, not a free win: it preserves the frequency
distribution of a column, so low-cardinality fields stay re-identifiable even
once tokenized. `colgov` treats that as a first-class concern and refuses, by
default, to tokenize columns whose cardinality is too low to protect.

## Usage

```bash
pip install colgov
```

```python
from colgov import Tokenizer

key = Tokenizer.generate_key()        # 32 random bytes — store it in a KMS / secret manager
t = Tokenizer(key)

token = t.tokenize("ada@example.com", column="email")
t.detokenize(token, column="email")   # 'ada@example.com'

t.tokenize(None, column="email")      # None — NULL stays NULL
```

- **One key per column.** Each column's AES-256-SIV key is derived from the
  master key with HKDF-SHA256, using the column name (its *token domain*) as
  context. The same value in two different domains gives unrelated tokens,
  so you can't join tables on a column the policy didn't mean to link.
- **Tokens name their key.** Each token starts with a key ID, so master keys
  can be rotated (see below).
- **Tokens are URL- and SQL-safe.** They use unpadded base64url (`A–Z a–z 0–9 - _`).
- **Tampering is detected.** `detokenize` raises `colgov.InvalidToken` when a
  token was changed or was made with a different key or column.
- **Lose the master key and the tokens can't be reversed.** Anyone who has
  the key can reverse every token.

### Rotating keys, and keeping them in AWS KMS

```python
from colgov import Keyring, Tokenizer

t = Tokenizer(Keyring(new_key, previous=[old_key]))
t.tokenize("ada@example.com", column="email")        # made with new_key
t.detokenize(old_token, column="email")              # old_key tokens still read
t.retokenize(old_token, column="email")              # re-issued under new_key
t.is_current(token)                                  # header check, no decryption
```

- **Tokens depend on the key.** After rotating, the same value gets a new
  token, so migrate stored tokens with `retokenize` (or
  `colgov retokenize`) before joining old data with new.
- **Keys can live in AWS KMS.** `colgov keygen --aws-kms-key-id alias/colgov`
  prints an `aws-kms:...` spec. That is a data key encrypted by KMS, and it's
  safe to keep in configuration. It is decrypted with `kms:Decrypt` only
  when loaded. Install with `pip install "colgov[aws]"`.
- **Keyring specs:** `load_keyring(text)`, `$COLGOV_MASTER_KEY` and
  `--key-file` all take key specs, one per line or comma-separated, with the
  primary key first.
- **Tokens from colgov 0.1–0.2 still read.** They have no key ID, so each
  key in the keyring is tried. `retokenize` upgrades them.

### Refusing columns too predictable to protect

`tokenize_column` profiles a column before it tokenizes anything. If the
column has fewer than 10 distinct non-null values, it raises
`LowCardinalityError` and tokenizes nothing:

```python
t.tokenize_column(["M", "F", "F", None], column="gender")
# LowCardinalityError: column 'gender' has 2 distinct values (minimum 10) ...

t.tokenize_column(values, column="gender", min_distinct=3)             # adjust the threshold
t.tokenize_column(values, column="gender", allow_low_cardinality=True) # opt out explicitly
```

### Measuring re-identification risk

```python
from colgov import column_risk, k_anonymity

column_risk(["a", "a", "a", "b", None])
# ColumnRisk(n_rows=5, n_null=1, n_distinct=2, min_frequency=1, top_share=0.75)

result = k_anonymity(rows, quasi_identifiers=["birth_year", "postcode", "gender"])
result.k               # size of the smallest group of rows sharing all three values
result.rows_below(5)   # how many rows sit in groups smaller than 5
```

`k == 1` means at least one person is unique on those columns and can be
singled out, even when every column is tokenized.

### Classify, review, then govern

The full workflow has three steps: a rule pack **suggests** labels, a person
**decides**, and a policy **resolves** what each role sees.

```python
from colgov import PUBLIC, Catalog, Policy, RulePack, Tokenizer

table = {
    "customer_email": [...],
    "mobile_no": [...],
    "order_total": [...],
    "comments": [...],
}

# 1. Suggest: rule packs match column names and sampled values.
suggestions = RulePack.builtin("core").classify(table)
suggestions["customer_email"][0]
# Suggestion(column='customer_email', label='email', confidence=0.95,
#            rule_ids=('email-name', 'email-value'), ...)

# 2. Decide: only a named person turns a suggestion into a decision.
catalog = Catalog()
catalog.accept(suggestions["customer_email"][0], by="alice")
catalog.accept(suggestions["mobile_no"][0], by="alice")
catalog.decide("order_total", PUBLIC, by="alice", note="no personal data")
catalog.pending(table)     # ['comments']  — not reviewed yet
catalog.save("catalog.yaml")  # commit it; review decisions like code

# 3. Resolve: a fail-closed policy per role.
policy = Policy.from_yaml("""
roles:
  analyst:
    email: tokenize
    phone_number: deny
""")
view = policy.apply(table, role="analyst", catalog=catalog, tokenizer=Tokenizer(key))
list(view)                 # ['customer_email', 'order_total']
```

Policies fail closed at every step:

- **An unknown role sees nothing.**
- **A column nobody has reviewed is denied,** whatever the machine suggested.
- **A label the role isn't granted is denied.** That includes misspelt labels.
- **Tokenized columns still go through the cardinality check,** so a
  predictable column raises `LowCardinalityError` instead of leaking.

Treatments are `clear`, `tokenize` and `deny`. Columns reviewed as `public`
are `clear` unless a role overrides it. Use `policy.plan(role, columns,
catalog)` to see each column's treatment and the reason for it.

### Writing a rule pack

```yaml
pack: my-org
version: 1
labels:
  employee_id:
    description: Internal staff number
rules:
  - id: employee-id-name
    label: employee_id
    column_name: 'emp(loyee)?_?(id|no)'   # regex, case-insensitive, searched in the name
    confidence: 0.8
  - id: employee-id-value
    label: employee_id
    value_pattern: 'E[0-9]{6}'           # regex, must match the whole value
    min_match_ratio: 0.9                 # share of sampled non-null values (default 0.8)
    confidence: 0.9
```

Load it with `RulePack.load("my-org.yaml")`. Packs are validated strictly:
unknown keys, undeclared labels, invalid regexes and duplicate rule ids are
all rejected when the pack loads.

A value rule can also name a `validator`, a check built into colgov that
each value must pass as well as the pattern: `luhn` (payment cards),
`my_nric`, `sg_nric` or `id_nik`. A pattern alone can't tell a real ID
number from any other string of digits the same length.

### Built-in rule packs

- **`core`:** email, phone numbers, names, national IDs, dates of birth,
  postal codes, street addresses, IP addresses, and payment cards (with a
  Luhn check).
- **`sea`:** Malaysia, Singapore and Indonesia. It recognises ID numbers
  from their values, not only their column names:

  | Value | Checked |
  |---|---|
  | Malaysian MyKad (`900101-14-5678`) | a real date of birth and place-of-birth code |
  | Singapore NRIC/FIN (`S1234567D`) | the check letter (S, T, F and G series) |
  | Indonesian NIK (16 digits) | province code and date of birth |
  | Malaysian, Singapore and Indonesian phone numbers | local formats |

  It also knows Malay and Indonesian column names, such as `no_kp`, `nama`,
  `alamat`, `tarikh_lahir`, `poskod`, `nik` and `no_hp`.

`sea` uses the same label names as `core`, so one policy covers both. Use
them together:

```python
pack = RulePack.combine(RulePack.builtin("core"), RulePack.builtin("sea"))
```

On the command line, pass `--pack core,sea`.

### Optional Presidio suggestions

Install `colgov[presidio]` and configure Presidio's language model, then pass
`--presidio` to `colgov classify` or `colgov review`. Presidio's detections
are merged with rule-pack suggestions. A detection must span the entire
sampled value; PII embedded in prose is outside this bridge's scope. The
reviewer still makes every catalog decision.

```bash
pip install "colgov[presidio]"
colgov classify customers.csv --pack core,sea --presidio
colgov review customers.csv -c catalog.yaml --by alice --presidio
```

Python callers can pass a configured `AnalyzerEngine` (including custom
recognizers) to `PresidioBridge(analyzer)`, then call `classify(table)` and
pass a returned suggestion to `Catalog.accept`. By default, the bridge maps
Presidio's `EMAIL_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `CREDIT_CARD` and
`IP_ADDRESS` entities to colgov labels. `entity_labels=` changes that map.
Neither suggestions nor their evidence contain sampled values.

### Detokenization, with an audit trail

Detokenizing is its own permission. It is granted per label with the long
form of a grant, and seeing a column in `clear` does **not** imply it:

```yaml
roles:
  support:
    email: clear                                  # sees plaintext; can't detokenize
  fraud:
    email: {view: tokenize, detokenize: true}     # works on tokens; may reverse them
```

The same fail-closed checks apply as for views: the role must be known, the
column reviewed, and the label granted. Every attempt is recorded before any
plaintext is returned, whether it was allowed, denied or failed. Each
record names who asked, why, and how many values were involved.

```python
from colgov import AccessDenied, JsonlAuditLog

audit = JsonlAuditLog("audit.jsonl")
policy.detokenize(
    tokens, column="customer_email", role="fraud", catalog=catalog,
    tokenizer=t, actor="carol", purpose="TICKET-4521", audit=audit,
)                          # ['ada@example.com', ...]

policy.detokenize(tokens, column="customer_email", role="analyst", ...)
# AccessDenied: role 'analyst' may not detokenize 'customer_email' ...
```

- **Actor and purpose are required.** If the audit log can't be written,
  no plaintext is returned.
- **Audit records never contain data,** neither plaintext nor tokens.
- **The log is tamper-evident.** `JsonlAuditLog` chains every line to the
  one before it with SHA-256. `verify_audit_log("audit.jsonl")` (or
  `colgov audit verify`) finds any line that was edited, deleted or
  reordered. Save the final hash and event count outside the log, then pass
  them to `colgov audit verify --expected-hash HASH --expected-count N` to
  detect a truncated or entirely rewritten log.
- **Views can be audited too.** Pass `audit=` and `actor=` to
  `policy.apply`.
- **CLI views record authorization and completion separately.** `allowed`
  means the view passed policy checks; `completed` means its output write
  finished. A write failure gets an `error` event. Spark views are lazy, so
  their `allowed` event only records authorization.

### Several tables in one catalog

Decisions are keyed by table and column, so `customers.id` and `orders.id`
are reviewed separately. A decision never covers a table it wasn't made for:
there is no fallback from a table to table-less decisions.

```python
catalog.decide("email", "email", by="alice", table="customers")
catalog.decide("buyer_email", "email", by="alice", table="orders", domain="email")

policy.apply(customers, role="analyst", catalog=catalog, table="customers", tokenizer=t)
policy.apply(orders, role="analyst", catalog=catalog, table="orders", tokenizer=t)
# customers.email and orders.buyer_email share the "email" token domain, so they join.
```

A column's token domain defaults to its name, so same-named columns join
across tables. Set `domain=` to join differently named columns, or to keep
same-named columns apart. The CLI takes `--table` for the same purpose.

### pandas, Polars and PySpark

```bash
pip install "colgov[pandas]"   # or "colgov[polars]", "colgov[spark]"
```

```python
from colgov import pandas as cpd

suggestions = cpd.classify(df)
view = cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=t)
plain = cpd.detokenize(view["customer_email"], policy, role="support", catalog=catalog,
                       tokenizer=t, actor="carol", purpose="TICKET-4521", audit=audit)

from colgov import polars as cpl

view = cpl.apply(df, policy, role="analyst", catalog=catalog, tokenizer=t)  # same API, Polars DataFrames

from colgov import spark as cspark

view = cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=t)  # lazy DataFrame
```

- **pandas:** the index and the dtypes of `clear` columns are kept. `None`,
  `NaN` and `pd.NA` all count as null.
- **Polars:** `clear` columns keep their dtype, and tokenized columns
  become `String`. `Categorical` columns can be tokenized. Pass an eager
  `DataFrame`, so call `.collect()` on a `LazyFrame` first.
- **Spark:** tokenization runs in a UDF on the executors, and the
  cardinality check is a single aggregation. The master key is shipped to
  the executors, so colgov must be installed there, and you should only use
  a cluster you trust with the key.
- **All three:** tokenized columns must hold strings, so cast other types first.

### Command line

```bash
colgov keygen                                   # new master key (base64)
colgov keygen --aws-kms-key-id alias/colgov     # ...or one protected by AWS KMS
export COLGOV_MASTER_KEY=...                    # or --key-file (primary first, older keys after)

colgov classify customers.csv                   # suggestions per column
colgov review customers.csv -c catalog.yaml --by alice
                                                # decide interactively; saved after every answer
colgov plan customers.csv -p policy.yaml -c catalog.yaml --role analyst
                                                # what the role would see, and why
colgov apply customers.csv -p policy.yaml -c catalog.yaml --role analyst -o analyst.csv \
             --audit audit.jsonl --actor bob
colgov detokenize -p policy.yaml -c catalog.yaml --role support --column customer_email \
                  --actor carol --purpose TICKET-4521 --audit audit.jsonl < tokens.txt
colgov retokenize analyst.csv --columns customer_email -o migrated.csv
                                                # after rotating keys
colgov report customers.csv -c catalog.yaml -p policy.yaml --format json
                                                # review coverage, access and cardinality
colgov audit verify audit.jsonl
```

Add `--table customers` to `review`, `plan`, `apply` and `detokenize` to use
that table's catalog decisions.

`review` shows suggestions and the evidence for them, but never the
column's values.

`classify` and `review` inspect the first 1000 rows by default. For a
reproducible sample across the whole file, pass `--sample-strategy reservoir`
and optionally `--sample-size` and `--sample-seed`. This scans the full file
while keeping at most the requested number of non-null values per column in
memory. Suggestions still require a person's review; sampling cannot prove
that a column contains no PII.

`detokenize` processes at most 1000 tokens per audited batch; use
`--batch-size` to change that limit. Each batch has its own audit event. If a
later batch contains a bad token, earlier batches may already have been
printed, so treat stdout as a stream.

**Parquet.** Every command that reads or writes data also takes Parquet.
The format comes from the file name (`.parquet` or `.pq`), so `apply
customers.parquet -o analyst.parquet` stays Parquet. Parquet is read and
written in batches, so memory stays bounded, and `clear` columns keep their
types. Install it with `pip install "colgov[parquet]"`. In CSV files, empty
cells are nulls.

### Checking for unreviewed columns in CI

`colgov check` fails when a schema has a column nobody has reviewed. Run it
on every pull request, so a new column can't reach production until a
person has decided what it holds:

```bash
colgov check customers.parquet -c catalog.yaml --table customers
colgov check target/catalog.json -c catalog.yaml -p policy.yaml   # every dbt model
```

- **Schemas:** CSV or Parquet files (only the column names are read), or a
  dbt `manifest.json` or `catalog.json`. In a dbt file, each model is a
  table named after the model, and a source is `<source>.<table>`.
  `manifest.json` only lists documented columns, while `catalog.json` (from
  `dbt docs generate`) lists every column in the warehouse.
- **Errors (exit status 1):** columns with no decision.
- **Warnings:** decisions for columns that no longer exist, and, with
  `--policy`, labels that no role is granted. Pass `--strict` to fail on
  warnings too.
- **GitHub Actions:** `--format github` shows each finding as an annotation
  on the pull request.

```yaml
# .github/workflows/pii.yml
- run: pip install "colgov[parquet]"
- run: colgov check target/catalog.json -c governance/catalog.yaml --format github
```

### Reporting on governance coverage

`colgov report customers.csv -c catalog.yaml -p policy.yaml` summarizes
reviewed and pending columns, stale decisions, and each role's view and
detokenization grants. `--format json` produces machine-readable output.
For reviewed, non-public string columns, it scans the full CSV or Parquet
file and reports whether the column falls below `--min-distinct` (default:
10). Distinct values are tracked only up to that threshold to bound memory;
the report gives an exact count below the threshold and a lower bound above
it. It never includes data values or tokens.

### Generating a SQL view

`colgov sql-view` emits a `CREATE VIEW` statement from a policy and
catalog. The source table must already contain a separate token column for
every logical column treated as `tokenize`; provide each pairing with
`--token-column`. The generator refuses a tokenized treatment without one.
Denied and unreviewed columns are omitted.

```bash
colgov sql-view customers.parquet -p policy.yaml -c catalog.yaml \
  --role analyst --table customers \
  --source warehouse.customers --view analytics.analyst_customers \
  --token-column customer_email=customer_email_token \
  --dialect postgres > analyst_view.sql
```

The input file supplies the source table's column names, including token
columns. Generate those columns with colgov using each catalog decision's
token domain, and keep them in sync with the raw data. The view selects a
token column under its logical name; it does not encrypt inside SQL. Check
cardinality before producing tokens. Restrict direct access to the source
table and grant access to the generated view with your warehouse's permission
system. The command generates SQL but does not run it or grant permissions.

### Reviewing policy changes

`policy-explain` shows the reviewed label, reviewer, token domain, view
treatment and separate detokenization decision for one role and column.
`policy-diff` compares effective access across two policy and catalog
revisions. It reports access expansions, restrictions and configuration
changes such as a token-domain change. Pass `--fail-on-expansion` in CI.

```bash
colgov policy-explain -p policy.yaml -c catalog.yaml --role analyst \
  --table customers --column customer_email
colgov policy-diff --old-policy old-policy.yaml --old-catalog old-catalog.yaml \
  --new-policy policy.yaml --new-catalog catalog.yaml --fail-on-expansion
```

### Enforcing risk thresholds

`risk-check` scans selected string columns exactly and exits 1 when a
threshold fails. Its temporary SQLite database contains keyed digests and
counts, never source values. `--min-distinct` defaults to 10. Use
`--max-top-share` and `--min-frequency` for further limits. `apply` accepts
the latter two flags too and checks tokenized columns before writing output.

```bash
colgov risk-check customers.csv --columns customer_email \
  --min-distinct 10 --max-top-share 0.2 --min-frequency 2
```

### Generating dbt views

`dbt-views` combines `manifest.json` with the complete `catalog.json` from
`dbt docs generate`. It refuses missing physical columns or unreviewed
logical columns. A token map names pretokenized companion columns for each
dbt model. Output is SQL only; restrict direct source-table access yourself.

```yaml
# token-map.yaml
tables:
  customers:
    customer_email: customer_email_token
```

```bash
colgov dbt-views --manifest target/manifest.json --dbt-catalog target/catalog.json \
  -p policy.yaml -c catalog.yaml --role analyst --view-schema governed \
  --token-map token-map.yaml --dialect bigquery > governed_views.sql
```

### Audit checkpoints, rotation preview and rule tests

Save a verified audit count and final hash outside the log, then compare it
later. S3 checkpoint writes use a create-only request. For immutable S3
checkpoints, configure an Object Lock bucket and pass `--retention-days`.

```bash
colgov audit checkpoint audit.jsonl s3://my-audit-bucket/checkpoints/run-001.json \
  --retention-days 90
colgov audit verify audit.jsonl --checkpoint s3://my-audit-bucket/checkpoints/run-001.json
colgov rotation-preview analyst.csv --columns customer_email -c catalog.yaml \
  --table customers --format json
```

`rotation-preview` authenticates each token and counts current and older
tokens without writing a migrated file or printing plaintext. A keyring
with the new primary key and all relevant older keys is required.

`rules test` checks example cases for a built-in or YAML rule pack. The
output contains label names but never sample values. Add
`--strict-overlap` to fail cases that suggest several labels.

```yaml
# rule-cases.yaml
cases:
  - name: email-example
    column: contact_email
    values: [person@example.com]
    expected: [email]
```

```bash
colgov rules test rule-cases.yaml --pack core --strict-overlap
```

## Roadmap

**v0.1**

- [x] Deterministic reversible tokenization with per-column key derivation (HKDF)
- [x] Column classification from portable YAML rule packs
- [x] Human review workflow — a machine suggests, a person decides
- [x] Fail-closed policy resolution: an unclassified column is never visible
- [x] Re-identification risk scoring (cardinality, k-anonymity)

**v0.2**

- [x] Policy-governed detokenization with a tamper-evident audit log
- [x] pandas and PySpark helpers
- [x] `colgov` command-line tool

**v0.3**

- [x] Key rotation: key IDs in tokens, keyrings, `retokenize`, AWS KMS
- [x] Catalogs keyed by table, with configurable token domains
- [x] Detokenizing as a separate, explicitly granted permission

**Road to 1.0**

- [x] `ruff`, `mypy --strict`, docs site, API stability policy
- [x] `SECURITY.md` and threat model
- [x] Audit log shared by several processes; `logging` and multi-log sinks
- [x] Streaming CLI, Arrow-based Spark UDF, benchmarks
- [x] Property-based and fuzz tests, coverage gate
- [x] 1.0.0 release candidate (`1.0.0rc1`)
- [x] 1.0.0

**v1.1**

- [x] `colgov check`: fail CI on unreviewed columns (CSV, Parquet, dbt)
- [x] `sea` rule pack: MyKad, NRIC/FIN and NIK checked beyond their shape
- [x] Parquet in the CLI, and Polars helpers

**After 1.1**

- [x] Optional Presidio bridge for whole-value suggestions
- [x] `colgov report`: catalog coverage, role access and bounded cardinality summary
- [x] ANSI SQL view generation over pretokenized companion columns

## Scope

`colgov` governs **columns in tabular data**. It does not detect PII inside
free-text prose — for that, use
[Presidio](https://github.com/data-privacy-stack/presidio), which can also
provide whole-value suggestions through the optional bridge above.

## Security

Read the [threat model](https://github.com/chowkuanlaw/colgov/blob/main/docs/threat-model.md) before using colgov with real
personal data. Report vulnerabilities privately as described in
[SECURITY.md](https://github.com/chowkuanlaw/colgov/blob/main/SECURITY.md). The [API stability policy](https://github.com/chowkuanlaw/colgov/blob/main/docs/stability.md)
explains what stays compatible from 1.0.

## License

Apache-2.0
