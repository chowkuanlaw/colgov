# colgov

**Deterministic, reversible tokenization and fail-closed access policy for tabular PII.**

Tokenize a column and it stays joinable. Same plaintext, same token — every
time, across tables and across runs — so `JOIN`, `GROUP BY` and
`COUNT(DISTINCT)` keep working on data nobody can read.

> **Status: alpha (`0.1.0`).** Every v0.1 feature is in place. The API may
> still change before 1.0. See [CHANGELOG.md](CHANGELOG.md).

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
  master key with HKDF-SHA256, using the column name as context. The same
  value in two different columns gives unrelated tokens, so you can't join
  tables on a column the policy didn't mean to link.
- **Tokens are URL- and SQL-safe.** They use unpadded base64url (`A–Z a–z 0–9 - _`).
- **Tampering is detected.** `detokenize` raises `colgov.InvalidToken` when a
  token was changed or was made with a different key or column.
- **Lose the master key and the tokens can't be reversed.** Anyone who has
  the key can reverse every token.

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
all rejected when the pack loads. The built-in `core` pack covers email,
phone numbers, names, national IDs, dates of birth, postal codes, street
addresses, IP addresses and payment cards.

## Planned for v0.1

- [x] Deterministic reversible tokenization with per-column key derivation (HKDF)
- [x] Column classification from portable YAML rule packs
- [x] Human review workflow — a machine suggests, a person decides
- [x] Fail-closed policy resolution: an unclassified column is never visible
- [x] Re-identification risk scoring (cardinality, k-anonymity)

## Scope

`colgov` governs **columns in tabular data**. It does not detect PII inside
free-text prose — for that, use
[Presidio](https://github.com/data-privacy-stack/presidio), which is excellent
at it. An optional bridge is planned so Presidio can act as a value-shape
detector feeding `colgov`'s classification.

## License

Apache-2.0
