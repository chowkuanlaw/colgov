"""colgov — deterministic, reversible tokenization and fail-closed access
policy for tabular PII.

See https://github.com/chowkuanlaw/colgov
"""

from colgov.risk import (
    DEFAULT_MIN_DISTINCT,
    ColumnRisk,
    KAnonymity,
    LowCardinalityError,
    column_risk,
    k_anonymity,
)
from colgov.tokenization import MIN_MASTER_KEY_BYTES, InvalidToken, Tokenizer

__version__ = "0.1.0.dev0"
__all__ = [
    "__version__",
    "DEFAULT_MIN_DISTINCT",
    "MIN_MASTER_KEY_BYTES",
    "ColumnRisk",
    "InvalidToken",
    "KAnonymity",
    "LowCardinalityError",
    "Tokenizer",
    "column_risk",
    "k_anonymity",
]
