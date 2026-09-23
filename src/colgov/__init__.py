"""colgov — deterministic, reversible tokenization and fail-closed access
policy for tabular PII.

See https://github.com/chowkuanlaw/colgov
"""

from colgov.tokenization import MIN_MASTER_KEY_BYTES, InvalidToken, Tokenizer

__version__ = "0.1.0.dev0"
__all__ = ["__version__", "InvalidToken", "MIN_MASTER_KEY_BYTES", "Tokenizer"]
