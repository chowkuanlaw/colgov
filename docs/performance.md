# Performance

Measured with `python benchmarks/bench.py --spark`, using 200,000 email
addresses, one tokenized column, Python 3.11 and 4 CPUs. Numbers depend on
the machine, so re-run the script on your own hardware before planning
capacity.

| Path | Values per second |
|---|---:|
| `Tokenizer.tokenize` in a loop | 340,000 |
| `Tokenizer.tokenize_many` | 410,000 |
| `Tokenizer.detokenize` in a loop | 250,000 |
| `colgov.pandas.apply` | 330,000 |
| `colgov apply` (CLI, streaming, including start-up) | 146,000 |
| `colgov.spark.apply`, row UDF, `local[2]` | 75,000 |
| `colgov.spark.apply`, Arrow UDF, `local[2]` | 372,000 |

## Tips

- **Install `pyarrow` alongside PySpark.** `colgov.spark` then uses a
  vectorized Arrow UDF, which is about 5× faster than the row UDF on the
  same cluster.
- **Tokenize whole columns rather than single values.** `tokenize_many`,
  `tokenize_column` and the pandas and Spark helpers set up the cipher once
  per column.
- **Large files can go through the CLI.** `colgov apply` streams the file,
  so memory stays flat whatever its size.
- **The cost is AES-SIV itself.** Each value costs one AES-SIV encryption
  (two AES passes) plus base64. Throughput scales with cores in Spark, so
  add executors rather than tuning colgov.
