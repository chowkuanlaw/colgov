"""Throughput benchmarks for colgov.

    python benchmarks/bench.py            # core, pandas, CLI
    python benchmarks/bench.py --spark    # also PySpark (row and Arrow UDFs)

Numbers depend on the machine; compare runs on the same one.
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import subprocess
import sys
import tempfile
import time

from colgov import Catalog, Policy, Tokenizer

N = 200_000
KEY = bytes(range(32))


def rate(label: str, n: int, seconds: float) -> None:
    print(f"{label:<44} {n / seconds:>12,.0f} values/s   ({seconds:.2f}s for {n:,})")


def bench_core(values: list[str]) -> None:
    tok = Tokenizer(KEY)
    start = time.perf_counter()
    for v in values:
        tok.tokenize(v, column="email")
    rate("Tokenizer.tokenize (loop)", len(values), time.perf_counter() - start)

    start = time.perf_counter()
    tok.tokenize_many(values, column="email")
    rate("Tokenizer.tokenize_many", len(values), time.perf_counter() - start)

    tokens = tok.tokenize_many(values, column="email")
    start = time.perf_counter()
    for t in tokens:
        tok.detokenize(t, column="email")
    rate("Tokenizer.detokenize (loop)", len(values), time.perf_counter() - start)


def bench_pandas(values: list[str]) -> None:
    import pandas as pd

    from colgov import pandas as cpd

    df = pd.DataFrame({"email": values, "amount": range(len(values))})
    catalog = Catalog()
    catalog.decide("email", "email", by="bench")
    catalog.decide("amount", "public", by="bench")
    policy = Policy({"analyst": {"email": "tokenize"}})
    start = time.perf_counter()
    cpd.apply(df, policy, role="analyst", catalog=catalog, tokenizer=Tokenizer(KEY))
    rate("colgov.pandas.apply (1 tokenized column)", len(values), time.perf_counter() - start)


def bench_cli(values: list[str]) -> None:
    with tempfile.TemporaryDirectory() as d:
        data = os.path.join(d, "data.csv")
        with open(data, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["email", "amount"])
            w.writerows((v, i) for i, v in enumerate(values))
        catalog = Catalog()
        catalog.decide("email", "email", by="bench")
        catalog.decide("amount", "public", by="bench")
        catalog.save(os.path.join(d, "catalog.yaml"))
        with open(os.path.join(d, "policy.yaml"), "w") as f:
            f.write("roles:\n  analyst:\n    email: tokenize\n")
        env = dict(os.environ, COLGOV_MASTER_KEY="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
        cmd = [
            sys.executable,
            "-m",
            "colgov.cli",
            "apply",
            data,
            "-p",
            os.path.join(d, "policy.yaml"),
            "-c",
            os.path.join(d, "catalog.yaml"),
            "--role",
            "analyst",
            "-o",
            os.path.join(d, "out.csv"),
        ]
        start = time.perf_counter()
        subprocess.run(cmd, check=True, env=env)  # noqa: S603
        rate("colgov apply (CLI, streaming, incl. startup)", len(values), time.perf_counter() - start)


def bench_spark(values: list[str]) -> None:
    from pyspark.sql import SparkSession

    from colgov import spark as cspark

    os.environ["PYSPARK_PYTHON"] = sys.executable
    spark = (
        SparkSession.builder.master("local[2]")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "2")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    sdf = spark.createDataFrame([(v,) for v in values], "email string").repartition(4).cache()
    sdf.count()
    catalog = Catalog()
    catalog.decide("email", "email", by="bench")
    policy = Policy({"analyst": {"email": "tokenize"}})
    for arrow in (False, True):
        cspark._arrow_available = lambda a=arrow: a  # type: ignore[assignment]
        out = cspark.apply(sdf, policy, role="analyst", catalog=catalog, tokenizer=Tokenizer(KEY))
        start = time.perf_counter()
        out.write.format("noop").mode("overwrite").save()
        rate(
            f"colgov.spark.apply ({'Arrow' if arrow else 'row'} UDF, local[2])",
            len(values),
            time.perf_counter() - start,
        )
    spark.stop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=N)
    parser.add_argument("--spark", action="store_true")
    args = parser.parse_args()
    values = [f"user{i}@example.com" for i in range(args.n)]
    print(f"Python {platform.python_version()} on {platform.machine()}, {os.cpu_count()} CPUs\n")
    bench_core(values)
    try:
        bench_pandas(values)
    except ImportError:
        print("(pandas not installed; skipped)")
    bench_cli(values)
    if args.spark:
        bench_spark(values)


if __name__ == "__main__":
    main()
