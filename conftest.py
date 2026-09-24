# Skip doctest collection of optional-dependency modules when the dependency
# isn't installed; their tests skip themselves with pytest.importorskip.
import importlib.util

collect_ignore = [
    path
    for module, path in [("pandas", "src/colgov/pandas.py"), ("pyspark", "src/colgov/spark.py")]
    if importlib.util.find_spec(module) is None
]
