FROM python:3.12-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Spark tests need Java. Build tools allow Python dependencies without wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# The scanner supplies the colgov checkout as the Docker build context.
COPY . /src
WORKDIR /src

# Fetch all optional integrations and test dependencies while networking is
# available. The scanner's analysis phase runs without Internet access.
RUN python -m pip install --no-cache-dir \
      -e ".[test,pandas,polars,parquet,spark,aws,presidio]" "moto[kms]"

RUN python -m pytest -q
