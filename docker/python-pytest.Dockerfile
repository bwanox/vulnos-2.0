FROM python:3.11-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --disable-pip-version-check \
    "flask==3.0.0" \
    "pytest>=8.0,<9.0"

WORKDIR /workspace
