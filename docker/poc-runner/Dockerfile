FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl jq ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir httpx requests

WORKDIR /workspace
USER nobody

CMD ["python", "/workspace/poc.py"]
