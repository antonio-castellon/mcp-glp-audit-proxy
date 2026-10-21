# Stdio image for mcp-glp-audit-proxy.
# Build from the repository root:
#   docker build -f docs/manual-guides/docker/Dockerfile -t mcp-glp-audit-proxy:local .
# No port is published. A host attaches stdin. Glama can point at this file
# and wrap stdio. The baked principal is for discovery only.

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 proxy
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY docs/manual-guides/docker/discovery.config.json /app/discovery.config.json

RUN pip install --no-cache-dir . \
    && chown -R proxy:proxy /app

USER proxy

ENV GLP_CONFIG=/app/discovery.config.json \
    GLP_PRINCIPAL_ID=discovery \
    GLP_PRINCIPAL_NAME=Discovery \
    GLP_PRINCIPAL_ROLE=qa

ENTRYPOINT ["mcp-glp-audit-proxy"]
CMD ["--config", "/app/discovery.config.json"]
