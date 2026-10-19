# syntax=docker/dockerfile:1.7
# One image for api and worker: Python backend + built web app. Runs as non-root with a read-only
# root file system (see docker-compose.yml). Base images are pinned by version and digest.
ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG NODE_IMAGE=node:24.21.0-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

# --- web app -----------------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS web
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.34.7 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY frontend/package.json frontend/
RUN pnpm install --frozen-lockfile --filter sentinelops-web
COPY frontend/ frontend/
RUN pnpm --dir frontend run build

# --- python environment ------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir uv==0.13.1
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/
COPY generator/pyproject.toml generator/
RUN uv sync --frozen --no-dev --all-packages --no-install-workspace
COPY backend/ backend/
COPY generator/ generator/
RUN uv sync --frozen --no-dev --all-packages

# --- runtime -----------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="SentinelOps" \
      org.opencontainers.image.description="Explainable, AI-assisted security operations: from log lines to an investigable case" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin sentinelops \
    && mkdir -p /data /drop \
    && chown 10001:10001 /data /drop
WORKDIR /app
COPY --from=build /app /app
COPY rules/ rules/
COPY --from=web /src/frontend/dist /app/frontend/dist
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINELOPS_STATIC_DIR=/app/frontend/dist \
    SENTINELOPS_RULES_DIR=/app/rules
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)"]
ENTRYPOINT ["sentinelops"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
