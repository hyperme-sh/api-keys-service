FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY core/lib/controlplane-db ./core/lib/controlplane-db
COPY scripts/alembic_head.py /tmp/alembic_head.py
ARG ALEMBIC_HEAD
# Bake the Alembic head from the migrations copied above. See scripts/alembic_head.py.
RUN python3 /tmp/alembic_head.py \
      --versions /app/core/lib/controlplane-db/src/controlplane_db/alembic/versions \
      --write /alembic-head \
      --expect "${ALEMBIC_HEAD}"
LABEL com.fyberlabs.alembic-head="${ALEMBIC_HEAD}"
COPY core/events ./core/events
COPY core/models ./core/models
COPY core/lib/controlplane-core ./core/lib/controlplane-core
COPY core/auth-service ./core/auth-service
COPY core/tests ./core/tests
COPY core/api-keys-service ./core/api-keys-service
RUN uv sync --frozen --no-dev --package api-keys-service
ENV PYTHONPATH=/app/core/lib/controlplane-core/src:/app/core/lib/controlplane-db/src:/app/core/events/src:/app/core/models/src:/app/core/auth-service/src:/app/core/api-keys-service/src
WORKDIR /app/core/api-keys-service
CMD ["uv", "run", "--project", "/app/core/api-keys-service", "python", "-m", "api_keys_service.main"]
