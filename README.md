# API keys service

API key creation, listing and revocation, purpose restrictions, secret hashing
and renter-key fingerprint propagation. Version 0.1.0. Runtime lives in
src/api_keys_service; application factory: api_keys_service.app.create_app.

## Development

Use Python 3.13 and uv 0.11.26 with read access to the eight pinned private
hyperme-sh dependency repositories listed in the hosted workflow.

    uv sync --frozen
    bash scripts/check-package.sh

The suite runs from source, a fresh normally installed wheel outside this checkout,
and a rebuilt sdist wheel. Both wheel payloads must match the runtime source.
Tests use deterministic dependency doubles; no provider or deployment is exercised.

Original tests and Dockerfile remain under core/api-keys-service as integration
references. The gateway source-boundary test requires the owning monorepo and is
retained there; it is not part of the standalone suite. The historical Dockerfile
is not a standalone build. Container and consumer integration need separate validation.

The hosted workflow runs only on main with read-only contents, pinned actions,
and exact repository Git credential headers. DEPENDENCY_READ_TOKEN must have
contents:read for the eight dependencies only. Actions remains disabled until
scoped access and hosted-worker policy are provisioned. No publishing or deployment.
