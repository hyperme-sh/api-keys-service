# API keys service

`api-keys-service` 0.1.0 creates, lists, renames, and revokes tenant-scoped API keys for the Hypermesh control plane. A key is a `prefix.secret` string. The service stores a bcrypt hash of the secret and a SHA-256 fingerprint of the full key, and it is the process the control-plane edge and the Hypermesh gateway call when a request presents an API key. The runtime package is `src/api_keys_service`. Build an app with `api_keys_service.app.create_app`.

## Why

Renters call Hypermesh with a key instead of a person's access token. The secret is shown once, at creation, and every later check compares the presented secret with the bcrypt hash. Each key belongs to one tenant and carries a purpose (`renter`, `service`, or `ir`). Org admins, the billing group, and the renter group mint renter and service keys. Org admins and the `ir` group mint `ir` keys. Revocation and account closure hand Hypermesh and the gateway the key's fingerprint so they can stop accepting it. The plaintext secret and the bcrypt hash stay in this service.

## How it works

The process is a FastAPI application. `python -m api_keys_service.main` serves it with uvicorn (`HOST` defaults to `0.0.0.0`, `PORT` defaults to `8000`) and exposes Prometheus on `METRICS_PORT` (default `9100`). PostgreSQL is reached through `DATABASE_URL` and the `controlplane-db` models. Each request sets the tenant row-level-security context from `X-Tenant-ID` and commits the session when the handler returns.

User routes require `Authorization: Bearer` plus `X-Tenant-ID`. The header must equal the tenant claim on the access token (`tenant_id`, or `https://spanopticon.dev/tenant_id`). Membership for that tenant and subject is loaded from the database and combined with the token's roles and groups. A smoke session, marked by the `hypermesh_smoke` claim, may mint a renter key with an empty scope list, and may list, rename, and revoke only keys that session created.

A deployment may set `API_KEYS_ORACLES_TENANT_ID` to its s3r.ch tenant. For that tenant, the Auth owner's network-session exchange lets the network administrator create a service key with exactly the `oracles:attest` scope and manage keys of that kind owned by the same subject. The exchange verifies current network authority for the selected tenant. Leaving the variable unset disables this path.

On create, the service draws an 8-byte hex prefix and a URL-safe secret, stores `bcrypt(secret)` and `sha256(prefix.secret)`, and returns both the secret portion and the full `prefix.secret` string. Later responses include the prefix, name, scopes, purpose, and timestamps. They omit the secret. List and rename also attach the tenant's mapped lease when Hypermesh reports one: the lease a key for that tenant reaches when the caller does not override the model. Revoked keys omit the lease.

`POST /api/v1/internal/validate` and `POST /api/v1/internal/touch` authenticate with `X-Internal-Token` (`API_KEYS_INTERNAL_TOKEN`). The token must be set to a private value. An empty value and the published development default are rejected. Validate splits the presented key on the first `.`, checks the prefix, the tenant, the bcrypt hash, and that the key is still active. When the key records a creating subject, validate also requires that account to be open. Touch writes `last_used_at`. The gateway is expected to call touch about once a minute per key.

Account closure, when `ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED=true`, serializes minting with retirement of that subject. The closure routes live under `/api/v1/api-keys/internal/` and require `X-Account-Lifecycle-Token`.

| Method | Path | Who calls it |
| --- | --- | --- |
| `POST` | `/api/v1/api-keys` | Bearer user. Body: `name`, `scopes`, `purpose` (`renter` by default). `201` returns the secret once. |
| `GET` | `/api/v1/api-keys` | Bearer user. Lists keys for the tenant. |
| `PATCH` | `/api/v1/api-keys/{key_id}` | Bearer user. Body: `name`. |
| `DELETE` | `/api/v1/api-keys/{key_id}` | Bearer user. Revokes the key. `204`. |
| `POST` | `/api/v1/internal/validate` | Edge and gateway. Body: `api_key`, `tenant_id`. |
| `POST` | `/api/v1/internal/touch` | Gateway. Body: `key_id`. |
| `POST` | `/api/v1/api-keys/internal/account-status` | Closure guard. Body: `key_id`. |
| `POST` | `/api/v1/api-keys/internal/close-owner` | Closure operations. Revokes that subject's keys in the tenant and returns ids, fingerprints, and purposes. |
| `POST` | `/api/v1/api-keys/internal/owner-inventory` | Closure operations. Lists that subject's keys across tenants. |
| `POST` | `/api/v1/api-keys/internal/purge-owner` | Closure operations. Deletes that subject's keys in the tenant after erasure is authorized. |
| `GET` | `/api/v1/health/` | Load balancer. `{"status":"Ok"}`. |
| `GET` | `/version` | Build identity from `GIT_SHA`, `BUILT_AT`, and `SERVICE_NAME`. |

`purpose` accepts `renter`, `ir`, and `service`. The aliases `service_account`, `service-account`, and `named service account` are stored as `service`.

## Practical use

Install Python 3.13 and [uv](https://docs.astral.sh/uv/) 0.11.26. Direct dependencies, pinned in `pyproject.toml` and `uv.lock`, are `controlplane-api` 0.23.0, `auth-service` 0.2.0, `controlplane-core` 0.1.0, `controlplane-db` 0.1.0, `controlplane-events` 0.1.0, `controlplane-identity` 0.15.0, and `bcrypt` 5.0.0. The lock also pulls `controlplane-tenancy` 0.14.0 and `operator-ban-store` 0.1.0 (from `user-service`). `uv sync --frozen` needs read access to those `hyperme-sh` repositories.

Start PostgreSQL 16 and apply the `controlplane-db` migrations. The URL below matches the `controlplane-api` development default; use a different password on any shared machine.

```sh
docker run --detach --name api-keys-pg \
  --publish 127.0.0.1:5432:5432 \
  --env POSTGRES_USER=controlplane \
  --env POSTGRES_PASSWORD=controlplane123 \
  --env POSTGRES_DB=controlplane \
  postgres:16-alpine
until docker exec api-keys-pg pg_isready -U controlplane; do sleep 1; done

uv sync --frozen
export DATABASE_URL=postgresql+asyncpg://controlplane:controlplane123@127.0.0.1:5432/controlplane
uv run python -m controlplane_db.migrations upgrade

export API_KEYS_INTERNAL_TOKEN="$(openssl rand -hex 32)"
export HYPERMESH_CONTROL_PLANE_URL=http://127.0.0.1:8010
export HYPERMESH_INTERNAL_TOKEN="$(openssl rand -hex 32)"
export KEYCLOAK_ISSUER='http://localhost:8081/realms/controlplane'
export KEYCLOAK_JWKS_URL='http://localhost:8081/realms/controlplane/protocol/openid-connect/certs'
export SERVICE_NAME=api-keys-service
uv run python -m api_keys_service.main
```

`API_KEYS_SERVICE_CORS_ORIGINS` is a comma-separated origin list. When it is unset, the process allows the local Next.js and Vite origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`, `http://127.0.0.1:5173`). The `controlplane` realm must already exist in the local Keycloak instance. Set the issuer to the exact `iss` value of its tokens and the JWKS URL to an address this service can reach. Access tokens are checked against Keycloak. The development issuer is `http://localhost:8081/realms/controlplane` (`KEYCLOAK_ISSUER`, `KEYCLOAK_JWKS_URL`).

Mint a renter key. `secret_plaintext` is the secret portion. `api_key` is the full `prefix.secret` value to store and to send later. Both appear on this response only.

```sh
curl -sS -X POST http://127.0.0.1:8000/api/v1/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H 'Content-Type: application/json' \
  -d '{"name":"lab renter","purpose":"renter","scopes":[]}'
```

```json
{
  "id": "6f0c1b2e-3a4d-4e5f-8a9b-0c1d2e3f4a5b",
  "tenant_id": "11111111-2222-4333-8444-555555555555",
  "key_prefix": "0123456789abcdef",
  "name": "lab renter",
  "scopes": [],
  "created_at": "2026-11-05T22:00:00.000000+00:00",
  "revoked_at": null,
  "purpose": "renter",
  "last_used_at": null,
  "mapped_lease": null,
  "secret_plaintext": "the-urlsafe-secret",
  "api_key": "0123456789abcdef.the-urlsafe-secret"
}
```

List, rename, and revoke:

```sh
curl -sS http://127.0.0.1:8000/api/v1/api-keys \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID"

curl -sS -X PATCH http://127.0.0.1:8000/api/v1/api-keys/$KEY_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H 'Content-Type: application/json' \
  -d '{"name":"lab renter (rotated label)"}'

curl -sS -X DELETE http://127.0.0.1:8000/api/v1/api-keys/$KEY_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID"
```

The edge and the gateway validate a presented key with the internal token. `valid: false` is an ordinary `200`. A wrong internal token is `401`.

```sh
curl -sS -X POST http://127.0.0.1:8000/api/v1/internal/validate \
  -H "X-Internal-Token: $API_KEYS_INTERNAL_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$API_KEY\",\"tenant_id\":\"$TENANT_ID\"}"
```

```json
{
  "valid": true,
  "key_id": "6f0c1b2e-3a4d-4e5f-8a9b-0c1d2e3f4a5b",
  "tenant_id": "11111111-2222-4333-8444-555555555555",
  "scopes": [],
  "purpose": "renter"
}
```

Mint still returns the key when `HYPERMESH_CONTROL_PLANE_URL` or `HYPERMESH_INTERNAL_TOKEN` is unset, or when Hypermesh refuses the fingerprint POST. Revoke of a key that has a fingerprint returns `502` with `Could not unpublish the API key` until every required fingerprint owner returns a 2xx acknowledgement. Redirects and errors leave the local key unrevoked. Point both variables at the Hypermesh control plane before revoking.

The tree under `core/api-keys-service` is the earlier monorepo layout. Its Dockerfile copies sibling checkouts that this repository does not contain. Run the root package as shown above.

## How Hypermesh uses it

Hypermesh renters mint keys through the control-plane portal. The caller is an org admin, a member of `billing`, or a member of `renter`. An `ir` key uses the same routes with `"purpose":"ir"` and requires an org admin or the `ir` group. The `billing_manager` role counts as `billing`, and the `ir_door` role counts as `ir`. The control-plane edge forwards the browser's access token and `X-Tenant-ID` to this service. Rename and revoke load the key within that matched tenant before checking its purpose. IR members can manage their own IR keys, bound to the immutable creating subject; the existing admin authority can manage other keys in that tenant. Renter and service keys retain their renter/billing/admin guard. Smoke sessions remain restricted to their own renter keys.

When a renter later calls Hypermesh with that key, the Hypermesh gateway and the control-plane edge both use `controlplane_identity.api_keys_client.validate_api_key_remote`. That client POSTs `/api/v1/internal/validate` with `X-Internal-Token` set to the shared `API_KEYS_INTERNAL_TOKEN`. A truthy `valid` means the secret matched, the key is not revoked, and the tenant on the request is the key's tenant. The gateway then POSTs `/api/v1/internal/touch` so `last_used_at` moves. A completion presents a paid ticket at the gateway. Key administration and this validation call are the traffic that reaches this service.

After a mint, when `HYPERMESH_CONTROL_PLANE_URL` and `HYPERMESH_INTERNAL_TOKEN` are both set, this service POSTs the fingerprint to Hypermesh:

```http
POST {HYPERMESH_CONTROL_PLANE_URL}/api/v1/hypermesh/internal/renter-key-fingerprints
X-Internal-Token: {HYPERMESH_INTERNAL_TOKEN}
X-Tenant-ID: {tenant}
{"fingerprint":"<sha256 hex of prefix.secret>"}
```

Revoke POSTs the same fingerprint to `.../renter-key-fingerprints/revoke`. An `ir` key is also removed with `.../ir-key-fingerprints/revoke`. List and rename call `GET .../api/v1/hypermesh/internal/mapped-lease` and copy `lease_id` and `catalog_id` onto keys that are still active.

Closing an account is a separate exchange. With closure enforcement on, the operations caller sends `X-Account-Lifecycle-Token: $ACCOUNT_CLOSURE_OPERATIONS_TOKEN` and `X-Tenant-ID` to `POST /api/v1/api-keys/internal/close-owner` (`subject`, `closed_at`). The handler revokes that subject's keys in the tenant and returns each key's id, fingerprint, and purpose. Hypermesh and the gateway use those fingerprints to drop the key. The body contains neither the secret nor the bcrypt hash. `owner-inventory` lists the same subject's keys across tenants. `purge-owner` deletes the tenant's rows after `ACCOUNT_CLOSURE_GUARD_URL` reports that erasure is allowed and the closed inventory matches. `account-status` answers the guard token (`ACCOUNT_CLOSURE_GUARD_TOKEN`) with whether a single key is blocked.

## Develop and test

From a clean checkout, with read access to the pinned repositories:

```sh
uv sync --frozen
bash scripts/check-package.sh
```

The script runs `tests/` and `integration/` from the checkout, from a freshly installed wheel, and from a wheel rebuilt from the sdist. The wheel must match the runtime source, the `Apache-2.0` SPDX metadata, and the `LICENSE` text. Integration tests need Docker: each session starts PostgreSQL 16 on a loopback port, applies the pinned `controlplane-db` migrations, and removes the container and its volumes on exit. Those tests cover subject-bound membership (a changed email keeps a bound subject's grants; an unbound, missing, or inactive subject, and a group from another tenant, do not) and account closure (mint and close stay serialized, mutation uses a separate credential, and a purge removes only that subject in that tenant).

`bash scripts/check-package.sh --fixtures` runs the same three consumers from the wheels in `tests_artifacts/dependencies`, with no Git credentials. Pull requests use that lane. Pushes to `main` run `scripts/check-package.sh` with repository-scoped read tokens. See [Releasing](docs/releasing.md) for what those workflows keep.

## Release and versioning

The package version is **0.1.0**. The recorded release line in `release-policy.json` is **0.1**. A stable GitHub release is a `vMAJOR.MINOR.PATCH` tag published from the exact artifact `main` already tested. Channel rules, artifact retention, and the accepted-baseline variable are in [Releasing](docs/releasing.md). Compatibility checks are in [Release compatibility](docs/release-policy.md).

## License

First-party code is [Apache-2.0](LICENSE). Dependencies keep their own licenses. The wheel check compares the SPDX expression and the packaged `LICENSE` bytes with this repository.

## Isolated runtime qualification

PR and main CI run the normal container entrypoint against a disposable PostgreSQL
schema under a non-superuser, non-RLS-bypassing role. The checked-in lifecycle
(`scripts/qualify_runtime.py` and `scripts/runtime/`) owns random container names,
publishes no host ports and shares only a network-none container's loopback.
A synthetic fingerprint owner runs inside that namespace. HTTP checks cover mint,
SDK validation, tenant isolation, membership SQL row visibility, key-use callbacks,
IR ownership and failed/successful fingerprint acknowledgements. Generated keys,
JWTs and passwords stay in memory; containers and anonymous volumes are removed.
SIGTERM unwinds through cleanup. CI also records only the generated owner name in
a private file and runs an always-step recovery scoped to that owner label.
This is isolated qualification, not shared TEST deployment or live key acceptance.

To reproduce using credential-free dependency fixtures:

```sh
context=$(mktemp -d)
RELEASE_ARTIFACT_DIR="$context" bash scripts/check-package.sh --fixtures
python3 scripts/prepare_runtime_context.py "$context"
docker build -f Dockerfile --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" -t api-keys-local:qualification "$context"
python3 scripts/qualify_runtime.py --image api-keys-local:qualification
docker image rm api-keys-local:qualification
rm -rf "$context"
```

Use a clean checkout so the reported revision identifies the qualified source.
Running TEST services follow the moving test channel; image digests in receipts
identify tested bytes and do not pin service deployments.

The pinned schema applies RLS to directory membership tables. `api_keys` itself
has no RLS policy: its public operations and remote validation use explicit tenant
predicates, while authorized account inventory discovers an exact subject across
tenants. The probe reports this distinction instead of installing a fixture-only
policy or claiming every table has RLS. The internal touch callback authenticates
the service token and addresses an opaque key ID; its tenant header carries caller
context but is not an additional owner authorization check.

### Organization-scoped key owner

`API_KEYS_SCOPED_AUTHORITY_REQUIRED=1` enables the canonical scoped-key contract.
The deployment lifecycle first runs the explicit User-owned API-key schema
migration and grants its nonprivileged runtime only key-table operations and the
private closure inventory function. Application startup never migrates or grants.
Current User authority is checked over verified HTTPS for every management or
validation operation. Signed session scope, current fixture generation, active
membership, organization payment eligibility and key purpose must agree.
Organization members can manage their own renter keys; organization admins can
manage that organization's keys and mint IR keys. Arbitrary explicit organization
scopes are refused. The configured s3r.ch network administrator may manage only
the declared `oracles:attest` service scope outside an organization.

Deployment provides `API_KEYS_USER_AUTHORITY_URL`,
`API_KEYS_USER_AUTHORITY_CA_FILE`, `API_KEYS_AUTHORITY_TOKEN_FILE`,
`API_KEYS_AUTHORITY_GENERATION`, `API_KEYS_AUTHORITY_MANIFEST_SHA256`,
`HYPERMESH_CONTROL_PLANE_URL`, `API_KEYS_FINGERPRINT_CA_FILE`,
`API_KEYS_FINGERPRINT_TOKEN_FILE`, `API_KEYS_GATEWAY_URL`, and
`API_KEYS_GATEWAY_CA_FILE`. All capability origins require verified HTTPS. The two token files
hold distinct purpose credentials with private file permissions. Startup checks
User authority, Plane registry and enforced Gateway scope protocol capabilities,
plus forced tenant RLS and permanent database privileges. These are protocol
checks, independent of service build revisions. Missing owners fail closed.

Created keys bind to the verified organization or network and subject. Listing
and mutation cannot use a caller-supplied organization to broaden this scope.
Validation rechecks current User membership and returns the organization and
purpose to Gateway, which limits model discovery, paid ticket use and IR receipt
history to that scope. Existing unbound renter credentials are not upgraded into
organization authority. Strict fingerprint publication must be acknowledged
before a new organization key commits; a failed publication rolls back the key.
