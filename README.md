# API keys service

API key creation, listing and revocation, purpose restrictions, secret hashing
and renter-key fingerprint propagation. Version 0.1.0. Runtime lives in
src/api_keys_service; application factory: api_keys_service.app.create_app.

## Development

Use Python 3.13 and uv 0.11.26 with read access to the eight pinned private
hyperme-sh dependency repositories listed in the shared-runner workflow.

    uv sync --frozen
    bash scripts/check-package.sh

The suite runs from source, a fresh normally installed wheel outside this checkout,
and a rebuilt sdist wheel. Both wheel payloads must match the runtime source.
Unit tests use deterministic dependency doubles. The package check also runs native
PostgreSQL membership tests; Docker is required. No live provider or deployment is exercised.

Original tests and Dockerfile remain under core/api-keys-service as integration
references. The gateway source-boundary test requires the owning monorepo and is
retained there; it is not part of the standalone suite. The historical Dockerfile
is not a standalone build. Container and consumer integration need separate validation.

The shared-runner workflow runs only on main with read-only contents, pinned actions,
and exact repository Git credential headers. DEPENDENCY_READ_TOKEN must have
contents:read for the eight dependencies. Validation runs on the shared local runners;
package publication is described below. Service deployment remains separate.

## Release channels

Successful main-push validation retains the validated Python wheel and source distribution and publishes
an immutable `test-<commit>` GitHub prerelease. Push a `vMAJOR.MINOR.PATCH`
tag at that tested commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Package metadata versions are preserved; these are GitHub distribution snapshots,
not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

## Membership adoption

The six database cases from Panopticon #680/#684 now run against source, the
installed wheel and the rebuilt sdist wheel in `scripts/check-package.sh`. They
verify that reassigned email, unbound/missing subjects, inactive users and foreign
groups cannot grant API-key authority, while changing email preserves a bound
subject's existing permissions. Denied actors also exercise the create-key handler
and leave no key rows. Group lookup constrains both group and membership tenants.

Each test session creates its own PostgreSQL 16 container on a random loopback
port, waits through the exact TCP migration URL, applies the pinned DB package's
owner migrations and removes the container and volumes on exit. Docker and
migration errors fail validation rather than skip it. No external database URL is
accepted. These are database authorization checks using a fixture owner connection,
not restricted-role/RLS, live token validation or deployed-service acceptance.

Account-closure fences and owner receipts from source #633/#638 remain tracked in
[adoption issue #13](https://github.com/hyperme-sh/api-keys-service/issues/13).

### Package preparation

`bash scripts/check-package.sh --fixtures` runs the existing source, fresh-wheel
and rebuilt-source-archive consumers without private Git credentials. Fixtures
are built from the exact clean Git revisions already pinned by this package;
the manifest records their digests and source provenance. The verifier checks
root metadata, the complete active lock graph and transitive wheel metadata.
Explicit private extras and unrecognized conditional pins fail closed.

The read-only pull-request workflow retains tested wheels, source archives and
an artifact-derived runtime inventory as Actions artifacts. It does not publish
releases. These are preparation evidence, not an accepted synchronized dependency
baseline: package version alignment, dependency adoption and comparison against
a qualified prior baseline remain separate work. Existing owner test boundaries
and live/provider qualification requirements continue to apply.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. Owning-package and artifact validation
remain separate from stable release admission. Future test receipts must carry
an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. Stable publication remains closed without a valid baseline;
first stable bootstrap and coordinated release qualification remain separate.
No stable version, approval prerequisite or deployment is introduced here.
