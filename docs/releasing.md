# Releasing

`api-keys-service` is version **0.1.0**. `release-policy.json` records release line **0.1** and the version file `pyproject.toml`. `.github/version-policy.json` records the same `0.1.0` for `pyproject.toml` and for the historical copy at `core/api-keys-service/pyproject.toml`. `.github/workflows/version-policy.yml` checks those declared versions on pull requests, on pushes to `main`, and on tags.

This page is how artifacts move. The compatibility manifest and the steps that produce `releases/accepted` and `releases/candidate` are in [release-policy.md](release-policy.md). The shared rules live in the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

## What each workflow keeps

| Workflow | When it runs | What it leaves behind |
| --- | --- | --- |
| `.github/workflows/package.yml` | Push to `main`, and manual dispatch on `main` | Qualified OCI runtime with the exact tested wheel and sdist at `/qualified/tested-dist.zip`. Main advances the moving `runtime:test` channel; no Actions package archive, Git tag or GitHub release. |
| `.github/workflows/preparation.yml` | Pull request | Credential-free source, wheel, rebuilt sdist and isolated HTTP runtime checks. Temporary bytes and the local image are removed; no artifact upload or publication. |
| `.github/workflows/release-admission.yml` | Any tag push, and manual dispatch | Admission through `hyperme-sh/spanopticon` `component-release` at line `0.1`, using `SPANOPTICON_RELEASE_BASELINE_SHA`. |
| `.github/workflows/release.yml` | Tag push matching `v*` | Admission, then publication of the already tested `package.yml` artifact. |

On a public repository those jobs run on `ubuntu-24.04`. On a private repository they select `[self-hosted, linux, x64, debrunner]`. `package.yml` requests a short-lived read token for `auth-service`, `controlplane-api`, `controlplane-core`, `controlplane-db`, `controlplane-events`, `controlplane-identity`, `controlplane-tenancy`, and `user-service`. The preparation lane installs the fixture wheels and does not receive that token.

The publish job in `release.yml` grants `contents: write` and `actions: read` only to the pinned action `hyperme-sh/.github/actions/release-channel`. That job does not check out this repository or install its packages. It retrieves the exact tested distribution bytes from the qualified GHCR image produced by a successful `package.yml` run. Admission has to succeed for that job to run.

## Development snapshots

A GitHub prerelease tagged `test-<commit>` is a development snapshot. The package version embedded in the snapshot does not reserve a stable version. Keep artifact and consumer evidence for those snapshots under `releases/qualification`, and mark the receipt as non-stable. `package.yml` and `preparation.yml` do not create those prereleases. Qualified distribution bytes travel inside the main OCI image; PR temporary files are removed.

## Stable publication

A stable release is an immutable, non-draft GitHub release tagged `vMAJOR.MINOR.PATCH`. For this component that tag is on line `0.1` and matches the version in `pyproject.toml`.

The publisher checks all of the following itself:

- the tag and the commit it peels to
- the exact tested distribution bundle in the qualified OCI image from successful main validation
- compatible declared contracts
- an accepted baseline at `releases/accepted`, selected with the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA` (the full 40-character commit SHA of that baseline)

A green caller job does not accept a release on its own. A `test-<commit>` snapshot cannot become `releases/accepted` by a provenance label. This repository does not yet contain `releases/accepted`. Until that directory records a real stable release, and `SPANOPTICON_RELEASE_BASELINE_SHA` points at it, stable publication has no baseline to compare against. The first baseline is produced from tested artifacts, contract files, and provenance, then stored as that immutable release. The procedure is in [release-policy.md](release-policy.md).

Publishing the package, accepting downstream consumers, and deploying the service are three separate steps. The release workflows do not deploy.
