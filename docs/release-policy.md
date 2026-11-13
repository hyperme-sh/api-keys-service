# Release compatibility

This component's recorded release line is **0.1** (`release-policy.json`). The package version is **0.1.0** in `pyproject.toml`. A patch on that line keeps the accepted API contract. Channel behavior, artifact retention, and who publishes are described in [releasing.md](releasing.md).

`release-policy.json` names the repository, the component, the line, and the version file. Version alignment of the declared package files is checked by `.github/workflows/version-policy.yml`. Release admission runs on tag pushes and on a manual request (`.github/workflows/release-admission.yml` and `.github/workflows/release-admission.yml`), using the pinned Spanopticon component workflow at line `0.1`. A configuration-only result is not a compatibility result.

Before attempting a release:

1. Produce an accepted bundle at `releases/accepted/release.json`, with its contract files and immutable artifact references. Set the repository variable `SPANOPTICON_RELEASE_BASELINE_SHA` to that commit's full 40-character SHA. The first baseline comes from tested artifacts, consumer qualification, and provenance. Example digests are not release evidence.
2. Generate the candidate bundle at `releases/candidate/release.json` from the release artifacts. It contains this component only, uses line `0.1`, and matches `pyproject.toml` and the requested tag.
3. Run admission against the baseline selected by `SPANOPTICON_RELEASE_BASELINE_SHA`. A patch keeps the published contract. Replacing a published artifact at the same version is rejected. Check artifact provenance and downstream consumers in their own pipelines.
4. Publish only after admission and the artifact checks succeed for that exact tag. The publisher reads the accepted baseline on its own, separately from fields in the candidate bundle.

A missing baseline stops stable admission. These workflows do not deploy the service, do not grant private dependency access to the publish job, and do not by themselves prove a declared artifact exists. The manifest format and the compatibility rules are in the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).
