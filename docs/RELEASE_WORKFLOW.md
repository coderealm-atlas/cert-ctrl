# Release Workflow

This guide walks through preparing, tagging, and publishing a new release of the project. It complements `RELEASE.md`, which captures the background details about versioning, CI, and packaging.

## 1. Preparation

- Ensure your local checkout is up to date: `git fetch origin --tags` and `git pull`.
- Confirm the working tree is clean: `git status` should report no pending changes.
- Run the full test suite (debug config is fine during iteration):
  ```bash
  cmake --preset debug
  cmake --build build
  ctest --preset debug
  ```
- When you are ready for release bits, configure a clean Release build to surface optimization issues early:
  ```bash
  rm -rf build
  cmake --preset release
  cmake --build build
  ```
- Review `RELEASE.md` and update any manual release notes or checklists as needed.
- If you intend to publish artifacts, prepare platform-specific packaging scripts or notes ahead of time.

## 2. Select the version number

- Follow SemVer with a leading `v`, such as `v1.4.0`.
- Decide whether the release is a final build (`v1.4.0`) or a pre-release (`v1.4.0-rc.1`, `v1.4.0-beta.2`).
- Confirm no previous tag already uses the version: `git tag --list 'v1.4.0'` should be empty.

## 3. Tag the release

- Create an annotated tag at the commit you want to ship:
  ```bash
  git tag -a v1.4.0 -m "Release v1.4.0"
  ```
- Push the tag (and optionally the branch) to origin:
  ```bash
  git push origin v1.4.0
  # or push everything: git push origin main --tags
  ```
- The version baked into binaries comes from `git describe`. At the tagged commit, `MYAPP_VERSION` resolves to `v1.4.0`. If additional commits land after the tag, expect suffixes such as `v1.4.0-2-gabc1234`.

## 4. Validate the release build

- Reconfigure so CMake picks up the new tag and regenerates `version.h`:
  ```bash
  cmake --preset release
  cmake --build build
  ```
- Confirm the reported version matches the tag. For binaries that expose `--version`, run the command, or inspect `build/version.h`.
- Optionally run smoke or integration tests using the Release binary.

## 5. Publish artifacts (optional but recommended)

- If you need downloadable assets, upload the binaries produced in the Release build to a new GitHub Release tied to the tag.
- Include release notes summarizing major changes, known issues, and upgrade guidance.
- For reproducible packaging, archive the exact commands you used (e.g., tar/zip invocations) inside the Release description.

## 6. Post-release follow-up

- Communicate the new version to stakeholders (Slack, email, changelog, etc.).
- If hotfixes are needed, branch from the release tag, apply fixes, and repeat the workflow with an incremented patch version (e.g., `v1.4.1`).
- Consider creating issues or todos for any automation opportunities discovered during the release.

---

For deeper background—such as CI triggers, troubleshooting, or packaging strategy—refer to `RELEASE.md`. If you automate parts of this flow, update this document to keep the step-by-step instructions current.
