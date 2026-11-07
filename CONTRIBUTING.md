# Contributing to Blackbook

Thanks for your interest. Blackbook is security-critical software; contributions
are welcome, and held to a correspondingly high bar.

## Ground rules

- **Never commit secrets.** Credential bundles (`admin*`, `*-bundle.json`,
  `user*.json`), the `secrets/` directory, and `.env` are gitignored — keep it
  that way. Double-check `git status` before pushing.
- **Do not report security vulnerabilities in public issues or PRs.** See
  the [security policy](https://brian-summers.github.io/blackbook/security/policy/).
- By contributing you agree your work is licensed under the project's
  [AGPL-3.0-only](https://github.com/brian-summers/blackbook/blob/main/LICENSE) license.

## Development setup

You need Rust (via [rustup](https://rustup.rs)), Docker, and on Windows
[Strawberry Perl](https://strawberryperl.com) for the vendored OpenSSL build.
`rust-toolchain.toml` pins the Rust version; rustup installs it on the first
`cargo` command in the repository.

Once per clone, turn on the git hooks:

```bash
git config core.hooksPath .githooks
```

- **pre-commit** (seconds) refuses a commit that contains a credential bundle,
  a private key, a `bbk_` token, `.env` or anything under `secrets/`, and
  checks the Rust code is formatted.
- **pre-push** (a minute or two) runs `scripts/check.sh`: pins, rustfmt,
  clippy, the tests and cargo-deny.

  After a toolchain or dependency change, the first build recompiles every
  dependency, which takes several minutes. GitHub may close an SSH push that
  waits that long: `git push` then exits with no error message even though the
  hook passed. Push again. The build is cached by then, so the hook finishes
  quickly.

The optional tools make the local checks match CI. Without them, `check.sh`
skips their steps locally; CI never skips:

```bash
cargo install --locked cargo-deny cargo-llvm-cov
# gitleaks, for scanning staged changes: https://github.com/gitleaks/gitleaks#installing
```

`scripts/check.sh` is also what CI runs, step for step, so a check that passes
here passes there:

```bash
scripts/check.sh                 # pins fmt clippy test deny (the pre-push set)
scripts/check.sh coverage        # line coverage, lcov in target/lcov.info
scripts/check.sh docker scan e2e # build the image, scan it, run the end-to-end test
scripts/check.sh all             # everything CI checks
```

`scripts/e2e.sh` runs the image against the real `docker-compose.yml` in a
throwaway compose project with its own names, port and subnet. It's safe to
run next to your own stack, and it never touches `./secrets`, `./.env` or
`~/.bbk`.

To run your own stack (Postgres + server), see README "Quick start":

```bash
mkdir -p secrets && openssl rand 32 > secrets/master_keyfile
./scripts/generate-postgres-certs.sh
cp .env.example .env      # then change every password
docker compose up -d
```

## Making changes

1. Branch from `main`.
2. Keep changes focused; match the surrounding code's style, naming, and comment
   density (this codebase favors dense explanatory comments on non-obvious
   security decisions — preserve that).
3. Add or update tests for behavior changes. Security-relevant changes
   (auth, crypto, ACL, tunnels) **require** tests demonstrating both the allowed
   and the denied path. If the change is visible end to end, add a check to
   `scripts/e2e.sh` too, and assert *why* a denied path is denied (the error
   code), not just that it failed.
4. Run `scripts/check.sh` before opening a PR (the pre-push hook does this).
5. Update the relevant docs (`README.md`, `DEPLOYMENT.md`) in the same PR — the
   docs are treated as part of the contract and are reviewed for accuracy.

## Pull requests

`main` is protected. Every change lands through a pull request, and it can
merge only when:
- **CI result** is green;
- CodeQL reports no new high or critical alert;
- the branch is up to date with `main`.

Merges are squash or rebase, so history stays linear. Force-pushing `main` and
deleting it are blocked for everyone.

```bash
git switch -c my-change
# ...commit...
git push -u origin my-change   # the pre-push hook runs scripts/check.sh first
gh pr create --fill
gh pr merge --auto --squash    # merges by itself once every check passes
```

- Describe the change, the threat/UX motivation, and how you tested it.
- The **CI result** check must be green. It covers rustfmt, clippy with
  warnings as errors, tests on Linux, Windows and macOS, the minimum Rust
  version, cargo-deny, dependency review, actionlint and zizmor on the
  workflows, hadolint, gitleaks, a Grype scan of the image and the end-to-end
  test.
- For anything touching the cryptographic core or the authentication path,
  expect a careful review and a request for a threat-model note.

## Dependencies

Dependabot opens weekly pull requests for crates, GitHub Actions, the Docker
base images and the Rust toolchain, and security updates as soon as an
advisory appears. Minor and patch updates for crates arrive as one grouped PR,
and major updates as another. A major update usually needs code changes, so
its PR stays red until someone migrates the code on that branch.

`deny.toml` is the dependency policy:
- licences must be compatible with AGPL-3.0;
- crates come only from crates.io;
- `ring` stays out of the tree;
- any advisory exception carries its reason.

GitHub Actions are pinned to full commit SHAs and base images to digests;
`scripts/check.sh pins` fails otherwise.

## Releasing

Releases are cut by pushing a tag; `.github/workflows/release.yml` does the rest.
Only repository admins can create, move or delete `v*` tags.

1. In a pull request, set `version` in `Cargo.toml` to the new version (no
   `v`) and run `cargo check` so `Cargo.lock` follows. Merge it.
2. Tag the merged commit on `main` and push the tag:

   ```bash
   git tag -s v0.4.0 -m "v0.4.0"    # -s signs the tag; use -a if you don't sign
   git push origin v0.4.0
   ```

   Push the tag rather than publishing a release in the web UI. Publishing
   there creates a plain, unsigned tag, and the workflow then works from
   that release instead of writing its own.

The workflow refuses a tag that doesn't match `Cargo.toml` or isn't on `main`.
It then:
1. runs the full CI suite on the tagged commit;
2. builds the `linux/amd64` and `linux/arm64` images, scans and end-to-end
   tests each one, and uploads them to GHCR by digest, untagged;
3. waits for a maintainer to approve the `release` environment (*Actions →
   the Release run → Review deployments*);
4. tags the images on `ghcr.io/brian-summers/blackbook`, and on Docker Hub if
   that's configured. The tags are `X.Y.Z`, `vX.Y.Z`, `X.Y`, `X` (from 1.0
   on) and `latest`. It also attaches an SBOM and a signed build-provenance
   attestation;
5. creates the GitHub release, with the pull commands, the digest and the
   attestation check above GitHub's generated notes. If the release already
   exists, it adds that section to the existing notes, and publishes the
   release if it's a draft.

A tag like `v0.4.0-rc.1` publishes a prerelease: it doesn't move `latest`,
and the GitHub release is marked *Pre-release*. Any other tag moves `latest`
on both registries and marks the release *Latest*.

Repository settings this relies on (configured for brian-summers/blackbook; a
fork needs its own):

- **Rulesets:** `main` (see Pull requests) and `release tags`, which lets
  only admins create, move or delete `v*` tags.
- **Environments → `release`:** deployable only from `v*` tags, with a
  required reviewer.
- **Docker Hub (optional):** create an access token at hub.docker.com with
  Read & Write scope for the repository, then:

  ```bash
  gh secret set DOCKERHUB_TOKEN --env release      # prompts for the token
  gh variable set DOCKERHUB_USERNAME --env release --body <user>
  ```

  If the repository isn't `<user>/blackbook`, set `DOCKERHUB_REPOSITORY`
  (for example `myorg/blackbook`) the same way. Without these, the workflow
  publishes to GHCR only.
- **After the first release:** the GHCR package starts private. Make it
  public under the package's settings, so users can pull without logging in.

## Reporting bugs & requesting features

Open an issue using the templates under `.github/ISSUE_TEMPLATE/`. For anything
with a security impact, use private reporting instead (see SECURITY.md).
