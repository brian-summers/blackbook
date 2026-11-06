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
advisory appears. `deny.toml` is the dependency policy:
- licences must be compatible with AGPL-3.0;
- crates come only from crates.io;
- `ring` stays out of the tree;
- any advisory exception carries its reason.

GitHub Actions are pinned to full commit SHAs and base images to digests;
`scripts/check.sh pins` fails otherwise.

## Releasing

Releases are cut by pushing a tag; `.github/workflows/release.yml` does the rest.

1. Set `version` in `Cargo.toml` to the new version (no `v`), run
   `cargo check` so `Cargo.lock` follows, and merge that to `main`.
2. Tag the merged commit and push the tag:

   ```bash
   git tag -s v0.4.0 -m "v0.4.0"    # -s signs the tag; use -a if you don't sign
   git push origin v0.4.0
   ```

The workflow refuses a tag that doesn't match `Cargo.toml` or isn't on `main`.
It then:
1. runs the full CI suite on the tagged commit;
2. builds `linux/amd64` and `linux/arm64` images;
3. scans and end-to-end tests each one;
4. publishes them to `ghcr.io/brian-summers/blackbook` (and Docker Hub, if
   configured) with an SBOM and a signed build-provenance attestation;
5. creates the GitHub release.

A tag like `v0.4.0-rc.1` publishes a prerelease without moving `latest`.

One-time setup, in the repository settings:

- **Environments → `release`**: under deployment branches and tags, allow only
  tags matching `v*`. Optionally add yourself as a required reviewer, so each
  publish waits for a click.
- **Docker Hub (optional)**: create an access token with read/write scope at
  hub.docker.com. Add it to the `release` environment as the secret
  `DOCKERHUB_TOKEN`, with your Docker Hub user name as the variable
  `DOCKERHUB_USERNAME`. Set `DOCKERHUB_REPOSITORY` (for example
  `myorg/blackbook`) if the repository isn't `<user>/blackbook`. Without these,
  the workflow publishes to GHCR only.
- **After the first release**: the GHCR package starts private. Make it public
  under the package's settings so users can pull without logging in.

## Reporting bugs & requesting features

Open an issue using the templates under `.github/ISSUE_TEMPLATE/`. For anything
with a security impact, use private reporting instead (see SECURITY.md).
