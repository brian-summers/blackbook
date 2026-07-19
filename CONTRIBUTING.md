# Contributing to Blackbook

Thanks for your interest. Blackbook is security-critical software; contributions
are welcome, and held to a correspondingly high bar.

## Ground rules

- **Never commit secrets.** Credential bundles (`admin*`, `*-bundle.json`,
  `user*.json`), the `secrets/` directory, and `.env` are gitignored — keep it
  that way. Double-check `git status` before pushing.
- **Do not report security vulnerabilities in public issues or PRs.** See
  [SECURITY.md](SECURITY.md).
- By contributing you agree your work is licensed under the project's
  [AGPL-3.0-only](LICENSE) license.

## Development setup

```bash
# Build the CLI/server (requires perl on Windows for the vendored OpenSSL).
cargo build --release

# Run the test suite (unit tests; no database required).
cargo test

# Lint.
cargo clippy --all-targets

# Bring up the full stack (Postgres + server) — see README "Quick start".
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
   and the denied path.
4. Run `cargo test` and `cargo clippy --all-targets` before opening a PR.
5. Update the relevant docs (`README.md`, `DEPLOYMENT.md`) in the same PR — the
   docs are treated as part of the contract and are reviewed for accuracy.

## Pull requests

- Describe the change, the threat/UX motivation, and how you tested it.
- CI (build, test, clippy, docker build, cargo-audit) must be green.
- For anything touching the cryptographic core or the authentication path,
  expect a careful review and a request for a threat-model note.

## Reporting bugs & requesting features

Open an issue using the templates under `.github/ISSUE_TEMPLATE/`. For anything
with a security impact, use private reporting instead (see SECURITY.md).
