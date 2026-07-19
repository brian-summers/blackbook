# Security Policy

Blackbook is a secrets engine. Its threat model and cryptographic design are
documented in [README.md](README.md) (see *Crypto details* and *Architecture*).
Please read this before reporting.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

Use GitHub's **[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
(Security → *Report a vulnerability* on this repository). If that is
unavailable, contact the maintainers privately and we will open a draft
advisory.

Please include:

- affected version / commit,
- a description of the issue and its impact,
- reproduction steps or a proof of concept,
- any suggested remediation.

We aim to acknowledge a report within **72 hours** and to agree on a disclosure
timeline with you. We support coordinated disclosure and will credit reporters
who wish to be named.

## Supported versions

This project is pre-1.0. Security fixes land on `main` and the latest tagged
release. Pin to a tag and watch releases for advisories.

| Version | Supported |
|---------|-----------|
| `main` / latest tag | ✅ |
| older tags | ❌ |

## Scope

In scope: the Blackbook server and CLI, the cryptographic envelopes, the
authentication/authorization path (mTLS + token, ACLs, K-of-N, MFA), the
tunnel handshake, and the Docker/Postgres hardening shipped in this repo.

Out of scope: issues that require a pre-compromised host or root on the machine
running the CLI (the web console and CLI run at the launching user's trust
level by design); the operator losing or mishandling the master-key provider
(keyfile / passphrase); and self-inflicted misconfiguration such as binding the
web console or API to a public interface without a proxy.

## Operator responsibilities

Blackbook's guarantees depend on the operator:

- **Back up the master-key provider** (`secrets/master_keyfile` or the master
  passphrase) **separately from the data volume.** Losing it makes all data
  unrecoverable; leaking it alongside a data-volume copy breaks at-rest secrecy.
- **Change every default password** in `.env` before first boot.
- **Keep credential bundles secret** — `admin-bundle.json` and any
  `client create -o …` output carry a live token and private key. They are
  gitignored; keep them out of images and backups too.
- **Bind to loopback** (the default) unless you intentionally front the service
  with a TLS-terminating proxy and firewall.
