---
title: Self-hosted secrets manager
description: "Blackbook is a self-hosted, open-source secrets manager written in Rust: an end-to-end-encrypted HashiCorp Vault alternative with mTLS, ACLs, TOTP MFA, K-of-N approvals, and a tamper-evident audit log. Deploys with Docker; driven from a CLI, a web console, or AI agents over MCP."
hide:
  - navigation
  - toc
---
<meta name="google-site-verification" content="EeM3Q6D09q2SgM-h-OQTQJ-oKCBCWLDRe0FDCG6nJyc" />
<div class="bb-hero" markdown>

![Blackbook logo](assets/logo.png){ .bb-hero__logo width="144" height="144" }

# Blackbook Secrets Engine

<p class="bb-hero__tagline">The utmost in paranoid security.</p>

A self-hosted, open-source **secrets manager** written in Rust. An end-to-end-encrypted alternative to HashiCorp Vault for API keys, passwords, tokens, certificates, and files. Deploy it with Docker; drive it from the `bbk` CLI, a local web console, or AI agents over MCP.

[Get started](getting-started/quick-start.md){ .md-button .md-button--primary }
[How it works](getting-started/how-it-works.md){ .md-button }
[View on GitHub](https://github.com/brian-summers/blackbook){ .md-button }

</div>

```bash
cargo install blackbook                # installs the bbk CLI
bbk put api-key "sk_live_abc123"       # save a secret
bbk get api-key                        # read it back
bbk file put ./id_rsa --name ssh-key   # save a file
```

## Secure by default, not by configuration

There's no "secure mode" to switch on, because there's no insecure mode to begin with. Every one of these is on out of the box:

<div class="grid cards" markdown>

-   :lucide-lock-keyhole:{ .lg .middle } **Encrypted in transit**

    ---

    TLS 1.3 only, with *mandatory* mutual TLS. Every request must present both a client certificate and a token, and both must belong to the same identity.

-   :lucide-database:{ .lg .middle } **Encrypted at rest, names included**

    ---

    Values *and* identifiers (secret names, users, groups, audit messages) are encrypted. A stolen database dump is just noise.

-   :lucide-users:{ .lg .middle } **Fine-grained access control**

    ---

    Private and shared domains, group rules, time windows, and use caps that count down and stop authorizing on their own.

-   :lucide-scroll-text:{ .lg .middle } **Tamper-evident audit log**

    ---

    Every action is logged in a keyed hash chain, so deleting, editing, or reordering history is detectable with `bbk audit --verify`.

-   :lucide-file-lock:{ .lg .middle } **Read-only by default**

    ---

    Saving over an existing secret is refused. Overwriting is a separate, deliberate action, so nothing important gets silently clobbered.

-   :lucide-laptop:{ .lg .middle } **Your saved login is sealed too**

    ---

    Credentials on your own machine are encrypted under an Argon2id-derived key. A copied `~/.bbk` folder is inert without your passphrase.

</div>

## Turn the dial up when a secret deserves it

<div class="grid cards" markdown>

-   :lucide-shield-check:{ .lg .middle } **Two-person rule**

    ---

    Require *K* of *N* named teammates to approve before anyone can read a secret.

    [:octicons-arrow-right-24: K-of-N approvals](guides/protection.md)

-   :lucide-smartphone:{ .lg .middle } **MFA on every read**

    ---

    Demand a fresh TOTP code from any authenticator app for each read of a flagged secret.

    [:octicons-arrow-right-24: Two-factor reads](guides/protection.md)

-   :lucide-eye-off:{ .lg .middle } **Even the server can't read it**

    ---

    `--external` encrypts on your machine first. The server stores ciphertext it has no way to open.

    [:octicons-arrow-right-24: Client-side encryption](security/architecture.md#client-side-external-encryption-advanced)

-   :lucide-flame:{ .lg .middle } **Burn after reading**

    ---

    Self-destruct after one read, cap the number of reads, or make a secret permanently immutable.

    [:octicons-arrow-right-24: Per-secret protections](guides/protection.md)

-   :lucide-bot:{ .lg .middle } **Built for AI agents**

    ---

    `bbk mcp` gives Claude Code and other MCP clients least-privilege, server-enforced access to secrets.

    [:octicons-arrow-right-24: AI agents (MCP)](guides/mcp.md)

-   :lucide-cable:{ .lg .middle } **End-to-end-encrypted tunnels**

    ---

    `ssh -L`-style port forwarding between two clients, relayed by a server that only ever sees ciphertext.

    [:octicons-arrow-right-24: Secure tunnels](guides/tunnels.md)

</div>

## Explore the docs

<div class="grid cards" markdown>

-   [:lucide-rocket: **Quick start**](getting-started/quick-start.md)

    Run the server with Docker Compose and store your first secret in a few minutes.

-   [:lucide-book-open: **Core concepts**](getting-started/concepts.md)

    Secrets and files, profiles, domains, and permissions, in plain language.

-   [:lucide-terminal: **Command reference**](reference/commands.md)

    Every `bbk` command and flag on one page.

-   [:lucide-server: **Deployment guide**](deployment.md)

    Hardening, PostgreSQL over mutual TLS, backups, monitoring, and scaling.

-   [:lucide-key-round: **Architecture & cryptography**](security/architecture.md)

    The layered defense, the key hierarchy, and the full data model.

-   [:fontawesome-brands-github: **Source on GitHub**](https://github.com/brian-summers/blackbook)

    Open source under AGPL-3.0, with heavily commented code you can audit.

</div>
