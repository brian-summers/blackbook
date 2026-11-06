## Summary

What this PR changes and why.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Docs / tooling
- [ ] Refactor (no behavior change)

## Security impact

Does this touch authentication, cryptography, ACLs, MFA, K-of-N, tunnels, or
at-rest encryption? If so, describe the threat-model implications and the
allowed/denied paths you tested.

## Testing

How you verified the change (commands, added tests, manual steps).

- [ ] `scripts/check.sh` passes (the pre-push hook runs it)
- [ ] Denied paths are tested, and assert why they're denied
- [ ] Docs updated (`README.md` / `DEPLOYMENT.md`) if behavior or flags changed
- [ ] No secrets, tokens, or bundle contents committed
