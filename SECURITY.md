# Security policy

## Supported versions

Security fixes are applied to the latest release on `main`. Earlier versions
are not maintained unless a release announcement explicitly says otherwise.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. open the repository's **Security** tab;
2. choose **Report a vulnerability**;
3. include the affected version, impact, reproduction steps, and any proposed
   mitigation.

Do not disclose an unpatched vulnerability in a public issue or discussion.
If private reporting is unavailable, open a public issue containing no
sensitive details and ask the maintainer to establish a private channel.

You should receive an acknowledgement within seven days. Valid reports will be
triaged, assigned a severity, and coordinated toward a fix and disclosure.

## Security boundary

Please read [docs/SECURITY.md](docs/SECURITY.md) before reporting behavior that
may be an intentional trust-boundary limitation. In particular, generic
operator certificates and utilities are assertions; only built-in verifiers
provide in-process mathematical recomputation.
