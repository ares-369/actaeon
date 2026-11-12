# Security

Please report vulnerabilities privately, through the repository's private
security advisory feature, not in a public issue. Include steps to reproduce
and the version or commit.

Actaeon is pre-alpha. See [docs/threat-model.md](docs/threat-model.md) for what it
tries to protect and [docs/known-limitations.md](docs/known-limitations.md) for
known gaps.

Deployment advice:

- Give every connector a read-only account on its source.
- Keep `bind_host: 127.0.0.1` unless a login mode is set.
- Use `auth.mode: proxy` only with `proxy_trusted_ips`.
- Keep `.env` readable only by the service user.
