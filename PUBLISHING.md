# Publishing to PyPI

This repo publishes automatically via **PyPI Trusted Publishing** (OIDC) — no
API token is stored anywhere. You do a one-time setup on PyPI, then every
version tag ships a release.

## One-time PyPI setup (~2 minutes)

1. Create the project's trusted publisher **before the first release** (PyPI
   supports "pending" publishers for projects that don't exist yet):
   - Log in to <https://pypi.org> → your account → **Publishing** →
     **Add a pending publisher**.
   - Fill in:
     - **PyPI Project Name:** `pramiti-mcp-gateway`
     - **Owner:** `vasamsetty86`
     - **Repository name:** `pramiti-mcp-gateway`
     - **Workflow name:** `publish.yml`
     - **Environment name:** `pypi`
2. In this GitHub repo, create the environment the workflow references:
   - **Settings → Environments → New environment → name it `pypi`.**
   (No secrets needed — the OIDC token is minted at publish time.)

## Cutting a release

```bash
# bump version in pyproject.toml, commit, then:
git tag v0.1.0
git push origin v0.1.0
```

The `publish.yml` workflow runs the test suite, builds the wheel + sdist, and
publishes to PyPI. After it succeeds, `pip install pramiti-mcp-gateway` works.

## Notes

- The gateway is developed in the private Pramiti monorepo and mirrored here.
  To sync future changes, copy the package contents over (or set up a
  `git subtree` split) and cut a new tag.
- `scan` is dependency-free; live connect / proxy need the `connect` extra and
  signing needs the `sign` extra (both declared in `pyproject.toml`).
