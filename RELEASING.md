# Releasing

Releases go to PyPI automatically when a version tag is pushed. The
`Release` workflow uses PyPI trusted publishing, so no API token is stored
in the repository.

## One-time setup

1. On PyPI, open the `colgov` project, then **Settings → Publishing → Add a
   new publisher → GitHub**, and enter:
   - Owner: `chowkuanlaw`
   - Repository: `colgov`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. On GitHub, open **Settings → Environments → New environment**, name it
   `pypi`, and optionally add yourself as a required reviewer. With a
   reviewer set, every publish waits for your approval.

## Each release

1. Update `version` in `pyproject.toml` and `__version__` in
   `src/colgov/__init__.py`, and move the `CHANGELOG.md` entry from
   "unreleased" to today's date. Merge that to `main`.
2. Tag the merge commit and push the tag:

   ```bash
   git checkout main && git pull
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. The workflow checks that the tag matches the package version, runs the
   tests, builds the package and publishes it. If the tag and the version
   don't match, nothing is published.
