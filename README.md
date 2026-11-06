# sfsecrets

Credential resolution for Studyflix Python apps -- the Python twin of the R
package `secretsR`. One function, two backends:

```python
import sfsecrets

conn = sfsecrets.secret_get("studyflix-postgresql-connection")
```

`secret_get` resolves a secret by **name** -- the same name `secretsR` uses on
the R side. Resolution only: this package knows nothing about databases or Ad
Manager. Shaping the resolved value into a connection belongs one layer up, in
packages like `pgaccessPy`.

## Backends

Selected via the `SF_SECRET_BACKEND` environment variable (default `gsm`):

| Backend | Selected by | Behaviour |
|---|---|---|
| `gsm` | `SF_SECRET_BACKEND=gsm`, or unset | Reads the secret from Google Secret Manager over REST, authenticating via Application Default Credentials. |
| `env` | `SF_SECRET_BACKEND=env` | Reads `SF_SECRET_<NAME>` (name upper-cased, `-` to `_`). For local dev / CI. |

On a host `sfsecrets.is_production()` considers production (the marker file
`/etc/studyflix/production` exists, or `GOOGLE_APPLICATION_CREDENTIALS` names a
file that exists), any backend other than `gsm` is refused with a
`RuntimeError`.

The secret names are a **contract with R**: `secretsR` resolves the same
strings, so a name is never invented on the Python side or altered without
updating both. `sfsecrets.SERVICES` maps service names to them.

## The file backend is gone (0.2.0)

0.2.0 removed the `file` backend, which decrypted the legacy keyfiles under
`keys/` with Fernet, together with its routing table (`FILES`) and the
`cryptography` dependency (Plan F). Every runtime resolves from Secret
Manager.

- `SF_SECRET_BACKEND=file` raises a `RuntimeError` naming the removal, from
  `backend()` and from `secret_get()`.
- `secret_get()` still accepts `key_dir` and `key` for this release, ignores
  them as the `gsm` and `env` backends always did, and emits a
  `DeprecationWarning` when either is passed. Callers pass `key_dir` on every
  call, so refusing it would break them the day they move to 0.2.0. Both
  arguments go in the next release.
- `DB_MASTER_KEY`, `ADMANAGER_DECRYPT_KEY` and `SF_KEY_DIR` are read by nothing.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SF_SECRET_BACKEND` | `gsm` | `gsm` or `env` |

## Installation

**This package is vendored as a git submodule, never pip-installed.** The
FlowForce host runs no dependency-installation step -- deploys only rsync
files, so whatever is hand-installed on the host is what actually gets
imported. `pyproject.toml` exists so the package is legible and testable on
its own, not because anything installs it from here.

The third-party dependencies -- `google-auth`, `requests` and `urllib3` -- are
pinned in `pyproject.toml` to the versions measured installed
on `shiny.studyflix.info`. The rule is not "add nothing": it is add nothing the
host does not already have, since the deploy only rsyncs files and runs no
install step.

### Local development

```sh
uv sync
uv run pytest tests -v
```

## Tests

`tests/test_secret_get.py` covers dispatch, the production guard, the cache
and the 0.2.0 removal; the `tests/test_gsm_*.py` files cover the gsm backend
without a network.
