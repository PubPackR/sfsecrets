# sfsecrets

Credential resolution for Studyflix Python apps -- the Python twin of the R
package `secretsR`. One function, three backends:

```python
import sfsecrets

conn = sfsecrets.secret_get("studyflix-postgresql-connection")
```

`secret_get` resolves a secret by **name** -- the same name `secretsR` uses on
the R side. Resolution only: this package knows nothing about databases or Ad
Manager. Shaping the resolved value into a connection belongs one layer up, in
packages like `pgaccessPy`.

## Status

Two backends are implemented. The **file backend** reads the encrypted legacy
keyfiles under `keys/` that `secretsR` also reads, so both languages resolve
the same secrets from the same files during the migration. The **gsm** backend
(Google Secret Manager, the migration's actual target) reads secrets from
Secret Manager over its REST API, authenticating via Application Default
Credentials.

## Backends

Selected via the `SF_SECRET_BACKEND` environment variable (default `file`):

| Backend | Selected by | Behaviour |
|---|---|---|
| `file` | `SF_SECRET_BACKEND=file` (default) | Decrypts the legacy keyfiles under `keys/` with Fernet. |
| `env` | `SF_SECRET_BACKEND=env` | Reads `SF_SECRET_<NAME>` (name upper-cased, `-` to `_`). For local dev / CI. |
| `gsm` | `SF_SECRET_BACKEND=gsm` | Reads the secret from Google Secret Manager over REST, authenticating via Application Default Credentials. |

On a host `sfsecrets.is_production()` considers production (the marker file
`/etc/studyflix/production` exists, or `GOOGLE_APPLICATION_CREDENTIALS` names a
file that exists), any backend other than `gsm` is refused with a
`RuntimeError` rather than silently falling back to reading `keys/`.

## The legacy map

`sfsecrets/_legacy_map.py` is the file backend's routing table: secret name ->
which file(s) under `keys/` hold it, how the Fernet key is derived, and which
environment variable carries that key. It is data on purpose -- adding a secret
the file backend should resolve is a new row, not new code.

The secret names are a **contract with R**: `secretsR` resolves the same
strings, so a name is never invented on the Python side or altered without
updating both.

Two derivations exist and must not be conflated:

- **`derived`** (`DB_MASTER_KEY`) -- the Fernet key is
  `base64.urlsafe_b64encode(sha256(raw_key).digest())`.
- **`verbatim`** (`ADMANAGER_DECRYPT_KEY`) -- the environment variable's value
  *is* the Fernet key, unmodified.

`studyflix-postgresql-connection` is one secret name backed by **two** legacy
files (server settings JSON, and the password). The file backend decrypts both
and merges them into one JSON object -- the same shape the `gsm` backend will
eventually return for that name.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SF_SECRET_BACKEND` | `file` | `file`, `env`, or `gsm` |
| `DB_MASTER_KEY` | -- | Required by the file backend for `studyflix-postgresql-connection`. |
| `ADMANAGER_DECRYPT_KEY` | -- | Required by the file backend for `studyflix-admanager-service-account`. |
| `SF_KEY_DIR` | `../../keys` | Directory holding the encrypted legacy keyfiles, if `key_dir` is not passed explicitly. |

`key_dir` is also accepted as a direct argument to `secret_get`, and takes
precedence over `SF_KEY_DIR`. It is an argument rather than something read from
process state on purpose: two callers in the same process resolving from
different key directories must never silently share one. Pass it explicitly
whenever more than one key directory can be in play.

## Installation

**This package is vendored as a git submodule, never pip-installed.** The
FlowForce host runs no dependency-installation step -- deploys only rsync
files, so whatever is hand-installed on the host is what actually gets
imported. `pyproject.toml` exists so the package is legible and testable on
its own, not because anything installs it from here.

The third-party dependencies -- `cryptography`, `google-auth`, `requests` and
`urllib3` -- are pinned in `pyproject.toml` to the versions measured installed
on `shiny.studyflix.info`. The rule is not "add nothing": it is add nothing the
host does not already have, since the deploy only rsyncs files and runs no
install step.

### Local development

```sh
uv sync
uv run pytest tests -v
```

## Tests

`tests/test_file_backend.py` covers the file backend end to end: decrypting the
legacy keyfiles, merging the Postgres pair into one object, and confirming that
two `key_dir` values used in the same process never bleed into each other.
