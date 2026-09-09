"""One function per backend. No shared state, no cross-calls."""
import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken

from ._legacy_map import FILES

DEFAULT_KEY_DIR = "../../keys"
_UNSET = object()  # marks "no value produced" without attaching implicit
                    # exception context -- see _join_legacy_parts.


def _fernet_for(derivation, env_var):
    raw = os.environ.get(env_var, "")
    if not raw:
        raise RuntimeError(
            "%s is not set. Pass it through the environment, never on the "
            "command line -- /proc/<pid>/cmdline is world-readable." % env_var)
    if derivation == "derived":
        key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    else:
        key = raw.encode()
    try:
        return Fernet(key)
    except (ValueError, TypeError):
        raise RuntimeError(
            "%s is not a usable Fernet key for a %r secret." % (env_var, derivation))


def secret_get_file(name, key_dir=None, version="latest"):
    """Resolve from keys/. `key_dir` is an ARGUMENT, never process state.

    An earlier draft read it from SF_KEY_DIR set by the caller with
    os.environ.setdefault. Two CredentialManager instances with different
    key_dirs in one process then silently shared the first one's -- verified in
    review: the second returned the first's host, database and user with no
    error. base-65's own test suite exercises exactly that via tmp_path.
    """
    if version != "latest":
        raise ValueError(
            "the file backend cannot resolve a specific version (%r asked for "
            "%r). keys/ holds one copy of each secret with no history. Use the "
            "gsm backend, or drop the version." % (name, version))
    if name not in FILES:
        raise KeyError(
            "%s has no file-backend mapping. Add it to _legacy_map.FILES." % name)
    paths, derivation, env_var = FILES[name]
    root = key_dir or os.environ.get("SF_KEY_DIR") or DEFAULT_KEY_DIR
    fernet = _fernet_for(derivation, env_var)

    parts = []
    for rel in paths:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            raise FileNotFoundError("%s not found for %s" % (path, name))
        with open(path, "rb") as fh:
            blob = fh.read()
        try:
            parts.append(fernet.decrypt(blob).decode())
        except InvalidToken:
            raise RuntimeError(
                "the key in %s did not open %s. Right shape, wrong key, or the "
                "file was re-encrypted." % (env_var, path))

    if len(parts) == 1:
        return parts[0]
    return _join_legacy_parts(name, parts)


def _join_legacy_parts(name, parts):
    """Join several legacy files into the one object the gsm backend would
    return for `name`, so the two backends are comparable rather than merely
    both "working". Today this is a single shape -- a JSON object plus a
    trailing password field -- because `studyflix-postgresql-connection` is
    the only multi-file secret _legacy_map has. That shape is NOT declared in
    _legacy_map (a fourth FILES field), which is otherwise meant to be pure
    data ("adding a secret is a row, not code"): a join *rule* still has to be
    code somewhere, and inventing a small enum of join-strategies for exactly
    one instance moves the label into data without removing the code, or the
    risk, from here. So this function keeps the join, but refuses silently:
    a secret with a join shape this doesn't understand raises a clear error
    instead of returning a wrong object with no indication anything is off --
    which matters because E2 has to prove `file` and `gsm` return the same
    shape for every secret, and a silently-wrong file-backend result would
    make that comparison meaningless rather than failing it.
    """
    if len(parts) != 2:
        raise RuntimeError(
            "%s: the file backend only knows how to join exactly 2 legacy "
            "files (a JSON object plus a password) into one secret, got %d. "
            "Add a join rule for this shape to _join_legacy_parts." % (name, len(parts)))
    merged = _UNSET
    parse_error = None
    try:
        merged = json.loads(parts[0])
    except json.JSONDecodeError as exc:
        # json.JSONDecodeError sets .doc to the string it failed to parse --
        # here parts[0], the DECRYPTED contents of the first legacy file (host,
        # port, dbname, user for studyflix-postgresql-connection). The password
        # is parts[1] and is never in .doc, so this is connection metadata, not
        # the credential itself -- still not something to keep reachable.
        # str(exc) is clean (verified: the "Expecting value: line 1 column 1"
        # form), so it is safe to keep in the message -- captured here, before
        # the except block ends, because the raise itself happens below.
        #
        # `from None` alone is NOT enough: it clears __cause__ and sets
        # __suppress_context__, but not __context__ -- Python attaches that to
        # any `raise` executed lexically inside this except block regardless
        # of the `from` clause, so a logger walking __context__ directly
        # (Sentry-style capture, structured JSON logging) would still reach
        # .doc. Same shape as _gsm.py's UnicodeDecodeError and response.json()
        # handling; the fix here is the same: raise OUTSIDE the except block,
        # below, where no exception is active for Python to attach.
        parse_error = str(exc)
    if merged is _UNSET:
        raise RuntimeError(
            "%s: the file backend expected the first of its 2 legacy files to "
            "be a JSON object to merge the second file's password into, but "
            "it did not parse as JSON (%s)." % (name, parse_error))
    if not isinstance(merged, dict):
        raise RuntimeError(
            "%s: the file backend expected the first of its 2 legacy files to "
            "decode to a JSON object, got %s." % (name, type(merged).__name__))
    merged["password"] = parts[1]
    return json.dumps(merged)


def secret_get_env(name):
    var = "SF_SECRET_" + name.replace("-", "_").upper()
    if var not in os.environ:
        raise KeyError("%s is not set" % var)
    return os.environ[var]
