"""One function per backend. No shared state, no cross-calls."""
import base64
import hashlib
import json
import os

from cryptography.fernet import Fernet, InvalidToken

from ._legacy_map import FILES

DEFAULT_KEY_DIR = "../../keys"


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


def secret_get_file(name, key_dir=None):
    """Resolve from keys/. `key_dir` is an ARGUMENT, never process state.

    An earlier draft read it from SF_KEY_DIR set by the caller with
    os.environ.setdefault. Two CredentialManager instances with different
    key_dirs in one process then silently shared the first one's -- verified in
    review: the second returned the first's host, database and user with no
    error. base-65's own test suite exercises exactly that via tmp_path.
    """
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
    # Several legacy files, one secret. Rebuild the object the gsm backend
    # returns for this name, so the two are comparable rather than merely both
    # "working". For postgresql that is the server JSON plus the password.
    merged = json.loads(parts[0])
    merged["password"] = parts[1]
    return json.dumps(merged)


def secret_get_env(name):
    var = "SF_SECRET_" + name.replace("-", "_").upper()
    if var not in os.environ:
        raise KeyError("%s is not set" % var)
    return os.environ[var]


def secret_get_gsm(name, version):
    raise NotImplementedError(
        "the gsm backend arrives in E2. E1 is the file backend only.")
