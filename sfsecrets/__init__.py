"""Credential resolution for Studyflix Python apps -- the twin of secretsR.

Resolution only. It knows nothing about databases or Ad Manager: shaping and
connecting belong to pgaccessPy and admanager_auth, one layer up.

Vendored as a git submodule, never pip-installed -- the FlowForce host runs no
dependency-installation step and the deploy only rsyncs files.
"""
import hashlib
import os

from ._backends import secret_get_env, secret_get_file
from ._gsm import secret_get_gsm
from ._legacy_map import FILES, SERVICES

__all__ = ["secret_get", "secret_cache_clear", "backend", "is_production",
           "SERVICES", "FILES"]

_CACHE = {}


def is_production():
    """True when this host must not read keys/ at all.

    Mirrors secretsR: the marker file, or GOOGLE_APPLICATION_CREDENTIALS naming
    a file that EXISTS -- existence, not readability, exactly as R checks it.
    """
    if os.path.exists("/etc/studyflix/production"):
        return True
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    return bool(gac) and os.path.exists(gac)


def backend():
    return os.environ.get("SF_SECRET_BACKEND", "file").lower()


def secret_get(name, version="latest", key_dir=None, key=None):
    """Resolve one secret by its NAME -- the same name secretsR uses.

    `key_dir` is honoured by the file backend only, and is an argument rather
    than process state so two callers with different key directories cannot
    silently share one. E3 adds `key` beside it, below, for the same reason
    and in the same shape -- key_dir does not disappear.

    `key` is the file backend's decrypt key, also an argument rather than
    process state -- see _backends._fernet_for. A hash of it (never the key
    itself) is folded into the cache key below, so a second call for the same
    name with a DIFFERENT key cannot be served the first call's value. This
    reverses what an earlier draft of this function did (leaving `key` out of
    the cache key entirely) -- overruled once review pointed at secretsR's own
    digest_key(), the same defence for the same failure class: "Two colliding
    keys shared one cache slot, so the second caller received the first
    caller's credential with no error."
    """
    if isinstance(key, bytes):
        key = key.decode()
    # `cache_key`, not `key`: the parameter above is the DECRYPT key. An earlier
    # draft of this plan added the parameter and left this local named `key`,
    # which silently shadowed it and passed a tuple to Fernet. The key's own
    # digest -- never the key -- is one of the tuple's elements, not the whole
    # of it: the cache is still keyed by what was asked for, with a digest
    # appended for what the caller proved it may have.
    cache_key = (name, version, key_dir,
                 hashlib.sha256(key.encode()).hexdigest() if key else "")
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    chosen = backend()
    if is_production() and chosen != "gsm":
        raise RuntimeError(
            "this host is in production mode, so the %r backend is refused. "
            "Set SF_SECRET_BACKEND=gsm." % chosen)

    if chosen == "file":
        value = secret_get_file(name, key_dir=key_dir, version=version, key=key)
    elif chosen == "env":
        value = secret_get_env(name)
    elif chosen == "gsm":
        value = secret_get_gsm(name, version)
    else:
        raise RuntimeError("unknown SF_SECRET_BACKEND: %r" % chosen)

    _CACHE[cache_key] = value
    return value


def secret_cache_clear():
    """Drop every cached value. The rotation runbook's answer for a
    long-running process that must pick up a new version without restarting.
    """
    _CACHE.clear()
