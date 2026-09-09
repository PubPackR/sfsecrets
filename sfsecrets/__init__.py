"""Credential resolution for Studyflix Python apps -- the twin of secretsR.

Resolution only. It knows nothing about databases or Ad Manager: shaping and
connecting belong to pgaccessPy and admanager_auth, one layer up.

Vendored as a git submodule, never pip-installed -- the FlowForce host runs no
dependency-installation step and the deploy only rsyncs files.
"""
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


def secret_get(name, version="latest", key_dir=None):
    """Resolve one secret by its NAME -- the same name secretsR uses.

    `key_dir` is honoured by the file backend only, and is an argument rather
    than process state so two callers with different key directories cannot
    silently share one. It disappears with the transitional wrapper in E3.
    """
    key = (name, version, key_dir)
    if key in _CACHE:
        return _CACHE[key]

    chosen = backend()
    if is_production() and chosen != "gsm":
        raise RuntimeError(
            "this host is in production mode, so the %r backend is refused. "
            "Set SF_SECRET_BACKEND=gsm." % chosen)

    if chosen == "file":
        value = secret_get_file(name, key_dir, version)
    elif chosen == "env":
        value = secret_get_env(name)
    elif chosen == "gsm":
        value = secret_get_gsm(name, version)
    else:
        raise RuntimeError("unknown SF_SECRET_BACKEND: %r" % chosen)

    _CACHE[key] = value
    return value


def secret_cache_clear():
    """Drop every cached value. The rotation runbook's answer for a
    long-running process that must pick up a new version without restarting.
    """
    _CACHE.clear()
