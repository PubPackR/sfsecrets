"""Credential resolution for Studyflix Python apps -- the twin of secretsR.

Resolution only. It knows nothing about databases or Ad Manager: shaping and
connecting belong to pgaccessPy and admanager_auth, one layer up.

Vendored as a git submodule, never pip-installed -- the FlowForce host runs no
dependency-installation step and the deploy only rsyncs files.

0.2.0 removed the file backend (Plan F). Every runtime resolves from Secret
Manager; `env` stays for tests and break-glass.
"""
import os
import warnings

from ._backends import secret_get_env
from ._gsm import secret_get_gsm
from ._names import SERVICES

__all__ = ["secret_get", "secret_cache_clear", "backend", "is_production",
           "SERVICES"]

_CACHE = {}

_BACKENDS = ("gsm", "env")


def is_production():
    """True when this host may use no backend but gsm.

    Mirrors secretsR: the marker file, or GOOGLE_APPLICATION_CREDENTIALS naming
    a file that EXISTS -- existence, not readability, exactly as R checks it.
    """
    if os.path.exists("/etc/studyflix/production"):
        return True
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    return bool(gac) and os.path.exists(gac)


def backend():
    """The backend this process uses, from SF_SECRET_BACKEND.

    Unset or empty means gsm since 0.2.0; before, it meant the file backend.
    Every production runtime sets gsm explicitly, and production refuses any
    other backend anyway, so the default matters only on a laptop or in CI.

    "file" raises here rather than in secret_get(), because callers ask this
    directly (admanager_auth's `backend() == "file"`), and a profile still
    naming the removed backend should say what happened. Any other unknown
    value is returned as before and refused by secret_get().
    """
    chosen = os.environ.get("SF_SECRET_BACKEND", "").lower() or "gsm"
    if chosen == "file":
        raise RuntimeError(
            "SF_SECRET_BACKEND=file: the file backend was removed in sfsecrets "
            "0.2.0. Set SF_SECRET_BACKEND=gsm, or unset it.")
    return chosen


def secret_get(name, version="latest", key_dir=None, key=None):
    """Resolve one secret by its NAME -- the same name secretsR uses.

    `key_dir` and `key` belonged to the file backend, which 0.2.0 removed. They
    stay accepted for this release only, because callers pass `key_dir` on
    every call, gsm included, where it never had an effect: admanager-control's
    credential_manager and admanager_auth (which also passes `key`), and
    pgaccessPy's credentials. Refusing them would force sfsecrets, pgaccessPy
    and both admanager folders to change in one step. So they are ignored,
    exactly as gsm and env always ignored them, and a DeprecationWarning names
    them: pytest shows it, a job's log stays quiet. They go in the next release.
    """
    if key_dir is not None or key is not None:
        warnings.warn(
            "sfsecrets.secret_get(): key_dir and key belonged to the file "
            "backend, which sfsecrets 0.2.0 removed. They are ignored; drop "
            "them, they go in the next release.",
            DeprecationWarning, stacklevel=2)

    chosen = backend()
    if is_production() and chosen != "gsm":
        raise RuntimeError(
            "this host is in production mode, so the %r backend is refused. "
            "Set SF_SECRET_BACKEND=gsm." % chosen)
    if chosen not in _BACKENDS:
        raise RuntimeError("unknown SF_SECRET_BACKEND: %r" % chosen)

    # The backend is part of the cache key, as in secretsR: switching
    # SF_SECRET_BACKEND inside one process must not serve the other backend's
    # value. key_dir and key are not part of it any more, because they no
    # longer change what a name resolves to.
    cache_key = (chosen, name, version)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    if chosen == "env":
        value = secret_get_env(name)
    else:
        value = secret_get_gsm(name, version)

    _CACHE[cache_key] = value
    return value


def secret_cache_clear():
    """Drop every cached value. The rotation runbook's answer for a
    long-running process that must pick up a new version without restarting.
    """
    _CACHE.clear()
