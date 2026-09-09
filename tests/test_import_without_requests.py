"""Finding 6: `import sfsecrets` must not require requests or urllib3.

_gsm.py's own comment says the module "must stay importable on the file
path", where google-auth (and, transitively, requests/urllib3) may not even
be installed -- the file backend needs only cryptography. Verified with an
import blocker: before the E2 gsm-backend work, blocking requests or urllib3
still imported fine; a module-level `import requests` in _gsm.py made both
fail on this branch. requests is used ONLY inside secret_get_gsm's except
clauses (and google.auth's own transport, which is imported lazily inside
_session()), so it must be imported lazily there too -- exactly like the
existing lazy `from google.auth.exceptions import RefreshError` a few lines
below it.
"""
import importlib
import sys


class _Blocker:
    """A meta path finder that fails any import of the given top-level
    package names, simulating a host where they are simply not installed."""

    def __init__(self, blocked_top_names):
        self.blocked_top_names = blocked_top_names

    def find_spec(self, name, path, target=None):
        if name.split(".")[0] in self.blocked_top_names:
            raise ImportError("%r is blocked for this test" % name)
        return None


def test_the_package_imports_with_requests_and_urllib3_absent():
    blocked = {"requests", "urllib3"}
    affected = {"sfsecrets"} | blocked

    # Drop any already-imported copies so the blocker is actually exercised,
    # and so a module cached from an earlier test (with requests already
    # resolved inside it) can't hide a regression here.
    saved = {name: mod for name, mod in sys.modules.items()
             if name.split(".")[0] in affected}
    for name in saved:
        del sys.modules[name]

    blocker = _Blocker(blocked)
    sys.meta_path.insert(0, blocker)
    try:
        import sfsecrets  # noqa: F401 -- the import itself is the assertion
        importlib.import_module("sfsecrets._gsm")
        importlib.import_module("sfsecrets._backends")
    finally:
        sys.meta_path.remove(blocker)
        for name in list(sys.modules):
            if name.split(".")[0] in affected:
                del sys.modules[name]
        sys.modules.update(saved)
