"""One function per backend. No shared state, no cross-calls.

Only the env backend lives here: gsm has its own module (_gsm.py), and 0.2.0
removed the file backend.
"""
import os


def secret_get_env(name):
    var = "SF_SECRET_" + name.replace("-", "_").upper()
    if var not in os.environ:
        raise KeyError("%s is not set" % var)
    return os.environ[var]
