"""The gsm backend: Secret Manager over REST.

Apart from _backends.py because this is the only backend with a network, a
retry policy and an authentication story. _backends.py promises "one function
per backend, no shared state"; gsm needs helpers the other two do not.

Parity with secretsR is deliberate and is not transcription. Where secretsR
works around a gap in R's tooling that Python does not have -- its hand-rolled
token cache, its file:-name guard -- the workaround is not ported. Where the
CAUSE exists in both, the behaviour is.
"""
import json
import os

DEFAULT_PROJECT = "studyflix-secrets"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"


def _project_from_key():
    """project_id out of the service-account key, or None."""
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not gac or not os.path.exists(gac):
        return None
    try:
        with open(gac, encoding="utf-8") as fh:
            parsed = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed.get("project_id")


def gsm_project():
    """Which project holds the secrets.

    SF_GSM_PROJECT is honoured ONLY outside production. The threat is an actor
    who can set environment variables for a job: leaving the project pointer
    configurable would let them satisfy the backend guard with
    SF_SECRET_BACKEND=gsm and then repoint the whole package at a project they
    control. The pointer must not be as writable as the switch.
    """
    from . import is_production

    if not is_production():
        return os.environ.get("SF_GSM_PROJECT", "") or DEFAULT_PROJECT
    from_key = _project_from_key()
    return from_key if from_key else DEFAULT_PROJECT
