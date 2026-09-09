"""The gsm backend: Secret Manager over REST.

Apart from _backends.py because this is the only backend with a network, a
retry policy and an authentication story. _backends.py promises "one function
per backend, no shared state"; gsm needs helpers the other two do not.

Parity with secretsR is deliberate and is not transcription. Where secretsR
works around a gap in R's tooling that Python does not have -- its hand-rolled
token cache, its file:-name guard -- the workaround is not ported. Where the
CAUSE exists in both, the behaviour is.
"""
import base64
import binascii
import json
import os
from urllib.parse import quote

DEFAULT_PROJECT = "studyflix-secrets"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TIMEOUT_SECONDS = 10
_SESSION = None


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


def _no_credentials_message():
    """Explain why authentication could not be obtained.

    google.auth raises one generic DefaultCredentialsError, so a missing key, an
    unreadable key and a malformed key are indistinguishable. Without this
    ladder every production auth failure reads as "run gcloud auth
    application-default login" -- useless on a server, and actively misleading
    when the real cause is a key this uid cannot read. Ported from secretsR,
    where the same gap exists for the same reason.

    Never contains key contents.
    """
    gac = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not gac:
        return ("no Application Default Credentials found, and "
                "GOOGLE_APPLICATION_CREDENTIALS is not set.\n"
                "On a laptop run: gcloud auth application-default login\n"
                "On a server point GOOGLE_APPLICATION_CREDENTIALS at the "
                "service-account key.")
    if not os.path.exists(gac):
        return "GOOGLE_APPLICATION_CREDENTIALS points at %r, which does not exist." % gac
    if not os.access(gac, os.R_OK):
        return ("GOOGLE_APPLICATION_CREDENTIALS %r exists but is not readable by "
                "this process (uid mismatch on a 0400 key?)." % gac)
    try:
        with open(gac, encoding="utf-8") as fh:
            parsed = json.load(fh)
    except (OSError, ValueError):
        parsed = None
    if not isinstance(parsed, dict) or "type" not in parsed:
        return ("GOOGLE_APPLICATION_CREDENTIALS %r is readable but is not valid "
                "service-account key JSON." % gac)
    return ("the service-account key at %r was rejected by Google.\n"
            "Common causes: the key was revoked or deleted, the service account "
            "is disabled, or this host's clock has drifted -- service-account "
            "auth is JWT-signed and clock-sensitive." % gac)


def _session():
    """An authorized session, built once per process.

    google.auth mints, caches and refreshes the token, and AuthorizedSession
    re-authenticates once on a 401. secretsR hand-rolls all of that because
    gargle::token_fetch() does not cache across calls -- gargle is its token
    layer, httr2 only its HTTP layer. Porting the hand-rolled cache here would
    reimplement the library and leave two things to keep correct.
    """
    global _SESSION
    if _SESSION is not None:
        return _SESSION
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError
    from google.auth.transport.requests import AuthorizedSession

    try:
        credentials, _ = google.auth.default(scopes=[SCOPE])
    except DefaultCredentialsError as exc:
        raise RuntimeError("GSM: %s" % _no_credentials_message()) from exc
    _SESSION = AuthorizedSession(credentials)
    return _SESSION


def _session_reset():
    """Drop the cached session. For tests, and for a key that changed on disk."""
    global _SESSION
    _SESSION = None


def secret_get_gsm(name, version="latest"):
    project = gsm_project()
    url = ("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s"
           "/versions/%s:access"
           % (project, quote(name, safe=""), quote(str(version), safe="")))
    response = _session().get(url, timeout=TIMEOUT_SECONDS)
    return _payload_of(response, name, version)


def _payload_of(response, name, version):
    body = response.json()
    data = (body or {}).get("payload", {}).get("data")
    if not isinstance(data, str):
        raise RuntimeError(
            "GSM: unexpected response shape for %r version %s (no payload.data)"
            % (name, version))
    # validate=True: without it, b64decode silently DISCARDS characters outside
    # the base64 alphabet and complains only about padding, so a corrupted
    # payload decodes to something plausible instead of failing. That sits badly
    # beside the NUL and UTF-8 refusals below, which exist precisely because this
    # function does not trust the payload blindly.
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(
            "GSM: secret %r version %s did not decode as base64"
            % (name, version)) from exc
    # A NUL means the value was uploaded mis-encoded -- a UTF-16 file from a
    # PowerShell redirect is how this happens -- rather than that it is binary.
    # Returning it would give the caller something other than what was stored.
    # secretsR refuses these for a SECOND reason that does not apply here:
    # rawToChar()'s error embeds the decoded bytes verbatim, putting the
    # credential into a job log. Python's decode() does not, so only the
    # correctness reason is carried across.
    if b"\x00" in raw:
        raise RuntimeError(
            "GSM: secret %r version %s contains NUL bytes; binary payloads are "
            "out of scope" % (name, version))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            "GSM: secret %r version %s is not valid UTF-8" % (name, version)) from exc
