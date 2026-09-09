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
RETRY_STATUSES = (408, 429, 500, 502, 503, 504)
_SESSION = None
_UNSET = object()  # marks "no value produced" without attaching implicit
                    # exception context -- see _payload_of.


def _retry_policy():
    """Retries transient statuses and connection failures, on top of the
    initial request.

    Safe ONLY because versions/{v}:access is an idempotent GET. Do not copy this
    policy to a mutating call.

    raise_on_status=False so an exhausted 5xx comes back as a response and can be
    mapped to a message naming the secret; urllib3's own RetryError names neither
    the secret nor the status, which is useless in a job resolving several. The
    worst case is bounded by arithmetic rather than a total-time setting, which
    urllib3 does not offer: total=3 permits 3 retries IN ADDITION TO the initial
    request, so 4 attempts at a 10s timeout plus backoff sleeps of 0s, 2s and 4s
    is roughly 46 seconds.
    """
    from urllib3.util.retry import Retry

    return Retry(total=3, backoff_factor=1, status_forcelist=list(RETRY_STATUSES),
                 allowed_methods=["GET"], raise_on_status=False)


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

    SF_GSM_PROJECT is honoured ONLY outside production; in production it is
    neutralised in favour of _project_from_key(). That is defence against
    MISCONFIGURATION, not against an actor with control of the job's
    environment: _project_from_key() reads the file named by
    GOOGLE_APPLICATION_CREDENTIALS, an environment variable of exactly the
    same writability as SF_SECRET_BACKEND. Someone who can set one can set the
    other. On this host such an actor can also edit the command itself, so
    they are not meaningfully constrained by this function either way --
    pinning the compiled-in DEFAULT_PROJECT in production would close that,
    and is deferred as cleanup rather than treated as a fix here.
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
    if parsed.get("type") == "service_account":
        # google.auth.default() wraps the ValueError that
        # from_service_account_info() raises for a missing/garbled required
        # field into the same generic DefaultCredentialsError as every other
        # cause here -- so a key that is valid JSON with the right "type" but a
        # missing client_email/token_uri or a garbled private_key would
        # otherwise fall through to the "rejected by Google" branch below,
        # which is wrong: Google never saw this key, it never left the host.
        missing = [field for field in ("client_email", "token_uri", "private_key")
                   if not parsed.get(field)]
        if missing:
            return ("the service-account key at %r is missing required field(s): "
                    "%s. This is a locally malformed key -- it was never sent to "
                    "Google." % (gac, ", ".join(missing)))
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
    from requests.adapters import HTTPAdapter

    try:
        credentials, _ = google.auth.default(scopes=[SCOPE])
    except DefaultCredentialsError as exc:
        raise RuntimeError("GSM: %s" % _no_credentials_message()) from exc
    _SESSION = AuthorizedSession(credentials)
    _SESSION.mount("https://", HTTPAdapter(max_retries=_retry_policy()))
    return _SESSION


def _session_reset():
    """Drop the cached session. For tests, and for a key that changed on disk."""
    global _SESSION
    _SESSION = None


def secret_get_gsm(name, version="latest"):
    # Deferred, matching _session()'s own lazy google.auth imports: the module
    # must stay importable on the file path, where google-auth may not even be
    # what's on the host's Python path. requests is deferred for the same
    # reason -- it is used here ONLY for these two exception classes, and the
    # file backend must not drag in requests/urllib3 as a hard import-time
    # dependency.
    import requests
    from google.auth.exceptions import RefreshError, TransportError

    project = gsm_project()
    url = ("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s"
           "/versions/%s:access"
           % (project, quote(name, safe=""), quote(str(version), safe="")))
    try:
        response = _session().get(url, timeout=TIMEOUT_SECONDS)
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            "GSM: could not reach Secret Manager for %r after retries (%s). "
            "Check network and DNS from this host." % (name, exc)) from exc
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            "GSM: request for %r timed out after retries. Check network and DNS "
            "from this host." % name) from exc
    except RefreshError as exc:
        # Raised by credentials.before_request() inside AuthorizedSession.request,
        # BEFORE any HTTP call -- so it is neither a ConnectionError nor a
        # Timeout and would otherwise propagate raw, naming neither the secret
        # nor the project. A real Google-side rejection of the credentials
        # themselves: a revoked/deleted key, a disabled service account, or
        # host clock drift (service-account auth is JWT-signed and
        # clock-sensitive).
        raise RuntimeError(
            "GSM: authentication was refreshed but rejected by Google for %r "
            "in project %r. Common causes: the key was revoked or deleted, the "
            "service account is disabled, or this host's clock has drifted."
            % (name, project)) from exc
    except TransportError as exc:
        # Also raised from credentials.before_request() during the pre-request
        # token refresh, BEFORE any HTTP call to Secret Manager -- but unlike
        # RefreshError this is NOT Google rejecting the credentials. It is
        # google-auth's own requests.Session (internal to the token refresh,
        # separate from _session()'s AuthorizedSession) wrapping a
        # requests.exceptions.RequestException it hit while reaching
        # oauth2.googleapis.com. TransportError subclasses GoogleAuthError, not
        # requests.exceptions.*, so it is caught neither by the ConnectionError
        # nor the Timeout handler above and would otherwise propagate raw,
        # naming neither the secret nor the project. The fix is a network
        # problem reaching the TOKEN endpoint, not Secret Manager itself.
        raise RuntimeError(
            "GSM: could not reach the token endpoint (oauth2.googleapis.com) "
            "while refreshing credentials for %r in project %r (%s). Check "
            "network and DNS from this host." % (name, project, exc)) from exc

    status = response.status_code
    if status == 401:
        _session_reset()
        raise RuntimeError(
            "GSM: authentication rejected for %r. The session has been discarded; "
            "the next call will re-authenticate. %s"
            % (name, _no_credentials_message()))
    if status == 403:
        raise RuntimeError(
            "GSM: access denied for %r in project %r. The calling principal needs "
            "roles/secretmanager.secretAccessor on this secret." % (name, project))
    if status == 404:
        raise RuntimeError(
            "GSM: secret %r (version %s) not found in project %r."
            % (name, version, project))
    if status == 400:
        raise RuntimeError(
            "GSM: bad request for %r version %s. If the newest version is "
            "disabled, 'latest' fails -- pin an explicit version."
            % (name, version))
    if status != 200:
        raise RuntimeError(
            "GSM: request for %r version %s failed after retries with HTTP %s in "
            "project %r. Check the Secret Manager service status."
            % (name, version, status, project))
    return _payload_of(response, name, version)


def _payload_of(response, name, version):
    body = _UNSET
    try:
        body = response.json()
    except ValueError:
        # requests raises RequestsJSONDecodeError here, which subclasses
        # ValueError (not ConnectionError or Timeout, so it would otherwise
        # escape secret_get_gsm's handler ladder unprefixed and unnamed). Its
        # .doc attribute holds the ENTIRE response body -- on a 200 that is
        # malformed mid-flight, that body contains payload.data, the base64 of
        # the credential.
        #
        # `from None` alone is NOT enough: it clears __cause__ and sets
        # __suppress_context__ so Python's own traceback printer stays quiet,
        # but it does not clear __context__ -- Python attaches that the moment
        # a `raise` executes lexically inside an active except block,
        # regardless of any `from` clause. Anything that walks __context__
        # directly instead of going through the traceback formatter --
        # Sentry-style exception capture, structured JSON logging -- still
        # reaches .doc and the credential inside it. Verified directly against
        # this exact shape (see tests/test_gsm_errors.py).
        #
        # The only complete fix is to raise OUTSIDE the except block, below,
        # where there is no active exception for Python to attach at all.
        pass
    if body is _UNSET:
        raise RuntimeError(
            "GSM: response for %r version %s was not JSON" % (name, version))
    payload = (body or {}).get("payload")
    data = payload.get("data") if isinstance(payload, dict) else None
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
    decoded = _UNSET
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        # str(exc) is clean, but exc.args and repr(exc) embed the decoded
        # bytes verbatim (e.g. args = ('utf-8', b'...secret...', 19, 20,
        # 'invalid start byte')). `from None` clears __cause__ and
        # __suppress_context__ but NOT __context__ -- Python attaches that to
        # any `raise` executed lexically inside this except block regardless
        # of the `from` clause, and anything walking __context__ directly
        # (Sentry-style capture, structured JSON logging) would still reach
        # args and repr(). So the raise happens OUTSIDE this except block,
        # below, where no exception is active for Python to attach.
        pass
    if decoded is _UNSET:
        raise RuntimeError(
            "GSM: secret %r version %s is not valid UTF-8" % (name, version))
    return decoded
