import base64
import pytest
import requests
from sfsecrets import _gsm


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        data = base64.b64encode(payload.encode()).decode() if payload is not None else None
        self._body = {"payload": {"data": data}} if data is not None else {}

    def json(self):
        return self._body


class StatusSession:
    def __init__(self, response=None, raises=None):
        self.response = response
        self.raises = raises

    def get(self, url, timeout=None):
        if self.raises is not None:
            raise self.raises
        return self.response


@pytest.fixture
def with_session(monkeypatch):
    def _install(session):
        monkeypatch.setattr(_gsm, "_session", lambda: session)

    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_GSM_PROJECT", "test-project")
    return _install


def test_403_names_the_role_and_the_project(with_session):
    with_session(StatusSession(FakeResponse(403)))
    with pytest.raises(RuntimeError) as err:
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert "roles/secretmanager.secretAccessor" in str(err.value)
    assert "test-project" in str(err.value)


def test_404_names_the_secret_and_the_version(with_session):
    with_session(StatusSession(FakeResponse(404)))
    with pytest.raises(RuntimeError) as err:
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "7")
    assert "studyflix-postgresql-connection" in str(err.value)
    assert "7" in str(err.value)


def test_401_says_authentication_was_rejected(with_session):
    with_session(StatusSession(FakeResponse(401)))
    with pytest.raises(RuntimeError, match="authentication"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_401_discards_the_cached_session(with_session, monkeypatch):
    """The 401 handler must drop the module-level session cache so the next
    call re-authenticates, rather than reusing the same rejected session."""
    monkeypatch.setattr(_gsm, "_SESSION", object())
    with_session(StatusSession(FakeResponse(401)))
    with pytest.raises(RuntimeError):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert _gsm._SESSION is None


def test_400_explains_the_disabled_latest_version_trap(with_session):
    """'latest' resolves to the highest version number regardless of state, so a
    disabled newest version fails rather than falling back to the one below."""
    with_session(StatusSession(FakeResponse(400)))
    with pytest.raises(RuntimeError, match="pin an explicit version"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_an_exhausted_5xx_names_the_secret_not_just_the_status(with_session):
    with_session(StatusSession(FakeResponse(500)))
    with pytest.raises(RuntimeError) as err:
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert "studyflix-postgresql-connection" in str(err.value)
    assert "500" in str(err.value)


def test_a_connection_failure_says_check_network_and_dns(with_session):
    with_session(StatusSession(raises=requests.exceptions.ConnectionError("boom")))
    with pytest.raises(RuntimeError, match="network and DNS"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_refresh_error_names_the_secret_and_the_project(with_session):
    """I2a: RefreshError is raised from credentials.before_request() inside
    AuthorizedSession.request, BEFORE any HTTP call is made -- so it is neither
    a ConnectionError nor a Timeout and would otherwise propagate raw, naming
    neither the secret nor the project. Covers a revoked/deleted key, a
    disabled service account, or host clock drift."""
    from google.auth.exceptions import RefreshError

    with_session(StatusSession(raises=RefreshError("invalid_grant")))
    with pytest.raises(RuntimeError) as err:
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert "studyflix-postgresql-connection" in str(err.value)
    assert "test-project" in str(err.value)
    assert "revoked" in str(err.value)


def test_the_retry_policy_covers_transient_statuses_and_not_403():
    """Asserts the CONFIGURATION. See the plan's self-review: the fake session
    bypasses the adapter the policy is mounted on, so this pins the values, not
    the effect."""
    retry = _gsm._retry_policy()
    assert retry.total == 3
    assert set(retry.status_forcelist) == {408, 429, 500, 502, 503, 504}
    assert 403 not in retry.status_forcelist
    assert list(retry.allowed_methods) == ["GET"]
    assert retry.raise_on_status is False
