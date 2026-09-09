import base64
import pytest
from sfsecrets import _gsm


class FakeResponse:
    def __init__(self, status_code, payload=None, body=None):
        self.status_code = status_code
        if body is not None:
            self._body = body
        else:
            data = base64.b64encode(payload.encode()).decode() if payload is not None else None
            self._body = {"payload": {"data": data}} if data is not None else {}

    def json(self):
        return self._body


class FakeSession:
    """Records the URL it was asked for, returns a canned response."""

    def __init__(self, response):
        self.response = response
        self.url = None
        self.timeout = None

    def get(self, url, timeout=None):
        self.url = url
        self.timeout = timeout
        return self.response


@pytest.fixture
def fake(monkeypatch):
    def _install(response):
        session = FakeSession(response)
        monkeypatch.setattr(_gsm, "_session", lambda: session)
        return session

    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_GSM_PROJECT", "test-project")
    return _install


def test_it_returns_the_decoded_payload(fake):
    fake(FakeResponse(200, payload='{"host":"h"}'))
    assert _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest") == '{"host":"h"}'


def test_the_version_reaches_the_url(fake):
    session = fake(FakeResponse(200, payload="v"))
    _gsm.secret_get_gsm("studyflix-postgresql-connection", "3")
    assert session.url == (
        "https://secretmanager.googleapis.com/v1/projects/test-project"
        "/secrets/studyflix-postgresql-connection/versions/3:access")


def test_the_request_is_bounded_by_a_timeout(fake):
    session = fake(FakeResponse(200, payload="v"))
    _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert session.timeout == 10


def test_a_response_without_payload_data_is_refused(fake):
    fake(FakeResponse(200, body={"nothing": "useful"}))
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_null_payload_hits_the_shape_check_not_AttributeError(fake):
    """(body or {}).get("payload", {}).get("data") raises AttributeError when
    payload is None, bypassing the function's own "unexpected response shape"
    message. {"payload": null} is a real shape Secret Manager can return."""
    fake(FakeResponse(200, body={"payload": None}))
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_string_payload_hits_the_shape_check_not_AttributeError(fake):
    """Same bug, other real shape: {"payload": "x"} -- a string has no .get()."""
    fake(FakeResponse(200, body={"payload": "x"}))
    with pytest.raises(RuntimeError, match="unexpected response shape"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_payload_containing_NUL_is_refused(fake):
    """A NUL means the value was uploaded mis-encoded -- a UTF-16 file from a
    PowerShell redirect is how this happens -- not that it is binary. Returning
    it would hand the caller something other than what was stored."""
    fake(FakeResponse(200, payload="abc\x00def"))
    with pytest.raises(RuntimeError, match="NUL"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_non_utf8_payload_is_refused(fake):
    body = {"payload": {"data": base64.b64encode(b"\xff\xfe not utf-8").decode()}}
    fake(FakeResponse(200, body=body))
    with pytest.raises(RuntimeError, match="not valid UTF-8"):
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")


def test_a_non_utf8_payload_does_not_chain_the_original_exception(fake):
    """I1: UnicodeDecodeError.args and repr() embed the decoded bytes verbatim
    (unlike str(exc)), so `raise ... from exc` would keep the secret reachable
    on __cause__ for any logger that serialises exception.args or logs %r of
    __cause__. The fix is `from None`; a revert to `from exc` must fail this."""
    payload = b"SUPERSECRETPASSWORD\xff"
    body = {"payload": {"data": base64.b64encode(payload).decode()}}
    fake(FakeResponse(200, body=body))
    with pytest.raises(RuntimeError) as err:
        _gsm.secret_get_gsm("studyflix-postgresql-connection", "latest")
    assert err.value.__cause__ is None
    assert err.value.__suppress_context__ is True


def test_the_name_is_url_encoded(fake):
    session = fake(FakeResponse(200, payload="v"))
    _gsm.secret_get_gsm("weird/name", "latest")
    assert "weird%2Fname" in session.url
