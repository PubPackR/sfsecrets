"""_session()'s own body -- every other gsm test monkeypatches _session
wholesale (see with_session/fake fixtures elsewhere), so its actual
construction -- the retry-adapter mount, the DefaultCredentialsError mapping
-- had zero coverage. Mutation-proven: deleting the HTTPAdapter mount line
left the suite fully green at 41 passed.

Fully offline: only google.auth.default is faked. AuthorizedSession itself is
REAL, but constructing one makes no network call -- it only calls the network
when a request method (.get/.post/...) is actually invoked, which nothing
here does.
"""
import pytest
from google.auth.credentials import AnonymousCredentials
from google.auth.exceptions import DefaultCredentialsError
from sfsecrets import _gsm


@pytest.fixture(autouse=True)
def _reset_session():
    """Must not leak the session built here into other tests, nor pick up a
    session another test left cached."""
    _gsm._session_reset()
    yield
    _gsm._session_reset()


def test_session_mounts_a_retry_adapter_with_total_3(monkeypatch):
    monkeypatch.setattr("google.auth.default",
                         lambda scopes: (AnonymousCredentials(), None))
    session = _gsm._session()
    adapter = session.get_adapter("https://secretmanager.googleapis.com/")
    assert adapter.max_retries.total == 3


def test_no_default_credentials_raises_runtime_error_with_the_diagnostic_ladder(monkeypatch):
    """Covers _session()'s DefaultCredentialsError -> RuntimeError mapping,
    also previously untested since every other test monkeypatches _session
    away entirely."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)

    def _raise(scopes):
        raise DefaultCredentialsError("no ADC found")

    monkeypatch.setattr("google.auth.default", _raise)

    with pytest.raises(RuntimeError) as err:
        _gsm._session()
    assert "GOOGLE_APPLICATION_CREDENTIALS is not set" in str(err.value)
    assert "gcloud auth application-default login" in str(err.value)
