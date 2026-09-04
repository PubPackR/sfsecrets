import pytest
import sfsecrets


def test_production_refuses_the_file_backend(tmp_path, monkeypatch):
    """A readable GOOGLE_APPLICATION_CREDENTIALS means production, and then
    only gsm is allowed. secretsR checks EXISTENCE, not readability -- a key
    the process cannot open still counts, which is why a directory at that path
    once took every dashboard down."""
    gac = tmp_path / "sa.json"
    gac.write_text("{}")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    monkeypatch.setenv("SF_SECRET_BACKEND", "file")

    assert sfsecrets.is_production() is True
    with pytest.raises(RuntimeError, match="production mode"):
        sfsecrets.secret_get("studyflix-postgresql-connection")


def test_a_missing_credentials_path_is_not_production(monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/sa.json")
    assert sfsecrets.is_production() is False


def test_the_value_is_cached_for_the_process(monkeypatch):
    """secret_get memoises with no TTL, as secretsR does. Jobs are short-lived
    so it rarely bites -- but a long-running process serves a rotated
    credential until it restarts, and the rotation runbook says so."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", "env")
    monkeypatch.setenv("SF_SECRET_STUDYFLIX_CRM_API_KEY", "first")

    assert sfsecrets.secret_get("studyflix-crm-api-key") == "first"
    monkeypatch.setenv("SF_SECRET_STUDYFLIX_CRM_API_KEY", "second")
    assert sfsecrets.secret_get("studyflix-crm-api-key") == "first"


def test_gsm_is_not_implemented_yet(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", "gsm")
    with pytest.raises(NotImplementedError, match="E2"):
        sfsecrets.secret_get("studyflix-crm-api-key")


def test_a_directory_at_the_credentials_path_is_production(tmp_path, monkeypatch):
    """On 2026-09-02 a misconfigured bind mount put a DIRECTORY at
    GOOGLE_APPLICATION_CREDENTIALS. os.path.exists() is True for a directory,
    so the R equivalent of this code entered production mode, refused the file
    backend, and could not authenticate with gsm either -- every dashboard went
    down, twice, across three attempts to fix it. That is deliberate, load-
    bearing behaviour, not an oversight: is_production() must key off EXISTENCE
    (os.path.exists), never readability or file-ness (os.path.isfile /
    os.access), or a future refactor would silently reverse the incident's
    fix and nothing would notice."""
    gac = tmp_path / "sa.json"
    gac.mkdir()
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))

    assert sfsecrets.is_production() is True
