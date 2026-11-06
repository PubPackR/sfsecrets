import os
import warnings

import pytest
import sfsecrets


def test_production_refuses_a_non_gsm_backend(tmp_path, monkeypatch):
    """A readable GOOGLE_APPLICATION_CREDENTIALS means production, and then
    only gsm is allowed. secretsR checks EXISTENCE, not readability -- a key
    the process cannot open still counts, which is why a directory at that path
    once took every dashboard down."""
    gac = tmp_path / "sa.json"
    gac.write_text("{}")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    monkeypatch.setenv("SF_SECRET_BACKEND", "env")
    monkeypatch.setenv("SF_SECRET_STUDYFLIX_POSTGRESQL_CONNECTION", "must-not-be-read")

    assert sfsecrets.is_production() is True
    with pytest.raises(RuntimeError, match="production mode"):
        sfsecrets.secret_get("studyflix-postgresql-connection")


# ---- 0.2.0: the file backend is gone ----

def test_an_unset_backend_means_gsm(monkeypatch):
    """Unset meant the file backend until 0.2.0. Every production runtime sets
    gsm explicitly, so the default matters only on a laptop or in CI."""
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setattr(sfsecrets, "secret_get_gsm", lambda n, v: "from-gsm")
    assert sfsecrets.backend() == "gsm"
    assert sfsecrets.secret_get("studyflix-test") == "from-gsm"


def test_an_empty_backend_means_gsm(monkeypatch):
    monkeypatch.setenv("SF_SECRET_BACKEND", "")
    assert sfsecrets.backend() == "gsm"


@pytest.mark.parametrize("value", ["file", "FILE"])
def test_the_removed_file_backend_is_refused_with_a_message(monkeypatch, value):
    """backend() lowercases, so FILE is the same removed backend. Callers ask
    backend() directly, so it raises there, not only in secret_get()."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", value)
    with pytest.raises(RuntimeError, match="removed in sfsecrets 0.2.0"):
        sfsecrets.backend()
    with pytest.raises(RuntimeError, match="removed in sfsecrets 0.2.0"):
        sfsecrets.secret_get("studyflix-postgresql-connection")


def test_an_unknown_backend_is_still_refused(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", "s3")
    with pytest.raises(RuntimeError, match="unknown SF_SECRET_BACKEND"):
        sfsecrets.secret_get("studyflix-test")


@pytest.mark.parametrize("kwargs", [{"key_dir": "../../keys"}, {"key": "k"},
                                    {"key_dir": "PostgreSQL_DB", "key": b"k"}])
def test_key_dir_and_key_are_ignored_with_a_deprecation_warning(monkeypatch, kwargs):
    """admanager-control and pgaccessPy pass key_dir on every call, gsm
    included. Refusing it would break them the day they move to 0.2.0, so it
    is ignored, as gsm always ignored it, and named in a DeprecationWarning."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", "gsm")
    seen = []
    monkeypatch.setattr(sfsecrets, "secret_get_gsm",
                        lambda n, v: seen.append((n, v)) or "from-gsm")
    with pytest.warns(DeprecationWarning, match="key_dir and key"):
        value = sfsecrets.secret_get("studyflix-postgresql-connection", **kwargs)
    assert value == "from-gsm"
    assert seen == [("studyflix-postgresql-connection", "latest")]


def test_no_warning_without_key_dir_or_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_BACKEND", "gsm")
    monkeypatch.setattr(sfsecrets, "secret_get_gsm", lambda n, v: "from-gsm")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert sfsecrets.secret_get("studyflix-test") == "from-gsm"


def test_the_cache_does_not_cross_backends(monkeypatch):
    """The backend is part of the cache key, as in secretsR. Before 0.2.0 it
    was not, so switching SF_SECRET_BACKEND inside a process served the other
    backend's cached value."""
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_SECRET_STUDYFLIX_TEST", "from-env")
    monkeypatch.setattr(sfsecrets, "secret_get_gsm", lambda n, v: "from-gsm")
    monkeypatch.setenv("SF_SECRET_BACKEND", "env")
    assert sfsecrets.secret_get("studyflix-test") == "from-env"
    monkeypatch.setenv("SF_SECRET_BACKEND", "gsm")
    assert sfsecrets.secret_get("studyflix-test") == "from-gsm"


def test_the_file_map_is_gone_and_the_service_names_stay():
    assert "FILES" not in sfsecrets.__all__
    assert not hasattr(sfsecrets, "FILES")
    assert sfsecrets.SERVICES == {
        "postgresql": "studyflix-postgresql-connection",
        "admanager": "studyflix-admanager-service-account",
    }


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


def test_gsm_is_routed_to_the_gsm_backend(monkeypatch):
    """secret_get must dispatch to the gsm backend, not merely accept the name."""
    monkeypatch.setenv("SF_SECRET_BACKEND", "gsm")
    monkeypatch.setattr(sfsecrets, "secret_get_gsm", lambda n, v: "from-gsm")
    assert sfsecrets.secret_get("studyflix-postgresql-connection") == "from-gsm"


def test_a_directory_at_the_credentials_path_is_production(tmp_path, monkeypatch):
    """On 2026-09-02 a misconfigured bind mount put a DIRECTORY at
    GOOGLE_APPLICATION_CREDENTIALS. os.path.exists() is True for a directory,
    so the R equivalent of this code entered production mode and refused the
    file backend -- deliberately, not an oversight. The outage happened twice,
    on two successive deploys that day, while three different designs for
    where the key lives were tried: 0400 owned by uid 997 (caught before any
    deploy by the role's own uid probe), 0700 root:root under /etc (deployed,
    failed), and /home/application-user/gsm (deployed, worked). is_production()
    must keep keying off EXISTENCE, never readability or file-ness (os.path.isfile
    / os.access), or a future refactor would silently reverse this."""
    gac = tmp_path / "sa.json"
    gac.mkdir()
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))

    assert sfsecrets.is_production() is True


@pytest.mark.skipif(
    os.name == "nt",
    reason="os.chmod cannot make a directory unreadable to its own owner on "
           "Windows, so exists() and access(R_OK) can't be forced apart here. "
           "The production host is Linux, where this guard is meaningful.",
)
def test_an_unreadable_credentials_path_is_still_production(tmp_path, monkeypatch):
    """exists() and access(R_OK) agree on an ordinary readable directory, so a
    mutation from exists() to an os.access() readability check would slip past
    every other test here undetected. An unreadable directory is the only way
    to force the two apart: exists() stays True, access(..., os.R_OK) becomes
    False. is_production() must still say True -- existence, not readability,
    is what secretsR checks and what this mirrors."""
    gac = tmp_path / "sa.json"
    gac.mkdir()
    os.chmod(gac, 0o000)
    try:
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
        assert sfsecrets.is_production() is True
    finally:
        os.chmod(gac, 0o700)
