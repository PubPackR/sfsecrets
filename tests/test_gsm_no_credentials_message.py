"""Every branch of _no_credentials_message().

A reviewer once replaced the entire function body with a constant string and
the suite still passed -- zero tests observed any branch. These pin each one
to a distinctive fragment, not the full string, since these are diagnostics
and will be reworded.
"""
import json
import os

import pytest
from sfsecrets import _gsm


def test_unset_points_at_adc_and_gcloud_login(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    msg = _gsm._no_credentials_message()
    assert "GOOGLE_APPLICATION_CREDENTIALS is not set" in msg
    assert "gcloud auth application-default login" in msg


def test_nonexistent_path_says_it_does_not_exist(monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/sa.json")
    msg = _gsm._no_credentials_message()
    assert "does not exist" in msg
    assert "/nonexistent/sa.json" in msg


@pytest.mark.skipif(
    os.name == "nt",
    reason="os.chmod cannot make a file unreadable to its own owner on "
           "Windows, so exists() and access(R_OK) can't be forced apart here. "
           "The production host is Linux, where this branch is meaningful. "
           "See test_secret_get.py::test_an_unreadable_credentials_path_is_still_production "
           "for the existing POSIX-only precedent for this same limitation.",
)
def test_an_unreadable_file_says_uid_mismatch(monkeypatch, tmp_path):
    gac = tmp_path / "sa.json"
    gac.write_text(json.dumps({"type": "service_account"}))
    os.chmod(gac, 0o000)
    try:
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
        msg = _gsm._no_credentials_message()
        assert "not readable by this process" in msg
        assert "uid mismatch" in msg
    finally:
        os.chmod(gac, 0o600)


def test_not_valid_json_says_so(monkeypatch, tmp_path):
    gac = tmp_path / "sa.json"
    gac.write_text("not json at all")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    msg = _gsm._no_credentials_message()
    assert "not valid" in msg
    assert "service-account key JSON" in msg


def test_valid_json_with_no_type_key_says_not_valid_key_json(monkeypatch, tmp_path):
    gac = tmp_path / "sa.json"
    gac.write_text(json.dumps({"project_id": "p"}))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    msg = _gsm._no_credentials_message()
    assert "not valid" in msg
    assert "service-account key JSON" in msg


def test_service_account_key_missing_client_email_names_the_field(monkeypatch, tmp_path):
    """I2b: google.auth.default() wraps the ValueError that
    from_service_account_info() raises for a missing required field into the
    same generic DefaultCredentialsError as every other cause -- so before this
    branch existed, a locally malformed key fell through to the final
    "rejected by Google" branch, which is false: Google never saw it."""
    gac = tmp_path / "sa.json"
    gac.write_text(json.dumps({
        "type": "service_account",
        "token_uri": "https://oauth2.googleapis.com/token",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        # client_email deliberately omitted
    }))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    msg = _gsm._no_credentials_message()
    assert "missing required field" in msg
    assert "client_email" in msg
    assert "never sent to Google" in msg
    assert "rejected by Google" not in msg


def test_structurally_complete_key_falls_back_to_rejected_by_google(monkeypatch, tmp_path):
    """The genuine fallback: a key with every required field present reads as
    structurally fine, so a Google-side rejection (revoked, disabled SA, clock
    drift) is the remaining explanation."""
    gac = tmp_path / "sa.json"
    gac.write_text(json.dumps({
        "type": "service_account",
        "client_email": "sa@project.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
        "private_key": "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
    }))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(gac))
    msg = _gsm._no_credentials_message()
    assert "was rejected by Google" in msg
    assert "clock has drifted" in msg
