import json
import pytest
from sfsecrets import _gsm


def test_outside_production_the_env_var_wins(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_GSM_PROJECT", "some-dev-project")
    assert _gsm.gsm_project() == "some-dev-project"


def test_outside_production_an_empty_env_var_falls_back(monkeypatch):
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("SF_GSM_PROJECT", "")
    assert _gsm.gsm_project() == _gsm.DEFAULT_PROJECT


def test_in_production_the_env_var_is_IGNORED(monkeypatch, tmp_path):
    """The security rule. An actor who can set a job's environment could
    otherwise set SF_SECRET_BACKEND=gsm to satisfy the backend guard and then
    repoint the package at a project they control."""
    key = tmp_path / "sa.json"
    key.write_text(json.dumps({"type": "service_account", "project_id": "real-project"}))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setenv("SF_GSM_PROJECT", "attacker-project")
    assert _gsm.gsm_project() == "real-project"


def test_in_production_an_unparseable_key_falls_back_to_the_default(monkeypatch, tmp_path):
    key = tmp_path / "sa.json"
    key.write_text("not json at all")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    monkeypatch.setenv("SF_GSM_PROJECT", "attacker-project")
    assert _gsm.gsm_project() == _gsm.DEFAULT_PROJECT


def test_in_production_a_key_without_project_id_falls_back(monkeypatch, tmp_path):
    key = tmp_path / "sa.json"
    key.write_text(json.dumps({"type": "service_account"}))
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
    assert _gsm.gsm_project() == _gsm.DEFAULT_PROJECT
