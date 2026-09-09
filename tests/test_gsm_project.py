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
    """SF_GSM_PROJECT must not be consulted in production.

    What this buys is defence against MISCONFIGURATION -- a stray SF_GSM_PROJECT
    in a profile or an inherited environment. NOT defence against an actor with
    control of the job environment: in production the project comes from the file
    named by GOOGLE_APPLICATION_CREDENTIALS, which is equally writable, and on
    the FlowForce host a job's environment IS its command string, so that actor
    already runs arbitrary code.

    An earlier version of this docstring called it "the security rule" and
    claimed the stronger property. The test is unchanged and still pins real
    behaviour; only the label was wrong. See gsm_project() in _gsm.py."""
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
