import base64, hashlib, json
import pytest
from cryptography.fernet import Fernet
import sfsecrets


def test_file_backend_joins_the_legacy_pair_into_one_object(tmp_path, monkeypatch):
    """DB_MASTER_KEY is DERIVED, not used verbatim -- base64(sha256(key)).
    ADMANAGER_DECRYPT_KEY is the opposite and is tested separately. Confusing
    the two is what broke the first E0 run.

    And postgresql is TWO legacy files behind ONE secret name. The backend joins
    them into the object the gsm backend returns for that name, which is what
    makes the two comparable in E2 rather than merely both working.
    """
    master = "the-master-password"
    fkey = base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest())
    cipher = Fernet(fkey)

    keydir = tmp_path / "keys" / "PostgreSQL_DB"
    keydir.mkdir(parents=True)
    (keydir / "postgresql_server_python.txt").write_bytes(cipher.encrypt(
        json.dumps({"host": "h", "port": "5432",
                    "dbname": "db", "user": "u"}).encode()))
    (keydir / "postgresql_key_python.txt").write_bytes(cipher.encrypt(b"pw"))

    monkeypatch.setenv("DB_MASTER_KEY", master)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)

    got = json.loads(sfsecrets.secret_get(
        "studyflix-postgresql-connection", key_dir=str(tmp_path / "keys")))
    assert got == {"host": "h", "port": "5432", "dbname": "db",
                   "user": "u", "password": "pw"}


def test_two_key_dirs_in_one_process_do_not_share(tmp_path, monkeypatch):
    """The bug review found in the first draft: key_dir arrived through
    os.environ.setdefault, so the second caller silently got the first's
    credentials -- wrong host, wrong database, no error."""
    master = "m"
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest()))
    monkeypatch.setenv("DB_MASTER_KEY", master)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)

    for host in ("first", "second"):
        d = tmp_path / host / "PostgreSQL_DB"
        d.mkdir(parents=True)
        (d / "postgresql_server_python.txt").write_bytes(cipher.encrypt(
            json.dumps({"host": host, "port": "5432",
                        "dbname": "d", "user": "u"}).encode()))
        (d / "postgresql_key_python.txt").write_bytes(cipher.encrypt(b"pw"))

    a = json.loads(sfsecrets.secret_get(
        "studyflix-postgresql-connection", key_dir=str(tmp_path / "first")))
    b = json.loads(sfsecrets.secret_get(
        "studyflix-postgresql-connection", key_dir=str(tmp_path / "second")))
    assert a["host"] == "first" and b["host"] == "second"
