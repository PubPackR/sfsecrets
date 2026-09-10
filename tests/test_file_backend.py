import base64, hashlib, json
import pytest
from cryptography.fernet import Fernet
import sfsecrets
import sfsecrets._backends as backends


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


def test_a_three_file_secret_refuses_instead_of_silently_dropping_a_part(tmp_path, monkeypatch):
    """The join rule in _join_legacy_parts only knows one shape: exactly 2
    files, a JSON object plus a trailing password. A hypothetical 3-file
    secret must not silently return an object built from only the first 2
    parts with the 3rd dropped -- it must refuse with a clear error, since
    nothing else would ever surface the missing part."""
    master = "m3"
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest()))
    d = tmp_path / "Three_Part"
    d.mkdir(parents=True)
    (d / "a.txt").write_bytes(cipher.encrypt(json.dumps({"x": 1}).encode()))
    (d / "b.txt").write_bytes(cipher.encrypt(b"part-b"))
    (d / "c.txt").write_bytes(cipher.encrypt(b"part-c"))

    monkeypatch.setenv("DB_MASTER_KEY", master)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    monkeypatch.setitem(backends.FILES, "test-three-part-secret", (
        ("Three_Part/a.txt", "Three_Part/b.txt", "Three_Part/c.txt"),
        "derived", "DB_MASTER_KEY"))

    with pytest.raises(RuntimeError, match="exactly 2 legacy files"):
        sfsecrets.secret_get("test-three-part-secret", key_dir=str(tmp_path))


def test_a_two_file_secret_whose_first_part_is_not_json_refuses_clearly(tmp_path, monkeypatch):
    """If the first of the 2 files does not decode to a JSON object, merging a
    password into it makes no sense -- refuse rather than raise a bare
    json.JSONDecodeError (or, worse, succeed with a wrong shape)."""
    master = "m4"
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest()))
    d = tmp_path / "Not_Json"
    d.mkdir(parents=True)
    (d / "a.txt").write_bytes(cipher.encrypt(b"not-json-at-all"))
    (d / "b.txt").write_bytes(cipher.encrypt(b"password"))

    monkeypatch.setenv("DB_MASTER_KEY", master)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    monkeypatch.setitem(backends.FILES, "test-non-json-secret", (
        ("Not_Json/a.txt", "Not_Json/b.txt"),
        "derived", "DB_MASTER_KEY"))

    with pytest.raises(RuntimeError, match="JSON object"):
        sfsecrets.secret_get("test-non-json-secret", key_dir=str(tmp_path))


def test_a_non_json_first_part_does_not_leak_the_decrypted_plaintext_via_cause(tmp_path, monkeypatch):
    """Finding 3: json.JSONDecodeError sets .doc to the string it failed to
    parse -- here the DECRYPTED contents of the first legacy file. `from exc`
    would keep that exception reachable as __cause__, so a structured logger
    serialising __cause__.doc (or vars(__cause__)) would write the decrypted
    plaintext to a log even though str(e) stays clean. (The password itself is
    parts[1] and is never in .doc -- this is connection metadata, not the
    credential -- but it must not leak either.)

    `from None` alone is NOT enough: it clears __cause__ and sets
    __suppress_context__, but __context__ still points at the original
    JSONDecodeError -- reachable by anything that walks __context__ directly
    instead of going through the traceback formatter (Sentry-style capture,
    structured JSON logging). The fix moves the raise outside the except
    block entirely, so __context__ is None too -- assert all three."""
    master = "m5"
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(master.encode()).digest()))
    d = tmp_path / "Not_Json_Cause"
    d.mkdir(parents=True)
    plaintext_secret_marker = "definitely-not-json-but-secret-looking-h0st"
    (d / "a.txt").write_bytes(cipher.encrypt(plaintext_secret_marker.encode()))
    (d / "b.txt").write_bytes(cipher.encrypt(b"password"))

    monkeypatch.setenv("DB_MASTER_KEY", master)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    monkeypatch.setitem(backends.FILES, "test-non-json-cause-secret", (
        ("Not_Json_Cause/a.txt", "Not_Json_Cause/b.txt"),
        "derived", "DB_MASTER_KEY"))

    with pytest.raises(RuntimeError) as err:
        sfsecrets.secret_get("test-non-json-cause-secret", key_dir=str(tmp_path))
    assert err.value.__cause__ is None
    assert err.value.__context__ is None
    assert plaintext_secret_marker not in str(err.value)


def test_the_file_backend_refuses_a_pinned_version(tmp_path):
    """secret_get accepts a version; the file backend cannot honour one. Before
    this it ignored the argument and returned whatever the file held -- the
    defect shape this project keeps meeting: a parameter accepted and ignored."""
    with pytest.raises(ValueError, match="cannot resolve a specific version"):
        backends.secret_get_file("studyflix-postgresql-connection",
                                 key_dir=str(tmp_path), version="3")


def test_the_file_backend_still_accepts_latest(monkeypatch, tmp_path):
    """The default must keep working -- every caller today passes nothing. Getting
    FileNotFoundError rather than ValueError proves it reached the file lookup."""
    monkeypatch.setenv("ADMANAGER_DECRYPT_KEY", Fernet.generate_key().decode())
    with pytest.raises(FileNotFoundError):
        backends.secret_get_file("studyflix-admanager-service-account",
                                 key_dir=str(tmp_path), version="latest")


def test_an_explicit_key_is_used_instead_of_the_environment(monkeypatch, tmp_path):
    """The caller may hold the key without the environment holding it.

    base-65's resolve_decrypt_key falls back to argv[0] and does NOT export it,
    and three of its four AdManager jobs pass the key that way. If resolution
    depended on the environment alone, those three would break on their next run.
    """
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    fkey = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = backends.secret_get_file("studyflix-admanager-service-account",
                                   key_dir=str(tmp_path), key=fkey.decode())
    assert got == '{"type":"sa"}'


def test_an_explicit_key_WINS_over_a_set_environment(monkeypatch, tmp_path):
    """Passing a key is explicit intent; a stale exported value must not beat it."""
    monkeypatch.setenv("ADMANAGER_DECRYPT_KEY", Fernet.generate_key().decode())
    fkey = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = backends.secret_get_file("studyflix-admanager-service-account",
                                   key_dir=str(tmp_path), key=fkey.decode())
    assert got == '{"type":"sa"}'


def test_without_an_explicit_key_the_environment_is_still_used(monkeypatch, tmp_path):
    """The existing contract is unchanged when the argument is absent."""
    fkey = Fernet.generate_key()
    monkeypatch.setenv("ADMANAGER_DECRYPT_KEY", fkey.decode())
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = backends.secret_get_file("studyflix-admanager-service-account",
                                   key_dir=str(tmp_path))
    assert got == '{"type":"sa"}'


def test_secret_get_threads_the_key_to_the_file_backend(monkeypatch, tmp_path):
    """The dispatcher must pass it through, not merely accept it."""
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    fkey = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = sfsecrets.secret_get("studyflix-admanager-service-account",
                               key_dir=str(tmp_path), key=fkey.decode())
    assert got == '{"type":"sa"}'


def test_secret_get_accepts_a_key_passed_as_bytes(monkeypatch, tmp_path):
    """secret_get's cache key hashes `key` with hashlib.sha256(key.encode()),
    computed BEFORE dispatching to the file backend -- so a bytes key would
    hit that same AttributeError one layer higher than _fernet_for's own
    normalisation if secret_get did not also normalise it first."""
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)
    fkey = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = sfsecrets.secret_get("studyflix-admanager-service-account",
                               key_dir=str(tmp_path), key=fkey)
    assert got == '{"type":"sa"}'


def test_a_wrong_explicit_key_names_the_argument_not_the_unset_env_var(monkeypatch, tmp_path):
    """Before `key` existed, ADMANAGER_DECRYPT_KEY was the only possible
    source, so naming it in the error was always true. It can now be a lie --
    precisely for base-65's three AdManager jobs that hold the key from
    argv[0] and never export it. An operator debugging a failed run must be
    told the argument was wrong, not sent chasing an empty environment
    variable."""
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    fkey = Fernet.generate_key()
    wrong_key = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    with pytest.raises(RuntimeError, match=r"the key in the key argument did not open"):
        backends.secret_get_file("studyflix-admanager-service-account",
                                 key_dir=str(tmp_path), key=wrong_key.decode())


def test_a_key_passed_as_bytes_works_the_same_as_str(monkeypatch, tmp_path):
    """Fernet.generate_key() returns bytes -- the obvious way to make a key,
    and exactly what every test in this file calls before .decode(). Passing
    the bytes straight through must not raise a bare AttributeError from
    raw.encode() finding a bytes object with no such method; os.environ.get()
    could only ever return str, so this path did not exist before `key` did."""
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    fkey = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    got = backends.secret_get_file("studyflix-admanager-service-account",
                                   key_dir=str(tmp_path), key=fkey)
    assert got == '{"type":"sa"}'


def test_an_explicit_empty_key_fails_loudly_instead_of_falling_back(monkeypatch, tmp_path):
    """key="" is a caller's mistake, not "unspecified" -- checked with `is
    None`, not truthiness, matching ad_manager_client's own `is not None`
    guard ("an empty key is never valid for Fernet") and secretsR's nzchar()
    validation. base-65's resolve_decrypt_key returns argv[0] whenever argv is
    non-empty, so a FlowForce command whose shell variable expands empty
    yields "", not None -- and must not silently resolve via a correctly-set
    environment variable nobody intended to use."""
    fkey = Fernet.generate_key()
    monkeypatch.setenv("ADMANAGER_DECRYPT_KEY", fkey.decode())
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(fkey).encrypt(b'{"type":"sa"}'))

    with pytest.raises(RuntimeError, match="is not set and no key was passed"):
        backends.secret_get_file("studyflix-admanager-service-account",
                                 key_dir=str(tmp_path), key="")


def test_a_different_key_for_the_same_name_does_not_reuse_the_cached_value(monkeypatch, tmp_path):
    """secretsR's digest_key() folds a hash of the key into its cache key for
    exactly this reason: "Two colliding keys shared one cache slot, so the
    second caller received the first caller's credential with no error." A
    second secret_get() call for the same name, version and key_dir but a
    DIFFERENT key must not be served the first call's cached value -- it must
    try to decrypt with the new key and fail, not return stale data with no
    error."""
    monkeypatch.delenv("ADMANAGER_DECRYPT_KEY", raising=False)
    monkeypatch.delenv("SF_SECRET_BACKEND", raising=False)

    first_key = Fernet.generate_key()
    second_key = Fernet.generate_key()
    d = tmp_path / "AdManager-Auth"
    d.mkdir(parents=True)
    (d / "encrypted_data.bin").write_bytes(Fernet(first_key).encrypt(b'{"type":"sa"}'))

    first = sfsecrets.secret_get("studyflix-admanager-service-account",
                                 key_dir=str(tmp_path), key=first_key.decode())
    assert first == '{"type":"sa"}'

    # Same name, version and key_dir as the call above -- only `key` differs.
    # If the cache key did not include it, this would silently return the
    # first call's cached value instead of attempting to decrypt with the
    # (wrong, for this file) second key.
    with pytest.raises(RuntimeError, match="did not open"):
        sfsecrets.secret_get("studyflix-admanager-service-account",
                             key_dir=str(tmp_path), key=second_key.decode())
