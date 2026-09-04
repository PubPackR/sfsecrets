"""Secret name -> where the file backend finds it.

The NAMES are the contract with R -- secretsR resolves the same strings. Never
invent a Python-side name for a secret R already knows.

Only what Python actually reads is listed. The other 20-odd secrets exist and R
uses them; adding one here is a row, not code, which is the point of this file
being data.
"""

# secret name -> (paths under the keys/ directory, key derivation, env var).
#
# THREE fields, not two. An earlier draft inferred the env var from the
# derivation -- "DB_MASTER_KEY" if derived else "ADMANAGER_DECRYPT_KEY" -- which
# cannot express a third secret opened by a third key without abusing the
# derivation field to mean something it does not.
#
# `paths` is a TUPLE because one secret can span several legacy files. The
# Postgres credential is two of them, and the file backend joins them into the
# single JSON object the gsm backend will return for the same name. That is what
# makes the two backends comparable, which E2 has to prove.
FILES = {
    "studyflix-postgresql-connection": (
        ("PostgreSQL_DB/postgresql_server_python.txt",
         "PostgreSQL_DB/postgresql_key_python.txt"),
        "derived", "DB_MASTER_KEY"),
    "studyflix-admanager-service-account": (
        ("AdManager-Auth/encrypted_data.bin",),
        "verbatim", "ADMANAGER_DECRYPT_KEY"),
}

# service name -> secret name. The seed of a later authenticate(service); not
# used by secret_get, which takes secret names.
SERVICES = {
    "postgresql": "studyflix-postgresql-connection",
    "admanager": "studyflix-admanager-service-account",
}
