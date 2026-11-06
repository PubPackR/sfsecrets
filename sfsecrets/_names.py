"""Service name -> secret name.

The NAMES are the contract with R -- secretsR resolves the same strings. Never
invent a Python-side name for a secret R already knows.

The seed of a later authenticate(service); not used by secret_get, which takes
secret names. Until 0.2.0 it lived in _legacy_map.py beside FILES, the file
backend's routing table, which went with that backend.
"""

SERVICES = {
    "postgresql": "studyflix-postgresql-connection",
    "admanager": "studyflix-admanager-service-account",
}
