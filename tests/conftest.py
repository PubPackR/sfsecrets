import pytest
import sfsecrets


@pytest.fixture(autouse=True)
def _clear_cache():
    sfsecrets.secret_cache_clear()
    yield
    sfsecrets.secret_cache_clear()
