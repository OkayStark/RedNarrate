from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def fx(fixtures):
    def _get(name: str) -> Path:
        return fixtures / name

    return _get
