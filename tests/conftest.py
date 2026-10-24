import json
from pathlib import Path

import pytest

from secwatch import config as config_mod
from secwatch.db import DB

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def state(tmp_path):
    return tmp_path


@pytest.fixture
def cfg(state):
    c = config_mod.load(state=state, env={})
    c.data["host_name"] = "testhost"
    for e in ("kev", "epss"):
        c.data["enrichers"][e]["enabled"] = False  # never touch the network in tests
    return c


@pytest.fixture
def db(cfg):
    d = DB(cfg.db_path)
    yield d
    d.close()


@pytest.fixture
def fixture_json():
    def _load(name):
        return json.loads((FIX / name).read_text())
    return _load
