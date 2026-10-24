"""The tag server through the Python package: ciplink.server.TagServer and the ciplink-server command."""

import json
import time
import urllib.request

import pytest

from ciplink.server import TagServer, main

CONFIG = """
[server]
audit_log = ""
pages_file = ""
[plc.P]
path = "192.0.2.1"
mock_tags = "tags.json"
[token.t]
secret = "s"
"""


@pytest.fixture
def config(tmp_path):
    (tmp_path / "tags.json").write_text('{"Speed": "REAL", "Count": "DINT"}')
    path = tmp_path / "tagserver.toml"
    path.write_text(CONFIG)
    return path


def get(address, path, token=None):
    request = urllib.request.Request(f"http://{address[0]}:{address[1]}{path}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def test_tag_server_serves_the_mock_until_stopped(config):
    with TagServer(config, mock=True, port=0) as server:
        host, port = server.address
        assert host == "127.0.0.1" and port > 0
        for _ in range(50):
            if get(server.address, "/health")["plcs"]["P"]["state"] == "connected":
                break
            time.sleep(0.05)
        tags = get(server.address, "/tags", token="s")
        assert tags["plc"] == "P"
        assert [t["name"] for t in tags["tags"]] == ["Speed", "Count"]
    server.stop()  # stopping again is fine


def test_bad_configs_raise(tmp_path):
    with pytest.raises(ValueError, match="tagserver.toml"):
        TagServer(tmp_path / "tagserver.toml")


def test_the_command_line(capfd, tmp_path):
    assert main(["--version"]) == 0
    assert "ciplink-server" in capfd.readouterr().out
    assert main(["nonsense"]) == 2
    with pytest.raises(RuntimeError, match="tagserver.toml"):
        main(["dump-tags", "--config", str(tmp_path / "tagserver.toml"), "--plc", "P", "--out", "x.json"])
