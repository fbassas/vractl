"""Proves offline de vractl (sense xarxa: tot el tràfic es simula via _http)."""
import json
import os
import sys

import pytest
from conftest import deployment_map, machine, pages, snapshot

import vractl

# --------------------------------------------------------------------------- tokens

def test_token_path_default_and_env(monkeypatch):
    monkeypatch.delenv("VRA_TOKEN_FILE", raising=False)
    assert vractl.token_path() == vractl.DEFAULT_TOKEN_FILE
    monkeypatch.setenv("VRA_TOKEN_FILE", "/tmp/x/tok")
    assert vractl.token_path() == "/tmp/x/tok"


def test_load_token_env_priority():
    os.environ["VRA_TOKEN"] = "  envtok  "
    assert vractl.load_token() == "envtok"


def test_load_token_file_skips_comments_and_blanks(monkeypatch, tmp_path):
    f = tmp_path / "token"
    f.write_text("# comentari\n\nsecret123\n")
    monkeypatch.setenv("VRA_TOKEN_FILE", str(f))
    monkeypatch.setenv("VRA_TOKEN", "")
    assert vractl.load_token() == "secret123"


def test_load_token_missing_file_default(monkeypatch, tmp_path):
    monkeypatch.setenv("VRA_TOKEN", "")
    monkeypatch.setenv("VRA_TOKEN_FILE", "")
    monkeypatch.setattr(vractl, "DEFAULT_TOKEN_FILE", str(tmp_path / "nope"))
    assert vractl.load_token() == ""


def test_save_token_creates_600(monkeypatch, tmp_path):
    target = str(tmp_path / "sub" / "token")
    monkeypatch.setenv("VRA_TOKEN_FILE", target)
    path = vractl.save_token("abc")
    assert open(path).read() == "abc\n"
    assert (os.stat(path).st_mode & 0o777) == 0o600
    assert (os.stat(os.path.dirname(path)).st_mode & 0o777) == 0o700


def test_load_token_warns_on_permissive_file(monkeypatch, tmp_path, capsys):
    f = tmp_path / "token"
    f.write_text("abc\n")
    os.chmod(f, 0o644)
    monkeypatch.setenv("VRA_TOKEN_FILE", str(f))
    monkeypatch.setenv("VRA_TOKEN", "")
    assert vractl.load_token() == "abc"
    assert "accessible per altres usuaris" in capsys.readouterr().err


# --------------------------------------------------------------------------- host

def test_normalize_host_strips_https():
    os.environ["VRA_HOST"] = "https://vra.example.org/"
    assert vractl.normalize_host(None) == "vra.example.org"


def test_normalize_host_rejects_http():
    with pytest.raises(SystemExit):
        vractl.normalize_host("http://vra.example.org")


def test_normalize_host_requires_host(monkeypatch):
    monkeypatch.setenv("VRA_HOST", "")
    with pytest.raises(SystemExit):
        vractl.normalize_host("")


# --------------------------------------------------------------------------- helpers pures

def test_vm_label_same_and_diff():
    vm = machine(deploymentName="web01", name="web01")
    assert vractl.vm_label(vm) == "web01"
    vm = machine(deploymentName="web01", name="mt-123")
    assert vractl.vm_label(vm) == "web01 (mt-123)"


def test_match_vm_deployment_and_name():
    vm = machine(deploymentName="web01", name="mt-123")
    assert vractl.match_vm(vm, "web*")
    assert vractl.match_vm(vm, "*123")
    assert not vractl.match_vm(vm, "db*")
    assert not vractl.match_vm(vm, "WEB*")  # majúscules importen


def test_describe_snapshot_prefers_real_date():
    s = snapshot(realDate="2026-10-02T00:00:00Z", createdAt="2026-10-01T00:00:00Z", description="abans")
    assert vractl.describe_snapshot(s) == "'pre', del 2026-10-02 (abans)"


def test_read_vms_file_ignores_comments(monkeypatch, tmp_path):
    f = tmp_path / "vms.txt"
    f.write_text("# hola\nvm1   # comentari inline\n\nvm2\n")
    assert vractl.read_vms_file(str(f)) == ["vm1", "vm2"]


def test_read_vms_file_missing_exits(tmp_path):
    with pytest.raises(SystemExit):
        vractl.read_vms_file(str(tmp_path / "nope"))


# --------------------------------------------------------------------------- request / url / json

def test_request_login_has_no_api_version(vra):
    vra.routes[("POST", "/csp/gateway/am/api/login")] = "{}"
    vra._request("POST", "/csp/gateway/am/api/login", body={}, auth=False)
    method, path, url, headers, data = vra.calls[0]
    assert "apiVersion" not in url


def test_request_iaas_includes_api_version(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([machine()])
    vra._access = "access-1"  # evita el login per provar només el muntatge d'URL
    vra._request("GET", "/iaas/api/machines")
    method, path, url, headers, data = vra.calls[-1]
    assert "apiVersion=2021-07-15" in url
    assert headers["Authorization"] == "Bearer access-1"


def test_request_deployment_api_omits_api_version(vra):
    vra.routes[("GET", "/deployment/api/requests/x")] = '{"status":"SUCCESSFUL"}'
    vra._access = "access-1"
    vra._request("GET", "/deployment/api/requests/x")
    method, path, url, headers, data = vra.calls[-1]
    assert "apiVersion" not in url


def test_request_sends_json_body(vra):
    vra.routes[("POST", "/deployment/api/resources/vm-1/requests")] = '{"id":"req-1"}'
    vra._access = "access-1"
    vra._request("POST", "/deployment/api/resources/vm-1/requests", body={"actionId": "X", "inputs": {}})
    method, path, url, headers, data = vra.calls[-1]
    assert headers["Content-Type"] == "application/json"
    assert json.loads(data.decode()) == {"actionId": "X", "inputs": {}}


def test_request_401_triggers_single_relogin(vra):
    # primer autentica (token d'accés renovat), llavors el GET retorna 401 (token
    # d'accés caducat a mitja sessió) -> relogin + refe de la petició, que ara passa.
    vra.routes[("GET", "/iaas/api/machines")] = pages([machine()])
    vra.stale_access_calls = 1
    out = vra._request("GET", "/iaas/api/machines")
    assert out["content"]
    # login fet dues vegades: el _token() inicial + el relogin
    login_calls = [c for c in vra.calls if c[1] == "/iaas/api/login"]
    assert len(login_calls) == 2


def test_request_401_exhausts_after_retry(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([machine()])
    vra.stale_access_calls = 2  # el reintent torna a fallar amb 401
    with pytest.raises(vractl.ApiError) as ei:
        vra._request("GET", "/iaas/api/machines")
    assert ei.value.code == 401


def test_api_error_parses_json_message():
    e = vractl.ApiError(500, json.dumps({"message": "el servidor ha fallat"}))
    assert "el servidor ha fallat" in str(e)
    assert e.code == 500
    assert not e.html


def test_api_error_detects_html_blocker():
    e = vractl.ApiError(200, "<html><head><title>Forbidden</title></head></html>")
    assert e.html
    assert "resposta HTML" in str(e)
    assert "Forbidden" in str(e)


# --------------------------------------------------------------------------- paginació

def test_paginate_all_pages(vra):
    # pàgina 1 plena (PAGE_SIZE) i l'última curta: exercita múltiples peticions
    full = [machine(id=str(i)) for i in range(vractl.PAGE_SIZE)]
    tail = [machine(id="tail-1"), machine(id="tail-2")]
    vra._access = "access-1"  # evita el login; el transport overriden no el sap servir

    def _http(method, url, headers, data):
        vra.calls.append((method, url, headers, data))
        skip = int(_qp(url, "$skip"))
        if skip == 0:
            return json.dumps({"content": full, "totalElements": vractl.PAGE_SIZE + 2}).encode()
        return json.dumps({"content": tail, "totalElements": vractl.PAGE_SIZE + 2}).encode()
    vra._http = _http
    out = vra._paginate("/iaas/api/machines")
    assert [m["id"] for m in out] == [str(i) for i in range(vractl.PAGE_SIZE)] + ["tail-1", "tail-2"]
    assert len(vra.calls) == 2


def test_paginate_stops_early(vra):
    # una pàgina per sota de PAGE_SIZE s'acaba de seguida (una sola petició)
    few = [machine(id=str(i)) for i in range(10)]
    vra._access = "access-1"
    def _http(method, url, headers, data):
        vra.calls.append((method, url, headers, data))
        return json.dumps({"content": few, "totalElements": 10}).encode()
    vra._http = _http
    out = vra._paginate("/iaas/api/machines")
    assert len(out) == 10 and len(vra.calls) == 1


def _qp(url, key):
    from urllib.parse import parse_qs, urlsplit
    return parse_qs(urlsplit(url).query).get(key, ["0"])[0]


# --------------------------------------------------------------------------- machines / find_all

def test_machines_joins_deployment_names(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([
        machine(id="vm-1", deploymentId="dep-1"),
        machine(id="vm-2", name="vm2", deploymentId="dep-nonexistent"),
    ])
    vra.routes[("GET", "/iaas/api/deployments")] = pages([{"id": "dep-1", "name": "web01"}])
    ms = vra.machines()
    by_id = {m["id"]: m for m in ms}
    assert by_id["vm-1"]["deploymentName"] == "web01"
    assert by_id["vm-2"]["deploymentName"] == "vm2"  # fallback al nom de VM


def test_find_all_by_deployment_name(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([
        machine(id="1", name="a"),
        machine(id="2", deploymentName="web02", name="b", deploymentId="dep-2"),
    ])
    vra.routes[("GET", "/iaas/api/deployments")] = pages(deployment_map() + [{"id": "dep-2", "name": "web02"}])
    out = vra.find_all(["web01"])
    assert [m["id"] for m in out] == ["1"]


def test_find_all_by_pattern(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([
        machine(id="1", name="a"),
        machine(id="2", deploymentName="db01", name="b", deploymentId="dep-2"),
    ])
    vra.routes[("GET", "/iaas/api/deployments")] = pages(deployment_map() + [{"id": "dep-2", "name": "db01"}])
    out = vra.find_all([], ("web*",))
    assert [m["id"] for m in out] == ["1"]


def test_find_all_errors_on_unknown(vra):
    vra.routes[("GET", "/iaas/api/machines")] = pages([machine()])
    vra.routes[("GET", "/iaas/api/deployments")] = pages(deployment_map())
    with pytest.raises(SystemExit) as ei:
        vra.find_all(["ghost", "second"])
    assert "No trobo cap deployment, VM ni id 'ghost'" in str(ei.value)


def test_find_all_notifies_ambiguity(vra):
    # el mateix nom de VM existeix en dos deployments diferents (ids diferents)
    vra.routes[("GET", "/iaas/api/machines")] = pages([
        machine(id="1", deploymentId="dep-1"),
        machine(id="2", deploymentName="other", name="vm1", deploymentId="dep-2"),
    ])
    vra.routes[("GET", "/iaas/api/deployments")] = pages(deployment_map() + [{"id": "dep-2", "name": "other"}])
    with pytest.raises(SystemExit) as ei:
        vra.find_all(["vm1"])
    assert "és ambigu" in str(ei.value)


def test_snapshot_id_found_by_name_or_id(vra):
    vra.routes[("GET", "/iaas/api/machines/vm-1/snapshots")] = pages([
        snapshot(id="s1", name="pre"),
        snapshot(id="s2", name="post"),
    ])
    assert vra.snapshot_id({"id": "vm-1"}, "pre") == "s1"
    assert vra.snapshot_id({"id": "vm-1"}, "s2") == "s2"


def test_snapshot_id_missing_raises(vra):
    vra.routes[("GET", "/iaas/api/machines/vm-1/snapshots")] = pages([])
    with pytest.raises(vractl.VraError):
        vra.snapshot_id({"id": "vm-1"}, "pre")


# --------------------------------------------------------------------------- action / wait

def test_action_retries_409_then_succeeds(vra, monkeypatch):
    monkeypatch.setattr(vractl, "ACTION_RETRY_DELAY", 0)
    vra._access = "access-1"  # evita el login; el transport overriden no el sap servir
    calls = {"n": 0}
    body = json.dumps({"status": "SUCCESSFUL"}).encode()

    def _http(method, url, headers, data):
        vra.calls.append((method, url, headers, data))
        calls["n"] += 1
        if method == "POST" and calls["n"] == 1:
            raise vractl.ApiError(409, "conflicte")
        return body
    vra._http = _http
    req = vra.action("vm-1", "Cloud.vSphere.Machine.PowerOn")
    assert req["status"] == "SUCCESSFUL"


def test_action_409_exhausts(vra, monkeypatch):
    monkeypatch.setattr(vractl, "ACTION_RETRY_DELAY", 0)
    vra._access = "access-1"
    def _http(method, url, headers, data):
        vra.calls.append((method, url, headers, data))
        raise vractl.ApiError(409, "conflicte permanent")
    vra._http = _http
    with pytest.raises(vractl.ApiError) as ei:
        vra.action("vm-1", "X")
    assert ei.value.code == 409


def test_action_403_clear_message(vra):
    vra._access = "access-1"
    def _http(method, url, headers, data):
        raise vractl.ApiError(403, "no")
    vra._http = _http
    with pytest.raises(vractl.VraError, match="no té permís"):
        vra.action("vm-1", "X")


def test_wait_success_and_failure(vra):
    vra.routes[("GET", "/deployment/api/requests/r1")] = '{"status":"SUCCESSFUL"}'
    vra._request("GET", "/deployment/api/requests/r1")
    vra.routes[("GET", "/deployment/api/requests/r2")] = '{"status":"FAILED","details":"boom"}'
    with pytest.raises(vractl.OpFailed, match="boom"):
        vra.wait({"id": "r2"})


def test_wait_human_interaction(vra):
    vra.routes[("GET", "/deployment/api/requests/r3")] = '{"status":"APPROVAL_PENDING","details":""}'
    with pytest.raises(vractl.VraError, match="aprovació"):
        vra.wait({"id": "r3"}, timeout=1)


# --------------------------------------------------------------------------- plan_snapshots

def test_plan_snapshots_assume_yes(vra):
    vra.routes[("GET", "/iaas/api/machines/vm-1/snapshots")] = pages([snapshot()])
    to_delete, skipped, failed = vractl.plan_snapshots(vra, [machine(id="vm-1")], "nou", assume_yes=True)
    assert "vm-1" in to_delete and skipped == set() and failed == set()


def test_plan_snapshots_no_tty_requires_yes(vra, monkeypatch):
    vra.routes[("GET", "/iaas/api/machines/vm-1/snapshots")] = pages([snapshot()])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit, match="--yes"):
        vractl.plan_snapshots(vra, [machine(id="vm-1")], "nou", assume_yes=False)


def test_plan_snapshots_interactive_yes_skips(vra, monkeypatch):
    vra.routes[("GET", "/iaas/api/machines/vm-1/snapshots")] = pages([snapshot()])
    vra.routes[("GET", "/iaas/api/machines/vm-2/snapshots")] = pages([snapshot()])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["s", "n"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    vms = [machine(id="vm-1", deploymentName="a"), machine(id="vm-2", deploymentName="b")]
    to_delete, skipped, failed = vractl.plan_snapshots(vra, vms, "nou", assume_yes=False)
    assert "vm-1" in to_delete
    assert "vm-2" in skipped
    assert failed == set()


def test_confirm_destructive_requires_yes_non_tty(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(SystemExit, match="--yes"):
        vractl.confirm_destructive("stop", [machine(id="1"), machine(id="2")])


# --------------------------------------------------------------------------- CLI

def test_cli_version(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vractl", "--version"])
    with pytest.raises(SystemExit) as ei:
        vractl.run()
    assert ei.value.code == 0
    assert "vractl 1.0.0" in capsys.readouterr().out


def test_cli_json_only_read(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vractl", "--json", "start", "web01"])
    with pytest.raises(SystemExit, match="--json només"):
        vractl.run()


def test_cli_list_json(monkeypatch, vra, capsys):
    vra.routes[("GET", "/iaas/api/machines")] = pages([machine()])
    vra.routes[("GET", "/iaas/api/deployments")] = pages([{"id": "dep-1", "name": "web01"}])
    monkeypatch.setattr(vractl, "Vra", lambda *a, **k: vra)
    monkeypatch.setattr(vractl, "load_token", lambda: "tok")
    monkeypatch.setattr(sys, "argv", ["vractl", "-h", "vra.test", "--json", "list"])
    vractl.run()
    lines = capsys.readouterr().out.strip().splitlines()
    block = "\n".join(lines).strip()
    data = json.loads(block)
    assert data[0]["deployment"] == "web01"
    assert data[0]["id"] == "vm-1"
    assert data[0]["vm"] == "vm1"