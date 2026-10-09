"""Fixtures compartides: un transport HTTP simulat per a `vractl.Vra`.

`Vra._http` és el punt d'injecció: se sobreescriu per servir respostes en memòria
(per ruta access-point i petició) i per enregistrar les crides, de manera que el
muntatge d'URL, la paginació, l'autenticació i el relogin (401) s'exerciten sense xarxa.
"""
import json
from urllib.parse import urlsplit

import pytest

import vractl


class FakeVra(vractl.Vra):
    """Vra amb un `_http` simulat. `routes` mapeja (method, path) a str/bytes/excepció.

    El matx es fa pel *path* de l'URL (sense query): és la manera neta de simular
    endpoints amb paràmetres. L'autenticació (/iaas/api/login) es serveix sempre.
    `stale_access_calls`: nombre de vegades que una petició autenticada retorna 401
    (token d'accés caducat) abans d'acceptar-se — per provar el relogin.
    """

    def __init__(self, routes=None, stale_access_calls=0):
        super().__init__("vra.test", None, refresh_token="rtoken")
        self.routes = routes or {}
        self.stale_access_calls = stale_access_calls
        self.calls = []  # (method, path, url, headers, data)
        self._access = None

    def _http(self, method, url, headers, data):
        path = urlsplit(url).path
        self.calls.append((method, path, url, headers, data))
        if path == "/iaas/api/login":
            return b'{"token":"access-1"}'
        if method == "GET" and path.startswith("/iaas/api/") and headers.get("Authorization") \
                and self.stale_access_calls > 0:
            # still the OLD access token -> reject; but only count once the token is set
            self.stale_access_calls -= 1
            raise vractl.ApiError(401, json.dumps({"message": "caducat"}))
        # el matx més llarg guanya (les rutes de snapshots comparteixen prefix amb machines)
        best = None
        for (m, p), resp in sorted(self.routes.items(), key=lambda kv: len(kv[0][1]), reverse=True):
            if m == method and path.startswith(p):
                best = (p, resp)
                break
        if best is not None:
            p, resp = best
            if isinstance(resp, Exception):
                raise resp
            if isinstance(resp, str):
                return resp.encode()
            return json.dumps(resp).encode()  # dict: es serialitza
        raise vractl.ApiError(404, json.dumps({"message": "no route: %s %s" % (method, path)}))


def machine(**kw):
    base = {"id": "vm-1", "name": "vm1", "deploymentId": "dep-1",
            "deploymentName": "web01", "powerState": "ON", "address": "10.0.0.1"}
    base.update(kw)
    return base


def deployment_map():
    """Ruta estàndard de deployments per fer coincidir dep-1 -> web01."""
    return [{"id": "dep-1", "name": "web01"}]


def snapshot(**kw):
    base = {"id": "snap-1", "name": "pre", "isCurrent": True,
            "createdAt": "2026-10-01T10:00:00Z", "description": ""}
    base.update(kw)
    return base


def pages(*groups):
    """Helper: content paginat -> resposta de l'API (totalElements i content)."""
    return {
        "content": [g for grp in groups for g in grp],
        "totalElements": sum(len(g) for g in groups),
    }


@pytest.fixture
def vra():
    return FakeVra()


@pytest.fixture(autouse=True)
def _restore_env(monkeypatch):
    """Aïlla les variables d'entorn entre proves."""
    for var in ("VRA_TOKEN", "VRA_TOKEN_FILE", "VRA_HOST", "VRA_CA_FILE",
                "VRA_INSECURE", "VRA_API_VERSION"):
        monkeypatch.delenv(var, raising=False)