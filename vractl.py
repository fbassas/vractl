#!/usr/bin/env python3
"""vractl - gestiona VMs de VMware Aria Automation (vRA 8.x) amb la IaaS API.

Arrencar, aturar, reiniciar i fer snapshots d'una o més VMs, en sèrie o en paral·lel.

Servidor i autenticació:
  -h HOST, --host HOST   servidor d'Aria Automation, p.ex. vra.example.org (o VRA_HOST)
  VRA_TOKEN              API token (refresh token) d'Aria Automation
  VRA_TOKEN_FILE         (alternativa) fitxer que conté el token; si no es defineix cap de les
                         dues, es prova ~/.config/vractl/token. Hauria de tenir permisos 600.
  El token es canvia per un token d'accés (JWT) a cada execució: POST /iaas/api/login.
  'vractl.py login' obté un token nou amb usuari i contrasenya i el desa al fitxer.

TLS:
  VRA_CA_FILE / --ca-file   certificats PEM addicionals (p.ex. l'intermedi que el servidor no envia);
                            s'afegeixen a les CA del sistema, no les substitueixen
  VRA_INSECURE=1            no verifica TLS (només proves; el token s'envia sense verificar el servidor)

Identificació: les VMs s'indiquen pel nom del deployment (el més descriptiu; si en té diverses,
se seleccionen totes), pel nom de la VM o per l'id. 'list' mostra les tres coses.

Diverses VM: es poden indicar totes les que es vulguin. Per defecte s'actua sobre una darrere
l'altra; amb --parallel N, fins a N alhora. També es poden seleccionar per patró (--match 'web*';
coincideix amb el deployment o la VM; es pot repetir) o per fitxer (--vms-file, una VM per línia).
Tot es pot combinar; van abans del subcomandament.

Exemples:
  vractl.py -h vra.example.org login
  vractl.py -h vra.example.org list
  vractl.py start web01
  vractl.py --parallel 4 start web01 web02 web03 web04
  vractl.py snapshot web01 pre-update --desc "abans d'actualitzar" [--memory]
  vractl.py --parallel 3 snapshot web01 web02 web03 nocturn --keep 2   # el NOM és l'últim argument
  vractl.py --match 'web*' snapshot nocturn --keep 7
  vractl.py snapshots web01
  vractl.py rollback web01 pre-update
  vractl.py --yes delsnap web01 web02 pre-update
"""
import argparse
import fnmatch
import getpass
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_API_VERSION = "2021-07-15"
DEFAULT_TOKEN_FILE = os.path.expanduser("~/.config/vractl/token")
# subcomandament -> operació de la IaaS API (/iaas/api/machines/{id}/operations/<operació>)
POWER_ACTIONS = {
    "start": "power-on", "stop": "power-off", "shutdown": "shutdown",
    "reboot": "reboot", "reset": "reset", "suspend": "suspend",
    "resume": "power-on",  # Aria no té "resume": una VM suspesa es reprèn arrencant-la
}
# Accions que, sobre més d'una VM, exigeixen confirmació (o --yes)
DESTRUCTIVE = ("stop", "reset", "rollback", "delsnap")
# Subcomandaments amb la forma "VM [VM...] NOM": el nom és l'últim argument
NAMED = ("snapshot", "rollback", "delsnap")
PAGE_SIZE = 100


class VraError(Exception):
    """Error d'una operació contra Aria Automation (es reporta per VM, sense aturar les altres)."""


class ApiError(VraError):
    """Error HTTP retornat per l'API."""

    def __init__(self, code, body):
        msg = body
        try:
            msg = json.loads(body).get("message") or body
        except (ValueError, AttributeError):
            pass
        super().__init__(f"HTTP {code}: {str(msg).strip()[:300]}")
        self.code = code


class OpFailed(VraError):
    """Una operació d'Aria Automation ha acabat amb estat FAILED."""

    def __init__(self, message):
        super().__init__(f"operació fallida: {message}")


_print_lock = threading.Lock()


def say(msg, err=False):
    """Imprimeix una línia sencera sense que es barregi amb la d'un altre fil."""
    with _print_lock:
        print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def token_path():
    return os.path.expanduser(os.environ.get("VRA_TOKEN_FILE") or DEFAULT_TOKEN_FILE)


def load_token():
    """VRA_TOKEN té prioritat; si no, es llegeix VRA_TOKEN_FILE o el fitxer per defecte."""
    token = os.environ.get("VRA_TOKEN", "").strip()
    if token:
        return token
    explicit = os.environ.get("VRA_TOKEN_FILE")
    path = token_path()
    if not explicit and not os.path.exists(path):
        return ""
    try:
        if os.stat(path).st_mode & 0o077:
            print(f"Avís: {path} és accessible per altres usuaris; feu 'chmod 600 {path}'.",
                  file=sys.stderr)
        with open(path) as f:
            for line in f:  # ignora línies buides i comentaris; agafa la primera línia útil
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError as e:
        sys.exit(f"No puc llegir el fitxer del token ({path}): {e.strerror}")
    sys.exit(f"El fitxer del token ({path}) és buit.")


def save_token(token):
    """Desa el token amb permisos 600 (es crea sense deixar-lo mai llegible per altres)."""
    path = token_path()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    os.chmod(path, 0o600)
    return path


def normalize_host(host):
    host = (host or os.environ.get("VRA_HOST", "")).strip()
    if host.lower().startswith("http://"):
        sys.exit("El servidor ha de ser HTTPS: el token no s'enviarà mai per HTTP.")
    host = re.sub(r"^https://", "", host, flags=re.I).rstrip("/")
    if not host:
        sys.exit("Cal indicar el servidor amb -h o VRA_HOST (p.ex. vra.example.org).")
    return host


def make_ssl_context(ca_file):
    if os.environ.get("VRA_INSECURE") == "1":
        print("AVÍS: VRA_INSECURE=1 -> no es verifica el certificat del servidor.", file=sys.stderr)
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()  # CA del sistema
    extra = ca_file or os.environ.get("VRA_CA_FILE")
    if extra:  # s'afegeix a les del sistema (p.ex. un intermedi que el servidor no envia)
        try:
            ctx.load_verify_locations(cafile=os.path.expanduser(extra))
        except (OSError, ssl.SSLError) as e:
            sys.exit(f"No puc carregar el fitxer de CA ({extra}): {getattr(e, 'strerror', None) or e}")
    return ctx


CERT_HINT = (
    "No es pot verificar el certificat del servidor. Si el servidor no envia el certificat "
    "intermedi (el navegador el resol sol, però aquest script no), cal que els administradors "
    "serveixin la cadena completa, o indicar-la amb --ca-file / VRA_CA_FILE."
)


class Vra:
    def __init__(self, host, ctx, api_version=DEFAULT_API_VERSION, refresh_token=None):
        self.host = host
        self.ctx = ctx
        self.api_version = api_version
        self.refresh_token = refresh_token
        self._access = None
        self._lock = threading.Lock()

    # --- HTTP ---------------------------------------------------------------------------------

    def _request(self, method, path, query=None, body=None, auth=True, _retry=True):
        q = {} if path == "/iaas/api/login" or path.startswith("/csp/") else {"apiVersion": self.api_version}
        q.update(query or {})
        url = f"https://{self.host}{path}" + (f"?{urllib.parse.urlencode(q)}" if q else "")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        used = None
        if auth:
            used = self._token()
            headers["Authorization"] = f"Bearer {used}"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401 and auth and _retry:  # token d'accés caducat: un sol relogin
                self._relogin(used)
                return self._request(method, path, query, body, auth, _retry=False)
            raise ApiError(e.code, e.read().decode(errors="replace"))
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise VraError(CERT_HINT + f" ({e.reason.verify_message})")
            raise VraError(f"No puc connectar amb {self.host}: {e.reason}")
        except OSError as e:
            raise VraError(f"No puc connectar amb {self.host}: {e}")
        return json.loads(raw) if raw.strip() else None

    def _token(self):
        """Token d'accés (JWT), obtingut un sol cop i compartit entre fils."""
        with self._lock:
            if self._access is None:
                self._access = self._login()
            return self._access

    def _relogin(self, stale):
        with self._lock:
            if self._access == stale:  # un altre fil ja pot haver-lo renovat
                self._access = self._login()

    def _login(self):
        if not self.refresh_token:
            raise VraError("Falta el token d'API (VRA_TOKEN, VRA_TOKEN_FILE o 'vractl.py login').")
        try:
            r = self._request("POST", "/iaas/api/login", body={"refreshToken": self.refresh_token}, auth=False)
        except ApiError as e:
            if e.code in (400, 401, 403):
                raise VraError(f"El servidor ha rebutjat el token d'API ({e}). Pot haver caducat "
                               "(90 dies) o ser invàlid: genereu-ne un de nou amb 'vractl.py login'.")
            raise
        if not r or not r.get("token"):
            raise VraError("Resposta inesperada del login: no inclou cap 'token'.")
        return r["token"]

    def get_refresh_token(self, username, password):
        """Usuari i contrasenya -> refresh token (pas 1 de la doc). No es desa la contrasenya."""
        try:
            r = self._request("POST", "/csp/gateway/am/api/login", query={"access_token": ""},
                              body={"username": username, "password": password}, auth=False)
        except ApiError as e:
            if e.code in (400, 401, 403):
                raise VraError(f"Login rebutjat ({e}). Comproveu usuari i contrasenya; si entreu "
                               "per SSO, genereu l'API token a la interfície web.")
            raise
        if not r or not r.get("refresh_token"):
            raise VraError("Resposta inesperada del login: no inclou cap 'refresh_token'.")
        return r["refresh_token"]

    # --- API ----------------------------------------------------------------------------------

    def _paginate(self, path):
        out, skip = [], 0
        while True:
            r = self._request("GET", path, query={"$top": PAGE_SIZE, "$skip": skip}) or {}
            page = r.get("content", [])
            out += page
            skip += len(page)
            if not page or len(page) < PAGE_SIZE or skip >= r.get("totalElements", skip + 1):
                return out

    def machines(self):
        """VMs visibles. Cada una porta 'deploymentName': el nom del deployment al qual pertany."""
        ms = self._paginate("/iaas/api/machines")
        try:
            dep_names = {d["id"]: d.get("name") for d in self._paginate("/iaas/api/deployments")}
        except VraError as e:
            say(f"Avís: no puc llegir els deployments ({e}); s'usen els noms de VM.", err=True)
            dep_names = {}
        for m in ms:
            m["deploymentName"] = dep_names.get(m.get("deploymentId")) or m.get("name")
        return ms

    def snapshots(self, machine_id):
        r = self._request("GET", f"/iaas/api/machines/{machine_id}/snapshots") or []
        return r.get("content", []) if isinstance(r, dict) else r

    def find_all(self, idents, patterns=()):
        """Resol noms/ids i patrons en una sola consulta. Tot o res: si un falla, no es fa res.

        Un identificador és, per ordre, el nom d'un deployment (selecciona totes les seves VMs), el
        nom d'una VM o l'id d'una VM. Primer van les indicades explícitament (en ordre) i després
        les dels patrons (per nom de deployment).
        """
        vms = self.machines()
        found, errors = {}, []
        for ident in idents:
            by_dep = [v for v in vms if v["deploymentName"] == ident]
            by_name = [v for v in vms if v.get("name") == ident]
            by_id = [v for v in vms if v["id"] == ident]
            if by_dep and by_name and {v["id"] for v in by_dep} != {v["id"] for v in by_name}:
                errors.append(f"'{ident}' és ambigu: és el nom d'un deployment i també d'una altra VM "
                              f"(ids {[v['id'] for v in by_name]}). Feu servir l'id.")
                continue
            hits = by_dep or by_name or by_id
            if not hits:
                errors.append(f"No trobo cap deployment, VM ni id '{ident}'")
            elif not by_dep and len(hits) > 1:
                errors.append(f"'{ident}' és ambigu: ids {[v['id'] for v in hits]}. Feu servir l'id.")
            else:
                for v in hits:
                    found.setdefault(v["id"], v)  # sense duplicats, mantenint l'ordre
        for pat in patterns:
            hits = [v for v in sorted(vms, key=lambda v: v["deploymentName"]) if match_vm(v, pat)]
            if not hits:
                errors.append(f"Cap VM coincideix amb el patró '{pat}'")
            for v in hits:
                found.setdefault(v["id"], v)
        if errors:
            sys.exit("\n".join(errors))
        return list(found.values())

    def snapshot_id(self, vm, name):
        """Id del snapshot amb aquest nom (o id). Error si no n'hi ha cap o n'hi ha diversos."""
        hits = [s for s in self.snapshots(vm["id"]) if s.get("name") == name or s.get("id") == name]
        if not hits:
            raise VraError(f"el snapshot '{name}' no existeix")
        if len(hits) > 1:
            raise VraError(f"hi ha {len(hits)} snapshots anomenats '{name}' (ids "
                           f"{[s['id'] for s in hits]}); indiqueu-ne l'id")
        return hits[0]["id"]

    def wait(self, tracker, timeout=900, interval=3):
        """Espera que acabi una operació (request tracker). Retorna si FINISHED, llença si FAILED."""
        tid = (tracker or {}).get("id")
        if not tid:
            return
        end = time.time() + timeout
        while True:
            t = self._request("GET", f"/iaas/api/request-tracker/{tid}") or {}
            if t.get("status") == "FINISHED":
                return
            if t.get("status") == "FAILED":
                raise OpFailed(t.get("message") or "sense missatge")
            if time.time() > end:
                raise VraError("temps d'espera esgotat (l'operació pot continuar a Aria Automation)")
            time.sleep(interval)

    def run(self, method, path, body=None, wait=True):
        """Llança una operació (202 + tracker) i, si wait, n'espera el final. Retorna el tracker."""
        tracker = self._request(method, path, body=body)
        if wait:
            self.wait(tracker)
        return tracker


def vm_label(vm):
    """Nom d'una VM per a missatges: el del deployment i, si és diferent, el de la VM entre parèntesis."""
    dep, name = vm.get("deploymentName"), vm.get("name")
    return dep if dep == name else f"{dep} ({name})"


def match_vm(vm, pattern):
    """Un patró coincideix amb el nom del deployment o amb el de la VM (distingeix majúscules)."""
    return any(fnmatch.fnmatchcase(vm.get(k) or "", pattern) for k in ("deploymentName", "name"))


# Amb --keep, el nom donat és un prefix i s'hi afegeix un sufix de data, que ordena cronològicament.
def snapshot_limit(vm):
    """Límit de snapshots de la VM (propietat 'snapshotLimit', un text), o None si no en té."""
    try:
        limit = int((vm.get("customProperties") or {}).get("snapshotLimit"))
    except (TypeError, ValueError):
        return None
    return limit if limit > 0 else None


def keep_warnings(vm, n_existing, keep):
    """Avisos sobre --keep per a una VM amb límit de snapshots (llista, buida si tot va bé).

    --keep crea primer el snapshot nou i després esborra els antics, així que durant un instant la
    VM en té un més que el final: amb el límit ja assolit, la creació falla.
    """
    limit = snapshot_limit(vm)
    if limit is None:
        return []
    out = []
    if keep > limit:
        out.append(f"--keep {keep} supera el límit de snapshots d'aquesta VM ({limit}): "
                   f"com a molt se'n podran conservar {limit}.")
    if n_existing >= limit:
        out.append(f"la VM té {n_existing} snapshot(s) i el límit és {limit}: probablement la creació del "
                   "nou fallarà, perquè --keep esborra els antics després de crear-lo.")
    return out


def prune_snapshots(vra, vm, prefix, keep, label=""):
    """Esborra els snapshots '<prefix>-AAAAMMDD-HHMMSS' més antics, deixant-ne `keep`."""
    pat = re.compile(re.escape(prefix) + r"-\d{8}-\d{6}$")
    group = sorted((s for s in vra.snapshots(vm["id"]) if pat.match(s.get("name", ""))),
                   key=lambda s: s["name"])
    for old in group[:-keep]:
        vra.run("DELETE", f"/iaas/api/machines/{vm['id']}/snapshots/{old['id']}")
        say(f"{label}Esborrat snapshot antic: {old['name']}")


def read_vms_file(path):
    """Llegeix un fitxer amb una VM (nom o id) per línia; ignora buides i comentaris (#)."""
    try:
        with open(os.path.expanduser(path)) as f:
            return [l for l in (line.split("#", 1)[0].strip() for line in f) if l]
    except OSError as e:
        sys.exit(f"No puc llegir el fitxer de VMs ({path}): {e.strerror}")


def confirm_destructive(cmd, vms):
    """Demana confirmació (només en interactiu) abans d'una acció destructiva sobre diverses VM."""
    names = ", ".join(vm_label(v) for v in vms)
    if not sys.stdin.isatty():
        sys.exit(f"'{cmd}' sobre {len(vms)} VMs requereix --yes (no hi ha terminal per confirmar-ho).")
    print(f"S'executarà '{cmd}' sobre {len(vms)} VMs: {names}")
    if input("Continuar? [s/N] ").strip().lower() not in ("s", "si", "sí", "y", "yes"):
        sys.exit("Cancel·lat.")


def cmd_login(vra, host):
    """Demana usuari i contrasenya al terminal, obté el token d'API i el desa. No desa la contrasenya."""
    if not sys.stdin.isatty():
        sys.exit("'login' és interactiu: cal un terminal per introduir la contrasenya.")
    username = os.environ.get("VRA_USER") or input(f"Usuari a {host}: ").strip()
    password = getpass.getpass("Contrasenya (no es mostra ni es desa): ")
    token = vra.get_refresh_token(username, password)
    del password
    path = save_token(token)
    print(f"Token d'API desat a {path} (permisos 600). Caduca als 90 dies.")


def main():
    try:
        run()
    except VraError as e:
        sys.exit(str(e))


def run():
    # add_help=False: el -h queda lliure per al servidor (l'ajuda és --help)
    ap = argparse.ArgumentParser(description="Gestió de VMs d'Aria Automation", add_help=False)
    ap.add_argument("--help", action="help", help="mostra aquesta ajuda i surt")
    ap.add_argument("-h", "--host", metavar="HOST", help="servidor d'Aria Automation (o VRA_HOST)")
    ap.add_argument("--ca-file", metavar="FITXER",
                    help="certificats PEM addicionals de confiança, p.ex. un intermedi que falta (o VRA_CA_FILE)")
    ap.add_argument("--api-version", default=os.environ.get("VRA_API_VERSION", DEFAULT_API_VERSION),
                    metavar="AAAA-MM-DD", help=f"versió de la IaaS API (defecte: {DEFAULT_API_VERSION})")
    ap.add_argument("--match", action="append", metavar="PATRÓ",
                    help="selecciona les VMs el nom de les quals coincideix amb el patró (p.ex. 'web-*'; "
                         "es pot repetir; citeu-lo perquè la shell no l'expandeixi)")
    ap.add_argument("--vms-file", metavar="FITXER",
                    help="fitxer amb una VM (nom o id) per línia (# = comentari)")
    ap.add_argument("--no-wait", action="store_true", help="no esperis que acabi l'operació")
    ap.add_argument("--parallel", type=int, default=1, metavar="N",
                    help="nombre de VMs a tractar alhora (defecte: 1, una darrere l'altra)")
    ap.add_argument("--yes", action="store_true",
                    help="no demanis confirmació per a accions destructives sobre diverses VMs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("login", help="obté un token d'API amb usuari i contrasenya i el desa")
    sub.add_parser("check", help="comprova el token i la connexió (només lectura)")
    sub.add_parser("list")
    subs = {}
    for c in tuple(POWER_ACTIONS) + ("status", "snapshots"):
        subs[c] = sub.add_parser(c)
        subs[c].add_argument("vm", nargs="*", metavar="VM",
                             help="VMs (nom o id); opcional si s'usa --match o --vms-file")
    for c in NAMED:
        subs[c] = p = sub.add_parser(c)
        p.add_argument("args", nargs="*", metavar="VM... NOM",
                       help="VMs (nom o id) i, al final, el nom del snapshot; "
                            "amb --match o --vms-file només cal el nom")
    p = subs["snapshot"]
    p.add_argument("--desc", default="")
    p.add_argument("--memory", action="store_true", help="inclou la memòria (snapshot amb la VM encesa)")
    p.add_argument("--keep", type=int, metavar="N",
                   help="rotació: el nom és un prefix, s'hi afegeix la data (nom-AAAAMMDD-HHMMSS) "
                        "i es conserven només els N snapshots més recents d'aquest prefix")
    a = ap.parse_args()

    selectors = bool(a.match or a.vms_file)  # VMs triades per patró o fitxer, no a la línia d'ordres
    if a.cmd in NAMED:
        if len(a.args) < (1 if selectors else 2):
            subs[a.cmd].error("cal indicar el nom del snapshot i, si no s'usa --match ni --vms-file, "
                              "almenys una VM (VM... NOM)")
        a.vm, a.name = a.args[:-1], a.args[-1]
    elif a.cmd in subs and a.cmd not in NAMED and not a.vm and not selectors:
        subs[a.cmd].error("cal indicar almenys una VM, o bé --match / --vms-file")

    if a.parallel < 1:
        sys.exit("--parallel ha de ser 1 o més.")
    keep = getattr(a, "keep", None)
    if keep is not None:
        if keep < 1:
            sys.exit("--keep ha de ser 1 o més.")
        if a.no_wait:
            sys.exit("--keep no es pot combinar amb --no-wait: cal esperar el snapshot per poder esborrar els antics.")

    host = normalize_host(a.host)
    vra = Vra(host, make_ssl_context(a.ca_file), a.api_version,
              refresh_token=None if a.cmd == "login" else load_token())

    if a.cmd == "login":
        return cmd_login(vra, host)
    if not vra.refresh_token:
        sys.exit("Cal definir VRA_TOKEN, VRA_TOKEN_FILE, o crear-ne un amb 'vractl.py login' "
                 f"(fitxer per defecte {DEFAULT_TOKEN_FILE}).")
    if a.cmd == "check":
        vra._token()
        n = len(vra.machines())
        say(f"OK: autenticat a {host}; el vostre compte veu {n} VMs.")
        return
    if a.cmd == "list":
        rows = [v for v in sorted(vra.machines(), key=lambda v: v["deploymentName"])
                if not a.match or any(match_vm(v, p) for p in a.match)]
        w = max([len("DEPLOYMENT")] + [len(v["deploymentName"]) for v in rows])
        say(f"{'DEPLOYMENT':<{w}}  {'VM':<12} {'ESTAT':<9} {'ADREÇA':<15} ID")
        for v in rows:
            say(f"{v['deploymentName']:<{w}}  {v.get('name', '-'):<12} {v.get('powerState', '?'):<9} "
                f"{v.get('address', ''):<15} {v['id']}")
        return

    vms = vra.find_all(a.vm + (read_vms_file(a.vms_file) if a.vms_file else []), a.match or ())
    many = len(vms) > 1
    if many and a.cmd in DESTRUCTIVE and not a.yes:
        confirm_destructive(a.cmd, vms)

    # Un sol sufix per a tota l'execució: totes les VMs reben el mateix nom de snapshot
    snapname = getattr(a, "name", None)
    if keep is not None:
        snapname = f"{a.name}-{time.strftime('%Y%m%d-%H%M%S')}"

    def work(vm):
        """Fa l'operació sobre una VM. Retorna True si ha anat bé; els errors es reporten aquí."""
        label = vm_label(vm)
        prefix = f"[{vm['deploymentName']}] " if many else ""
        base = f"/iaas/api/machines/{vm['id']}"
        try:
            if a.cmd == "status":
                say(f"{label}: {vm.get('powerState', '?')}")
                return True
            if a.cmd == "snapshots":
                lines = [f"{'*' if s.get('isCurrent') else ' '} {s.get('name', ''):<32} "
                         f"{s.get('createdAt', '')[:19]:<10}  {s.get('id', ''):<36}  {s.get('description', '')}"
                         for s in vra.snapshots(vm["id"])]
                if many:
                    lines.insert(0, f"== {label}")
                if lines:
                    say("\n".join(lines))
                return True

            body = None
            if a.cmd in POWER_ACTIONS:
                method, path = "POST", f"{base}/operations/{POWER_ACTIONS[a.cmd]}"
            elif a.cmd == "snapshot":
                method, path = "POST", f"{base}/operations/snapshots"
                body = {"name": snapname, "description": a.desc, "snapshotMemory": a.memory}
            elif a.cmd == "rollback":
                method, path = "POST", f"{base}/operations/revert/{vra.snapshot_id(vm, a.name)}"
            elif a.cmd == "delsnap":
                method, path = "DELETE", f"{base}/snapshots/{vra.snapshot_id(vm, a.name)}"

            if a.cmd == "snapshot" and keep is not None and snapshot_limit(vm) is not None:
                for w in keep_warnings(vm, len(vra.snapshots(vm["id"])), keep):
                    say(f"{prefix}AVÍS {label}: {w}", err=True)

            tracker = vra.run(method, path, body, wait=not a.no_wait)
            if a.no_wait:
                say(f"Operació enviada: {a.cmd} {label}: {(tracker or {}).get('id', '-')}")
            else:
                what = f"{a.cmd} '{snapname}'" if keep is not None else a.cmd
                say(f"OK: {what} {label}")
                if keep is not None:
                    prune_snapshots(vra, vm, a.name, keep, prefix)
            return True
        except VraError as e:
            say(f"ERROR: {a.cmd} {label}: {e}", err=True)
            return False

    if a.parallel == 1 or not many:
        results = [work(vm) for vm in vms]
    else:
        with ThreadPoolExecutor(max_workers=min(a.parallel, len(vms))) as ex:
            results = list(ex.map(work, vms))

    failed = results.count(False)
    if many and (failed or a.cmd not in ("status", "snapshots")):  # a les consultes només si hi ha errors
        say(f"Resum: {len(vms) - failed} correctes, {failed} amb error", err=bool(failed))
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
