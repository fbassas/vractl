# vractl

Eina de línia d'ordres per gestionar màquines virtuals de **VMware Aria Automation 8.x** (abans
vRealize Automation) amb la seva **IaaS API**: arrencar, aturar, reiniciar i fer snapshots d'una o
més VMs, en sèrie o en paral·lel. Fa servir les mateixes opcions que
[pvectl](https://github.com/fbassas/pvectl) (la versió per a Proxmox).

> **Estat:** el script s'ha provat amb un servidor Aria Automation **simulat** (HTTPS, login,
> paginació, renovació del token, seguiment d'operacions), construït a partir del Swagger de la
> IaaS API. **Encara no s'ha provat contra una instància real.** Comenceu per `check` i `list`
> (només lectura) i feu les primeres operacions amb una VM de prova.

Operacions: arrencar, aturar (dur o net), reiniciar, reset, suspendre/reprendre, crear/llistar/
revertir/esborrar snapshots i consultar l'estat.

## Requisits

- Python 3.8 o superior (no cal cap paquet extern).
- Accés HTTPS (443) al servidor d'Aria Automation.
- Un compte amb permís per gestionar les VMs a la IaaS API (vegeu *Permisos*).

## Instal·lació

```bash
cd ~/vractl
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # no instal·la res, però és inofensiu
```

## Configuració

### Servidor

```bash
./vractl.py -h vra.example.org check      # o bé:  export VRA_HOST=vra.example.org
```

Només s'accepta HTTPS: el token no s'envia mai per HTTP.

### Autenticació

L'API fa servir dos tokens. El **token d'API** (*refresh token*, dura 90 dies) es canvia a cada
execució per un **token d'accés** (JWT, 8 hores) amb `POST /iaas/api/login`. El script només
necessita el token d'API.

**Opció A: el teniu ja** (generat a la interfície web). Guardeu-lo en un fitxer amb permisos `600`:

```bash
mkdir -p ~/.config/vractl
install -m 600 /dev/null ~/.config/vractl/token
nano ~/.config/vractl/token        # enganxeu-hi el token, una sola línia
```

**Opció B: compte amb usuari i contrasenya.** `login` demana les credencials **al vostre terminal**,
obté el token d'API i el desa al mateix fitxer (permisos `600`). La contrasenya no es mostra,
no es desa i no es passa mai com a argument:

```bash
./vractl.py -h vra.example.org login
```

Si entreu per SSO, `login` no servirà: genereu el token d'API a la interfície web (opció A).

Ordre de cerca del token: variable `VRA_TOKEN`, després `VRA_TOKEN_FILE`, i si cap no està
definida, `~/.config/vractl/token`. Si el fitxer és accessible per altres usuaris, el script avisa.
Quan el token d'API caduca (90 dies), repetiu l'opció A o B.

Per comprovar que tot funciona (només lectura):

```bash
./vractl.py -h vra.example.org check
# OK: autenticat a vra.example.org; el vostre compte veu 12 VMs.
```

### TLS

El script **verifica el certificat del servidor**. Si el servidor no envia el certificat
**intermedi** de la seva CA (el navegador el resol sol, però `curl` i Python no), veureu un error
com *"No es pot verificar el certificat del servidor"*. Solucions, per ordre de preferència:

1. Que els administradors del servidor configurin la **cadena completa**.
2. Indicar al script el certificat intermedi que falta: `--ca-file ruta.pem` o `VRA_CA_FILE`. El
   fitxer (PEM) s'**afegeix** a les CA del sistema, no les substitueix, així que només cal l'intermedi.
   L'URL per baixar-lo és al camp *Authority Information Access* del certificat del servidor:

   ```bash
   echo | openssl s_client -connect vra.example.org:443 -servername vra.example.org 2>/dev/null \
     | openssl x509 -noout -ext authorityInfoAccess          # 'CA Issuers - URI:...'
   mkdir -p ca && curl -o ca/intermedi.cer <URI>
   openssl x509 -inform DER -in ca/intermedi.cer -out ca/intermedi.pem   # si és DER (si ja és PEM, copieu-lo)
   # Comproveu-ho abans de fer-lo servir (la descàrrega és per HTTP; la verificació la valida):
   echo | openssl s_client -connect vra.example.org:443 -servername vra.example.org 2>/dev/null \
     | openssl x509 > fulla.pem && openssl verify -untrusted ca/intermedi.pem fulla.pem   # ha de dir OK
   ./vractl.py -h vra.example.org --ca-file ca/intermedi.pem check
   ```

   Per no repetir-ho, definiu `VRA_CA_FILE` a l'entorn. El directori `ca/` està ignorat per git.
3. `VRA_INSECURE=1` desactiva la verificació (el script ho avisa a cada execució). **Només per
   proves:** el token s'envia sense comprovar qui hi ha a l'altre costat.

### Variables d'entorn

| Variable | Descripció |
|---|---|
| `VRA_HOST` | Servidor (alternativa a `-h`). |
| `VRA_TOKEN` | Token d'API. |
| `VRA_TOKEN_FILE` | Fitxer amb el token (defecte: `~/.config/vractl/token`). |
| `VRA_CA_FILE` | Certificats PEM addicionals de confiança, p.ex. un intermedi (alternativa a `--ca-file`). |
| `VRA_INSECURE` | `1` desactiva la verificació TLS. **Només per proves.** |
| `VRA_USER` | Usuari per a `login` (si no, el demana). |
| `VRA_API_VERSION` | Versió de la IaaS API (defecte `2021-07-15`; alternativa a `--api-version`). |

## Ús

```bash
./vractl.py list                                   # totes les VMs que veieu, per deployment
./vractl.py status web01                           # estat d'una VM (pel nom del deployment)

./vractl.py start web01                            # arrencar
./vractl.py shutdown web01                         # aturada neta (cal VMware Tools)
./vractl.py stop web01                             # aturada dura (power-off)
./vractl.py reboot web01
./vractl.py reset web01                            # reset dur
./vractl.py suspend web01
./vractl.py resume web01                           # = arrencar una VM suspesa

./vractl.py snapshot web01 pre-update --desc "abans d'actualitzar"
./vractl.py snapshot web01 amb-ram --memory        # inclou la memòria
./vractl.py snapshot web01 nocturn --keep 2        # rotació: en conserva els 2 més recents
./vractl.py snapshots web01                        # llistar (* = snapshot actual)
./vractl.py rollback web01 pre-update              # revertir
./vractl.py delsnap web01 pre-update               # esborrar
```

### Com s'identifiquen les VMs

Aria Automation agrupa les VMs en **deployments**, el nom dels quals sol ser més descriptiu que el
de la VM. Per això `vractl` identifica les VMs **pel nom del deployment**:

```
$ ./vractl.py list
DEPLOYMENT   VM        ESTAT  ADREÇA        ID
web-prod     vm-0012   ON     192.0.2.11    11111111-aaaa-bbbb-cccc-000000000001
db-prod      vm-0013   ON     192.0.2.12    22222222-aaaa-bbbb-cccc-000000000002
```

Allà on s'espera una VM, es pot donar (per aquest ordre de preferència):

1. el **nom del deployment** (`web-prod`). Si el deployment té diverses VMs, se seleccionen **totes**;
2. el **nom de la VM** (`vm-0012`);
3. l'**id** de la VM (un UUID).

Si un nom pot referir-se a dues coses diferents (p. ex. el nom d'un deployment i el nom d'una altra
VM, o dues VMs amb el mateix nom), el script ho diu i no fa res: feu servir l'id (l'última columna
de `list`). Els missatges mostren el deployment i, si és diferent, el nom de la VM entre parèntesis
(`web-prod (vm-0012)`). Si no es poden llegir els deployments, s'usen els noms de VM i s'avisa.
Per defecte el script espera que l'operació acabi (seguiment del *request tracker*) i falla si
Aria Automation la marca com a `FAILED`. Amb `--no-wait` retorna l'id del tracker immediatament
(l'opció va **abans** del subcomandament).

### Diverses VMs (`--parallel`)

Tots els subcomandaments accepten una o més VMs. Per defecte s'actua sobre una darrere l'altra;
amb `--parallel N`, fins a N alhora (opcions **abans** del subcomandament):

```bash
./vractl.py start web01 web02 web03
./vractl.py --parallel 4 start web01 web02 web03 web04
./vractl.py --parallel 3 snapshot web01 web02 web03 pre-update   # el NOM és l'últim argument
./vractl.py --yes delsnap web01 web02 pre-update
```

- **Snapshot, rollback i delsnap** tenen la forma `VM [VM...] NOM`: l'**últim argument és el nom
  del snapshot**. Les opcions del subcomandament (`--desc`, `--keep`...) van després.
- **Tot o res en la validació:** primer es resolen totes les VMs amb una sola consulta. Si alguna
  no existeix o el nom és ambigu, no es fa **res**.
- **Un error no atura les altres:** cada VM es reporta per separat, al final surt un resum i el
  codi de sortida és **1** si alguna ha fallat (útil per a cron i scripts).
- **Confirmació:** `stop`, `reset`, `rollback` i `delsnap` sobre **més d'una** VM demanen
  confirmació; sense terminal (cron) cal `--yes`. Amb una sola VM no es demana mai.
- Amb `--parallel`, les línies surten en l'ordre en què cada VM acaba.

### Seleccionar VMs per patró o per fitxer (`--match`, `--vms-file`)

```bash
./vractl.py --match 'www*' status                        # patró sobre el deployment, entre cometes
./vractl.py --match 'web-*' --parallel 4 --yes shutdown
./vractl.py --match 'web*' --match 'db*' start           # es pot repetir: unió dels patrons
./vractl.py --match 'web*' snapshot nocturn --keep 7     # amb --match, snapshot només necessita el NOM
./vractl.py --vms-file vms.txt status                    # una VM (nom o id) per línia, # = comentari
./vractl.py --match 'web*' list                          # a list, només filtra
```

Els patrons són de tipus shell (`*`, `?`, `[abc]`) i coincideixen amb el **nom del deployment o el
de la VM**; **distingeixen majúscules** i van ancorats a tot el nom (`web-*` no troba `old-web-1`;
cal `*web*`). Un patró pot
agafar més VMs de les previstes: abans de fer-hi res destructiu, comproveu-ho amb `list` o `status`.
Si un patró no coincideix amb cap VM, no es fa res.

### Rotació de snapshots (`--keep`)

Amb `--keep N`, el nom del snapshot passa a ser un **prefix**: s'hi afegeix la data i l'hora
(`nocturn-AAAAMMDD-HHMMSS`) i, un cop creat, s'esborren els més antics d'aquell prefix fins a
conservar-ne N. Primer es crea el nou i **després** s'esborren els antics; només es toquen els
snapshots que segueixen aquest patró. No es pot combinar amb `--no-wait`. Amb diverses VMs, totes
reben el mateix nom i cada una es rota pel seu compte.

```bash
./vractl.py snapshot web01 nocturn --keep 7        # per a cron: 0 2 * * * /ruta/vractl.py ...
```

Un snapshot també es pot indicar per **id** a `rollback` i `delsnap` (cal si dos tenen el mateix nom,
cosa que vSphere permet).

## Permisos i notes

- La IaaS API (`/iaas/api/machines…`) requereix permisos de **Cloud Assembly** sobre el projecte.
  Amb un rol només de *Service Broker* és possible que rebeu `403`; en aquest cas caldria la
  *Deployment API*, que aquest script no fa servir.
- Només veieu les VMs dels vostres projectes. Les polítiques de governança poden restringir
  accions concretes.
- Les operacions de Day 2 les fa Aria Automation sobre vCenter; poden tardar. El temps màxim
  d'espera per operació és de 15 minuts.
- Un `401` durant l'execució (token d'accés caducat) es resol sol amb un nou login. Un token d'API
  caducat o invàlid dona un error que indica com generar-ne un de nou.

## Llicència

MIT. Vegeu el fitxer [LICENSE](LICENSE).
