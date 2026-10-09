# vractl

Eina de línia d'ordres per gestionar màquines virtuals de **VMware Aria Automation 8.x** (abans
vRealize Automation): arrencar, aturar, reiniciar i fer snapshots d'una o més VMs, en sèrie o en
paral·lel. Fa servir les mateixes opcions que [pvectl](https://github.com/fbassas/pvectl) (la
versió per a Proxmox).

**Com parla amb Aria Automation.** Les *operacions* fan servir la **Deployment API** (la de
*Service Broker*): són les mateixes accions de Day 2 que la interfície web ofereix a cada VM
(*Power On*, *Create Snapshot*...) i no cal ser administrador de Cloud Assembly, només tenir permís
per fer-les a la web. Les *lectures* (llistar VMs i snapshots) fan servir la IaaS API.

> **Estat:** s'ha provat amb un servidor Aria Automation **simulat** (HTTPS, login, peticions
> d'acció, seguiment, reintents) i **contra una instància real**: lectura (`check`, `list`, `status`,
> `snapshots`), `snapshot` (amb un snapshot existent, que s'esborra abans de crear el nou, i sense
> cap) i `delsnap`. **Encara no s'han provat en real** `shutdown`, `stop`, `reboot`, `reset`,
> `suspend`, `rollback`, `--parallel` ni `--no-wait`. Feu les primeres amb una VM de prova.

Operacions: arrencar, aturar (dur o net), reiniciar, reset, suspendre/reprendre, crear/llistar/
revertir/esborrar snapshots i consultar l'estat.

## Requisits

- Python 3.8 o superior (no cal cap paquet extern).
- Accés HTTPS (443) al servidor d'Aria Automation.
- Un compte amb permís per fer accions de Day 2 a les VMs des de la interfície web (vegeu *Permisos*).

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
2. **`fetch-ca`**: baixa i verifica el certificat intermedi que falta, i el desa:

   ```bash
   ./vractl.py -h vra.example.org fetch-ca
   # vra.example.org no es verifica amb les CA actuals (unable to get local issuer certificate). Busco...
   #   + SHA-256 AB12CD...  (de http://crt.example.org/intermedi.cer)
   # Verificat: amb aquest certificat, vra.example.org es verifica contra les CA del sistema.
   # Desat a ~/.config/vractl/ca.pem. vractl el fa servir automàticament.
   ```

   Es fa un cop per servidor i màquina. El fitxer `~/.config/vractl/ca.pem` es **carrega sempre**
   (afegit a les CA del sistema, no les substitueix), així que no cal cap opció més. Si el servidor ja
   es verifica, no fa res. Amb `--out FITXER` el desa on vulgueu (llavors cal `--ca-file FITXER` o
   `VRA_CA_FILE`); si el fitxer ja existeix, hi **afegeix** el certificat sense esborrar el que hi
   havia.

   Com és segur, tot i que el certificat del servidor es llegeix sense verificar i l'intermedi es
   baixa per HTTP (és el que indica el certificat, camp *Authority Information Access*):
   - només es desa si, amb aquest certificat afegit, **OpenSSL verifica una connexió real** al servidor:
     cadena completa fins a una **arrel de les CA del sistema**, i nom del servidor. Si no, no es desa
     res;
   - **es rebutgen** els certificats baixats que siguin **arrels** (autosignades): una arrel que
     vingui de la xarxa no es pot creure, ha de ser ja al sistema;
   - només es baixa per `http(s)://`, amb mida màxima de 64 KB;
   - es mostra l'empremta SHA-256, per comparar-la si voleu.

   Si el sistema no té les arrels (típic en contenidors mínims), falla amb un missatge que ho explica:
   instal·leu el paquet `ca-certificates`.

   *A mà*, sense `fetch-ca`: el fitxer PEM de l'intermedi es pot passar amb `--ca-file ruta.pem` o
   `VRA_CA_FILE`; l'URL per baixar-lo és al camp *Authority Information Access* del certificat
   (`openssl x509 -noout -ext authorityInfoAccess`).
3. `VRA_INSECURE=1` desactiva la verificació (el script ho avisa a cada execució). **Només per
   proves:** el token s'envia sense comprovar qui hi ha a l'altre costat.

### Variables d'entorn

| Variable | Descripció |
|---|---|
| `VRA_HOST` | Servidor (alternativa a `-h`). |
| `VRA_TOKEN` | Token d'API. |
| `VRA_TOKEN_FILE` | Fitxer amb el token (defecte: `~/.config/vractl/token`). |
| `VRA_CA_FILE` | Certificats PEM addicionals de confiança, p.ex. un intermedi (alternativa a `--ca-file`). A més, sempre es carrega `~/.config/vractl/ca.pem` si existeix (el desa `fetch-ca`). |
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
./vractl.py snapshot web01 amb-ram --memory        # inclou la memòria (per defecte NO)
./vractl.py snapshots web01                        # llistar, amb id (* = snapshot actual)
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
Cada operació és una **petició** (*request*) a Aria Automation. Per defecte el script espera que
acabi i falla si l'estat és `FAILED`, `ABORTED` o `APPROVAL_REJECTED` (mostrant-ne els detalls). Si la
petició queda esperant una **aprovació** o una acció d'un usuari, no s'espera indefinidament: ho diu
i la petició continua pendent a Aria. Si Aria respon `409` (conflicte, normalment perquè hi ha una
altra operació en curs sobre la VM), es reintenta fins a 5 vegades cada 10 s. Amb `--no-wait`
retorna l'id de la petició immediatament (l'opció va **abans** del subcomandament).

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
  del snapshot**. Les opcions del subcomandament (`--desc`, `--memory`) van després.
- **Tot o res en la validació:** primer es resolen totes les VMs amb una sola consulta. Si alguna
  no existeix o el nom és ambigu, no es fa **res**.
- **Un error no atura les altres:** cada VM es reporta per separat, al final surt un resum i el
  codi de sortida és **1** si alguna ha fallat (útil per a cron i scripts).
- **Confirmació:** `stop`, `reset`, `rollback` i `delsnap` sobre **més d'una** VM demanen
  confirmació; sense terminal (cron) cal `--yes`. Amb una sola VM no es demana mai. (El `snapshot`
  té la seva pròpia confirmació, vegeu més avall.)
- Amb `--parallel`, les línies surten en l'ordre en què cada VM acaba.

### Seleccionar VMs per patró o per fitxer (`--match`, `--vms-file`)

```bash
./vractl.py --match 'www*' status                        # patró sobre el deployment, entre cometes
./vractl.py --match 'web-*' --parallel 4 --yes shutdown
./vractl.py --match 'web*' --match 'db*' start           # es pot repetir: unió dels patrons
./vractl.py --match 'web*' snapshot abans-update         # amb --match, snapshot només necessita el NOM
./vractl.py --vms-file vms.txt status                    # una VM (nom o id) per línia, # = comentari
./vractl.py --match 'web*' list                          # a list, només filtra
```

Els patrons són de tipus shell (`*`, `?`, `[abc]`) i coincideixen amb el **nom del deployment o el
de la VM**; **distingeixen majúscules** i van ancorats a tot el nom (`web-*` no troba `old-web-1`;
cal `*web*`). Un patró pot
agafar més VMs de les previstes: abans de fer-hi res destructiu, comproveu-ho amb `list` o `status`.
Si un patró no coincideix amb cap VM, no es fa res.

### Snapshots: com a màxim 1 per VM

`vractl` manté **com a màxim 1 snapshot per VM**. Els snapshots acumulats penalitzen el rendiment
de la VM, i Aria Automation pot limitar-ne el nombre (per exemple amb la propietat personalitzada
`snapshotLimit`): quan se supera el límit, rebutja la creació amb un error com *«Exceeded number of
snapshots»*. Per evitar-ho, `snapshot` fa això, VM per VM:

1. **Mira si la VM ja té algun snapshot.**
2. Si **no en té cap**, el crea (no pregunta res).
3. Si **en té**, en mostra el nom i la **data** i **demana confirmació** per esborrar-lo. Si
   confirmeu, l'**esborra primer** i, un cop esborrat, **crea el nou**. Si no, aquesta VM s'omet.

```
$ ./vractl.py snapshot web-prod abans-update
web-prod (vm-0012) ja té 1 snapshot (vractl en manté com a màxim 1 per VM):
  - 'antic', del 2026-01-15 (descripció)
Esborrar-lo i crear-ne un de nou ('abans-update')? [s/N] s
Esborrat el snapshot existent: 'antic', del 2026-01-15 (descripció)
OK: snapshot web-prod (vm-0012)
```

- El per defecte és **no** (Intro = no). Accepten `s`, `si`, `sí`, `y` i `yes`.
- **`--yes`** respon que sí a tot: és el que cal en un cron o script, on no hi ha terminal. Sense
  terminal i sense `--yes`, el script **es nega** a esborrar res i no fa **cap** canvi, ni a les VMs
  que no tenien snapshot.
- Amb **diverses VMs**, totes les preguntes es fan **abans** de començar i després s'actua (en
  paral·lel si cal). Només es pregunta per les VMs que ja tenen snapshot. Les omeses surten al resum
  i no compten com a error.
- Si una VM en té **més d'un** (per exemple, VMs antigues), es mostren **tots** amb la seva data i
  la pregunta és si els voleu esborrar tots; si confirmeu, s'esborren tots abans de crear el nou.
- L'esborrat sempre s'espera a que acabi, encara que useu `--no-wait`.
- **Compte:** com que primer s'esborra i després es crea, si la creació falla (per exemple, per
  espai) **la VM es queda sense cap snapshot**. El script ho diu explícitament a l'error. Si
  l'esborrat falla, no es crea el nou.

Un snapshot també es pot indicar per **id** a `rollback` i `delsnap`. Cal si dos snapshots tenen el
mateix nom, cosa que vSphere permet: el script ho detecta, no fa res i us demana l'id. `snapshots` el
mostra a la tercera columna:

```
* abans-update              2026-01-15  33333333-aaaa-bbbb-cccc-000000000001  descripció
  abans-update              2026-01-08  44444444-aaaa-bbbb-cccc-000000000002  descripció
```

## Permisos i notes

- Les operacions són les accions de Day 2 de *Service Broker*, així que necessiteu el mateix permís
  que a la web: amb un rol de consumidor n'hi ha prou. (La **IaaS API** directa exigeix rols de
  Cloud Assembly: amb només Service Broker permet llegir però respon `403` a qualsevol acció, per
  això `vractl` no la fa servir per operar.) Si una acció us dona `403`, el vostre compte no la pot
  fer sobre aquella VM.
- **Memòria als snapshots:** la interfície web crea els snapshots **amb memòria** per defecte;
  `vractl` **no**, tret que indiqueu `--memory`. Un snapshot amb memòria d'una VM encesa triga més i
  pot aturar-la breument.
- **Data dels snapshots:** s'usa la data **real** de vCenter, no la de registre a Aria (que pot ser
  molt posterior si la VM es va incorporar després).
- Només veieu les VMs dels vostres projectes. Les polítiques de governança poden restringir
  accions concretes.
- Les operacions de Day 2 les fa Aria Automation sobre vCenter; poden tardar. El temps màxim
  d'espera per operació és de 15 minuts.
- Un `401` durant l'execució (token d'accés caducat) es resol sol amb un nou login. Un token d'API
  caducat o invàlid dona un error que indica com generar-ne un de nou.

## Llicència

MIT. Vegeu el fitxer [LICENSE](LICENSE).
