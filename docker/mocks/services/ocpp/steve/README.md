# SteVe - real OCPP Central System (CSMS) mock for OIDA

This directory stands up **SteVe** (SteckdosenVerwaltung,
<https://github.com/steve-community/steve>), a genuine open-source OCPP
1.2/1.5/1.6 Central System Management System, as a multi-config integration
target for OIDA's `ocpp` scanner. It replaces nothing - it runs **alongside**
the lightweight Python `ocpp-insecure` simulator in `../mock/` and gives the
scanner a real OCPP server to talk to (real WebSocket handshake, real
BootNotification/Heartbeat CALL/CALLRESULT framing, real web UI + SOAP/Web API).

## License (GPL - built from source, not redistributed)

SteVe is licensed under the **GNU General Public License v3.0-or-later**.

* `Dockerfile.steve` **builds SteVe from source** at image-build time: it
  `git clone`s a pinned upstream release tag and runs `./mvnw package`. The
  resulting `steve.war` exists **only inside the built image layer**.
* **No SteVe binary/jar/war is committed to this repository or distributed by
  it.** Only this Dockerfile and the text config/SQL files here are committed.
* Because the artifact is reproduced from upstream source on the user's own
  machine, this repo redistributes neither modified nor unmodified SteVe
  binaries. The SPDX header in `Dockerfile.steve` records the license.

To pin a different release, override the build arg:
`--build-arg STEVE_TAG=steve-3.13.0`.

## Architecture

One shared **MariaDB** backend (`ocpp-steve-db`, image `mariadb:10.11.16`,
matching upstream) plus **three SteVe app containers** that share a single
built image and differ only by **runtime Spring property overrides**
(`JAVA_OPTS=-D...`) and by which **database schema** they use. SteVe 3.x is a
Spring Boot app, so every `application-*.properties` key (`db.*`, `http.port`,
`https.enabled`, `auto.register.unknown.stations`, ...) is overridable at runtime
via Spring relaxed binding - one image, three behaviours, no rebuild.

Each app gets its own schema (`stevedb_open` / `stevedb_registered` /
`stevedb_secure`, created by `initdb/01-schemas.sql`) so registered-chargebox
state does not bleed between configs.

## The three configurations

| Service | Host port | Scheme | DB schema | `auto.register.unknown.stations` | Meaning for the scanner |
|---|---|---|---|---|---|
| `ocpp-steve-open`       | 8180 | http  | `stevedb_open`       | **true**  | Open CSMS: accepts a WebSocket + BootNotification from **any** chargeBoxId. `oida ocpp` gets a clean CALLRESULT with no pre-registration. |
| `ocpp-steve-registered` | 8181 | http  | `stevedb_registered` | **false** | Hardened CSMS: **rejects** unknown chargeBoxIds (closes the WebSocket) - only charge boxes pre-registered via the Web UI/API are accepted. Tests the scanner's "BootNotification from unknown CP rejected" path (`--check-unknown-cp`). |
| `ocpp-steve-secure`     | 8543 | https | `stevedb_secure`     | **false** | Same reject-unknown policy but served over **HTTPS/WSS** (`wss://...`) with a self-signed keystore generated at container start. Tests TLS/`wss` handling. |

All three share web-UI creds **admin / 1234** (SteVe docker defaults) and Web
API key header **`STEVE-API-KEY: <empty>`** unless overridden.

### OCPP / web endpoints (context path `/steve`)

* Web UI:        `http(s)://<host>:<port>/steve/manager` (admin / 1234)
* OCPP WebSocket: `ws(s)://<host>:<port>/steve/websocket/CentralSystemService/<chargeBoxId>`
* OCPP SOAP:     `http(s)://<host>:<port>/steve/services/CentralSystemService`
* Web API:       `http(s)://<host>:<port>/steve/api/v1/...` (header `STEVE-API-KEY`)

## Scanning with OIDA

SteVe's WebSocket path is **not** the scanner's default `/<chargeBoxId>`, so
pass it explicitly with `--ws-path`:

```bash
# Open config (accepts any chargeBoxId)
oida ocpp 127.0.0.1 --port 8180 \
    --ws-path /steve/websocket/CentralSystemService/CP_SCANNER_001

# Registered-only config (unknown CP rejected)
oida ocpp 127.0.0.1 --port 8181 --check-unknown-cp \
    --ws-path /steve/websocket/CentralSystemService/CP_SCANNER_001

# Secure config (wss) - self-signed cert, so use --tls-insecure and put the
# path IN the URL (a full wss:// target takes its path from the URL):
oida ocpp wss://127.0.0.1:8543/steve/websocket/CentralSystemService/CP_SCANNER_001 \
    --tls-insecure
```

## Pre-registering a charge box (registered-only / secure configs)

The `registered`/`secure` configs reject unknown chargeBoxIds by design (the
WebSocket handshake returns HTTP 404). To make a chargeBoxId acceptable, add it
as a charge point. Three ways:

1. **Web UI** (simplest): log in to `/steve/manager` (admin / 1234) ->
   *Charge Points* -> *Add* -> set the chargeBoxId.

2. **Direct DB insert** (scriptable, used by the verification below). SteVe
   creates the `charge_box` table on first boot, so insert after it is up:
   ```bash
   docker exec ocpp-steve-db mariadb -usteve -pchangeme stevedb_registered \
     -e "INSERT IGNORE INTO charge_box (charge_box_id, registration_status) \
         VALUES ('CP_SCANNER_001','Accepted');"
   # same for stevedb_secure
   ```

3. **Web API**: only works if `webapi.value` is set (empty by default, so the
   API is disabled and all calls 302-redirect to signin). Enable it by adding
   `-Dwebapi.value=<secret>` to that service's `JAVA_OPTS`, then:
   ```bash
   curl -X POST http://127.0.0.1:8181/steve/api/v1/chargepoints \
     -H 'STEVE-API-KEY: <secret>' -H 'Content-Type: application/json' \
     -d '{"chargeBoxId":"CP_SCANNER_001"}'
   ```

## Notes

* SteVe boot is slow: Spring Boot + migrations take ~30-90 s after the WAR
  build. Compose healthchecks use a long `start_period`. The **image build**
  itself runs a full Maven build the first time and can take several minutes.
* MariaDB timezone is pinned to UTC (`TZ=+00:00`) to match SteVe's requirement.
