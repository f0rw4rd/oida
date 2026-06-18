# OCPP / EV Charger Default Credentials

## OCPP WebSocket Authentication

OCPP SecurityProfile 1/3 uses HTTP Basic Auth where **chargePointId = username** and
**AuthorizationKey = password**. Many chargers ship at SecurityProfile 0 (no auth at all).

| SecurityProfile | Transport | Auth | Default in Practice |
|----------------|-----------|------|---------------------|
| 0 | ws:// | None | Very common out-of-box |
| 1 | ws:// | HTTP Basic (cpId + AuthorizationKey) | Common; credentials in cleartext |
| 2 | wss:// | HTTP Basic + Server TLS | Recommended minimum |
| 3 | wss:// | Mutual TLS + Client cert | Highest; complex to deploy |

---

## Charger Web Interface / Admin Credentials

### Confirmed Hardcoded/Default Credentials

| Vendor | Username | Password | Interface | CVE/Advisory |
|--------|----------|----------|-----------|-------------|
| Schneider EVlink | `admin` | `ADMIN` | Web (192.168.0.102) | CVE-2018-7800, CVE-2021-22707 |
| Schneider EVlink | `user` | `USER` | Web (192.168.0.102) | CVE-2018-7800, CVE-2021-22707 |
| Schneider EVlink (bypass) | cookie-based | CURLTOKEN=`b35fcdc1ea1221e6dd126e172a0131c5a`, SESSIONID=`admin` | Web | CVE-2021-22707 |
| Alpitronic Hypercharger | `admin` | `admin123` | Web | CVE-2024-4622 |
| Phoenix Contact CHARX | `manufacturer` | `manufacturer` | Web | VDE-2024-011 |
| Phoenix Contact CHARX | `user-app` | `user` (reset default) | SSH | |
| Bender CC612/CC613 | `operator` | `yellow_zone` | Web / USB | |
| Vestel EVC04 | `admin` | `admin` | Web (192.168.0.10) | |
| Vestel EVC04 (E.ON) | `admin` | `eon01` | Web | |
| Enelion Lumina | `admin` | `admin` | Web (192.168.8.8) | |
| Etrel INCH | `root@etrel.com` | `toor` | Web (192.168.1.250) | |
| Juice Charger me | `operator` | `JuiCeMeUP!` | Web (192.168.123.123) | |
| Juice Charger me | `manufacturer` | (unknown) | Web /legacy/manufacturer/ | |
| Project EV | (none) | `12345678` | Web / WiFi AP | |
| Delta AC MAX Basic | `admin` | (on sticker) | Web (192.168.5.1) | |
| Delta AC MAX (app FW) | (none) | `1234567890123456` | App firmware update | |
| Delta AC MAX (logs) | (none) | `SN+@delta` (SN=serial) | Log extraction | |
| cFos Charging Manager | `admin` | (blank/empty) | Web (port 4712) | |
| OpenEVSE | (none) | `openevse` | WiFi AP | |
| Beny / Generic Chinese | (none) | `12345678` | WiFi AP (192.168.1.1) | |
| KEBA P30 x-series | `admin` | serial number | Web (192.168.42.1 via hotspot) | |
| KEBA P30 c-series | (none) | (none required) | Web (read-only) | |
| KEBA M10/M20 Controller | `admin` | serial number | Web | |
| Fronius inverters (SnapINverter) | `admin`/`service`/`user` | set by installer | Web (192.168.250.181 WiFi, 169.254.0.180 LAN) | |
| Fronius SnapINverter (backdoor) | `today` | daily rotating hash from device-ID + date | Web -- full admin access | CVE-2019-19228 |
| Fronius Smart Meter IP | (none) | `123` (initial) | Web (192.168.250.181) | |

### Per-Unit Unique Credentials (on sticker/label)

| Vendor | Where to Find | Interface |
|--------|--------------|-----------|
| ABB Terra AC | PIN code on sticker (BLE pairing) | TerraConfig app |
| Alfen Eve | Physical leaflet/flyer attached to charger | Web |
| Webasto Live | Label in manual (WLAN Key + login password) | Web (172.20.0.1) |
| Mennekes Amtron | Set-up data sheet (per socket) | Web |
| EVBox | Sticker inside the unit | Web (192.168.0.1) |
| KEBA P30 x-series | Serial number = web password; hotspot creds on config label | Web / WiFi AP |
| KEBA P40 | User PWD + Installer PWD + BLE PIN on quick-start sticker | App / Web |
| Fronius Wattpilot | Hotspot key on physical Reset Card (RFID-enabled) | WiFi AP / App |

### Cloud-Only Managed (No Local Default)

| Vendor | Notes |
|--------|-------|
| Wallbox (Pulsar, Commander) | Managed via myWallbox app. OCPP password optional. |
| ChargePoint | Cloud-managed. Activation email to owner. |
| Easee | OAuth2 JWT via cloud account only. |
| Siemens VersiCharge | Password created during cloud registration. Forbidden: pass123, admin, guest, test, root |

---

## Hardcoded Keys / Backdoors

| Vendor | Type | Value | CVE |
|--------|------|-------|-----|
| Schneider EVlink | Firmware signing key | `67acdb2bce676ac1b1766c99b07f37fa591ea5f39f57afc874bab704a0a36964` | CVE-2021-22708 |
| eCharge Hardy Barth | Hardcoded SSH authorized keys | Embedded in firmware (backdoor to all devices) | CVE-2025-48416 |
| eCharge Hardy Barth | Shared Basic Auth API creds | Firmware-embedded for saliaportal.echarge.de | CVE-2025-48417 |
| eCharge Hardy Barth | Hardcoded root password hashes | /etc/passwd and /etc/shadow | CVE-2025-48413 |
| Autel MaxiCharger | Debug credentials | Left from development | CVE-2024-23958 |
| Fronius SnapINverter | Backdoor account `today` | Daily rotating hash (device-ID + date); full admin | CVE-2019-19228 |

---

## Unauthenticated Network Interfaces

Protocols with **zero authentication** by design -- network access = full control.

| Vendor | Protocol | Port | Access | Notes |
|--------|----------|------|--------|-------|
| KEBA P30 (all series) | UDP | 7090 | Read + control (when DIP D1.3=ON) | Start/stop charging, set current limits |
| KEBA P30 (all series) | Modbus TCP | 502 | Read + write registers | Unit ID 255 |
| Fronius inverters (all) | Solar API v1 | 80 | Read-only HTTP API | Always-on (SnapINverter), disabled by default (GEN24) |
| Fronius inverters (all) | Modbus TCP | 502 | Read + write registers | Disabled by default; no auth once enabled |
| Fronius Datamanager 2.0 | Web (Position A) | 80 | Full admin -- no login | Physical switch on Datamanager card |

---

## OCPP Central System / CSMS Defaults

### SteVe

| Component | Username | Password |
|-----------|----------|----------|
| Web Interface (application-prod.properties) | `admin` | `1234` |
| RPi Image - Web | `admin` | `keba12` |
| RPi Image - MySQL root | `root` | `steve` |
| RPi Image - MySQL steve | `steve` | `keba12` |
| RPi Image - Java keystore | n/a | `keba12` |

### Open e-Mobility (SAP Labs France ev-server)

| Component | Username | Password |
|-----------|----------|----------|
| Master Tenant Admin | `super.admin@ev.com` | `Super.admin00` |
| SLF Tenant Admin | `slf.admin@ev.com` | `Slf.admin00` |
| Database | `evse-admin` | `evse-admin-pwd` |

### CitrineOS

| Component | Username | Password |
|-----------|----------|----------|
| RabbitMQ (docker dev) | `guest` | `guest` |

### MaEVe (ThoughtWorks)

Accepted charge stations and credentials are **hard-coded in `gateway/cmd/serve.go`**.

### OCPP-CS (apostoldevel)

| Component | Username | Password |
|-----------|----------|----------|
| Webhook config example | `ocpp` | `ocpp` |

---

## WiFi Hotspot Defaults

| Vendor | SSID Pattern | Default Password |
|--------|-------------|-----------------|
| OpenEVSE | `OpenEVSE_XXXX` | `openevse` |
| Webasto Live | `Webasto!Live_XXXX` | On manual sticker |
| Vestel EVC04 | Serial number | Chargebox-ID |
| Project EV | Vendor-specific | `12345678` |
| Beny / Generic Chinese | Vendor-specific | `12345678` |
| Delta AC MAX | Serial number | On sticker |
| Grizzl-E Smart | Serial number | (connect at 192.168.4.1) |
| KEBA P30 x-series | Device-specific numeric SSID | Device-specific (on config label) |
| Fronius SnapINverter | `FRONIUS_240.XXXXXX` | `12345678` |
| Fronius GEN24 / Tauro | `Fronius_3XXXXXXX` | `12345678` |
| Fronius Wattpilot | `Wattpilot_<serial>` | Unique per device (on Reset Card) |
| Fronius Smart Meter IP | `FroniusMeter_XXXXX` | Device-specific (on unit) |

---

## Common Test idTags / RFID Values

| Context | idTag | Notes |
|---------|-------|-------|
| OIDA Scanner default | `OIDA_SEC_TEST_00000000` | Non-matching fake tag |
| Generic test | `test` | Common in simulators |
| Chinese EVSE auth code | `123456` | Beny and similar (unverified from official docs) |
| FreeCharging mode | Configured per charger | Charger sends without RFID |

---

## Sources

- SEC Consult - Schneider EVlink Advisory
- CISA ICSA-19-031-01, ICSA-24-130-02, ICSA-25-023-03, ICSA-25-135-08
- CERT VDE VDE-2024-011, VDE-2025-014
- iVision Research - CHARX Exploitation
- ONEKEY - eCharge Controllers Analysis
- Pen Test Partners - Smart Car Chargers
- ZDI / Pwn2Own Automotive 2024/2025
- SEC Consult - Fronius SnapINverter Advisory (CVE-2019-19228, CVE-2019-19229)
- KEBA KeContact P30 Configuration Manual (ManualsLib)
- KEBA UDP Programmers Guide
- Fronius Datamanager 2.0 Operating Instructions
- Fronius Solar API V1 Documentation
- Vendor documentation and manuals (ManualsLib, GitHub, support pages)
