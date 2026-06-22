# MQTT Scanner Test Cases

## Authentication Tests

### Password Authentication
| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| AUTH-01 | Anonymous connection | No credentials | Check CONNACK code |
| AUTH-02 | Valid credentials | admin:admin | CONNACK 0 (success) |
| AUTH-03 | Invalid password | admin:wrong | CONNACK 5 (not authorized) |
| AUTH-04 | Invalid username | fake:fake | CONNACK 5 (not authorized) |
| AUTH-05 | Empty password | admin:"" | Broker-dependent |
| AUTH-06 | Brute-force single user | admin + wordlist | Find valid password |
| AUTH-07 | Brute-force user:pass pairs | credentials.txt | Find valid pairs |

### TLS Client Certificate Authentication
| Test ID | Test Case | Input | Expected |
|---------|-----------|-------|----------|
| TLS-01 | Connect with valid cert | client.crt + client.key | Success |
| TLS-02 | Connect without cert (cert required) | No cert | Rejected |
| TLS-03 | Connect with expired cert | expired.crt | Rejected |
| TLS-04 | Connect with untrusted CA | self-signed.crt | Rejected (unless --tls-insecure) |
| TLS-05 | Mutual TLS + password | cert + user:pass | Both validated |

---

## Topic Discovery Tests

| Test ID | Test Case | Subscribe Pattern | Purpose |
|---------|-----------|-------------------|---------|
| ENUM-01 | All topics | `#` | Full topic enumeration |
| ENUM-02 | System topics | `$SYS/#` | Broker info disclosure |
| ENUM-03 | Sparkplug namespace | `spBv1.0/#` | ICS infrastructure |
| ENUM-04 | Single-level wildcard | `+/+/status` | Pattern matching |
| ENUM-05 | Specific prefix | `factory/#` | Scoped enumeration |
| ENUM-06 | Retained messages only | Subscribe + check retain flag | Historical data |

---

## ICS/Sparkplug Discovery Tests

| Test ID | Test Case | Data Extracted |
|---------|-----------|----------------|
| SPB-01 | NBIRTH collection | Edge node IDs, groups |
| SPB-02 | DBIRTH collection | Device IDs per node |
| SPB-03 | Metric extraction | Tag names, datatypes, values |
| SPB-04 | Hardware fingerprint | Make, model, firmware from Properties/* |
| SPB-05 | DDATA monitoring | Live process values |
| SPB-06 | Node/device inventory | Full asset list |

---

## ACL / Authorization Tests

| Test ID | Test Case | Action | Expected |
|---------|-----------|--------|----------|
| ACL-01 | Subscribe restricted topic | SUB to admin/# | SUBACK 0x80 (failure) |
| ACL-02 | Publish to read-only topic | PUB to sensors/# | Silently dropped |
| ACL-03 | Access other user's topics | SUB to user2/# | Denied |
| ACL-04 | $SYS write attempt | PUB to $SYS/test | Denied |

---

## Brute-Force Tests

### Single Username Attack
```
Target: admin
Wordlist: rockyou-mqtt.txt (admin, password, 123456, mqtt, ...)
Rate: 10 attempts/sec (configurable)
Stop on: First success
```

### Credential Pair Attack
```
Wordlist format: username:password
Common pairs: admin:admin, root:root, mqtt:mqtt, user:user
```

### Default ICS Credentials
```
# Common MQTT/ICS defaults
admin:admin
operator:operator
mqtt:mqtt
mosquitto:mosquitto
ics:ics
scada:scada
plc:plc
hmi:hmi
guest:guest
test:test
user:password
admin:password
root:root
```

---

## Message Interception Tests

| Test ID | Test Case | Duration | Output |
|---------|-----------|----------|--------|
| MSG-01 | Passive capture | 30s | Topic list + message samples |
| MSG-02 | Continuous logging | Until stopped | Full message log |
| MSG-03 | Filtered capture | Topic pattern | Targeted messages |
| MSG-04 | Payload decode | Auto-detect | JSON, Sparkplug, hex |

---

## Continuous Listen Mode

### Purpose
Real-time monitoring of MQTT traffic for:
- Long-term traffic analysis
- Detecting anomalies and unauthorized publishes
- Capturing intermittent ICS events (alarms, state changes)
- Building topic/device inventory over time

### CLI Arguments
```
--listen                  # Enable continuous listen mode
--listen-topics PATTERN   # Topics to monitor (default: #)
--listen-output FILE      # Log to file (JSON lines format)
--listen-filter REGEX     # Filter messages by payload content
--listen-stats INTERVAL   # Print stats every N seconds
--listen-quiet            # Suppress message output, stats only
```

### Output Modes

**Real-time Console (default)**
```
[21:45:01] factory/plc1/temperature = 23.5
[21:45:01] factory/plc1/pressure = 101.3
[21:45:02] spBv1.0/Factory-Floor/DDATA/PLC-001/Conveyor-1 = {"metrics":[...]}
[21:45:05] scada/alarms = {"level":"warning","code":42}
^C
--- Statistics ---
Duration: 5m 32s
Messages: 1,523
Topics: 47
Avg rate: 4.6 msg/s
```

**JSON Lines Output (--listen-output)**
```json
{"ts":"2025-12-15T21:45:01Z","topic":"factory/plc1/temperature","payload":"23.5","qos":0,"retain":false}
{"ts":"2025-12-15T21:45:01Z","topic":"factory/plc1/pressure","payload":"101.3","qos":1,"retain":false}
```

**Stats Only (--listen-quiet)**
```
[5s] msgs=23 topics=8 rate=4.6/s
[10s] msgs=51 topics=12 rate=5.1/s
[15s] msgs=74 topics=12 rate=4.9/s
```

### Filters

**Topic filter**
```bash
msf-ics mqtt 192.168.1.100 --listen --listen-topics "factory/#"
msf-ics mqtt 192.168.1.100 --listen --listen-topics "spBv1.0/+/DDATA/#"
```

**Payload filter (regex)**
```bash
msf-ics mqtt 192.168.1.100 --listen --listen-filter "alarm|error|fault"
msf-ics mqtt 192.168.1.100 --listen --listen-filter "temperature.*[3-9][0-9]"  # Temp > 30
```

### Use Cases

| Use Case | Command |
|----------|---------|
| Monitor all traffic | `--listen` |
| Watch alarms only | `--listen --listen-topics "+/alarms"` |
| Log to file | `--listen --listen-output mqtt_capture.jsonl` |
| Sparkplug monitoring | `--listen --listen-topics "spBv1.0/#"` |
| Find sensitive data | `--listen --listen-filter "password\|secret\|key"` |
| Traffic stats | `--listen --listen-quiet --listen-stats 10` |

---

## Scanner Modes

### Quick Scan (--quick)
- Anonymous auth test
- $SYS/broker/version
- 5 second topic enumeration

### Discovery Scan (--discover)
- Auth test
- Full topic enumeration (30s)
- Sparkplug namespace check
- Broker info extraction

### Full Scan (--full)
- All discovery tests
- ACL testing
- Extended monitoring (60s)
- Retained message collection

### Brute-Force Mode (--brute)
- Credential testing with wordlist
- Default credential check
- Rate-limited attempts

---

## CLI Arguments Needed

```
# Connection
--port PORT           # Default 1883
--tls                 # Enable TLS (default port 8883)
--tls-port PORT       # Custom TLS port

# Password Auth
-u, --username USER   # MQTT username
-p, --password PASS   # MQTT password

# TLS Client Certs
--tls-cert FILE       # Client certificate
--tls-key FILE        # Client private key
--tls-ca FILE         # CA certificate
--tls-insecure        # Skip cert verification

# Brute-Force
--brute               # Enable brute-force mode
--wordlist FILE       # Password wordlist
--userlist FILE       # Username list (optional)
--credentials FILE    # user:pass pairs file
--brute-rate N        # Attempts per second (default 10)
--stop-on-success     # Stop after first valid cred

# Topic Enumeration
--topics PATTERN      # Custom subscription pattern
--enumerate-sys       # Include $SYS/#
--enumerate-all       # Subscribe to #
--sparkplug           # Include spBv1.0/#
--timeout SECS        # Enumeration timeout

# Message Capture
--intercept           # Enable message logging
--duration SECS       # Capture duration
--decode              # Auto-decode payloads

# Scan Modes
--quick               # Fast scan
--discover            # Discovery scan
--full                # Comprehensive scan

# Continuous Listen Mode
--listen              # Enable listen mode (runs until Ctrl+C)
--listen-topics PAT   # Topic pattern (default: #)
--listen-output FILE  # Log to JSON lines file
--listen-filter REGEX # Filter by payload regex
--listen-stats N      # Print stats every N seconds
--listen-quiet        # Stats only, no message output
```

---

## Test Against Mock Services

| Port | Service | Test Focus |
|------|---------|------------|
| 1883 | Insecure | Anonymous access, wildcard subs, $SYS exposure |
| 1884 | Auth | Credential testing, brute-force, ACLs |
| 1885 | Sparkplug | ICS discovery, NBIRTH/DBIRTH parsing |
