# Real-traffic capture harness for hash fixtures

These scripts spin up throwaway service containers + real clients, capture the
authentication handshake with a `tcpdump` sidecar (sharing the server
container's network namespace — needs only the `docker` group, not host root),
and save the result as a pcap fixture under `tests/fixtures/pcap/<proto>/`.

Each fixture is validated end-to-end: OIDA extracts the hash line, and the line
is cracked with hashcat/John against the **known** password baked into the
capture. The matching integration test pins the exact extracted line.

| Fixture | Tool/mode | User | Password | Verified crack |
|---|---|---|---|---|
| `pgsql/oida_pgsql_md5.pcap` | hashcat 11100 | `oida` | `S3cretPg1` | ✅ hashcat |
| `mysql/oida_mysql_native.pcap` | hashcat 11200 | `oida` | `S3cretMy1` | ✅ hashcat |
| `http/oida_http_digest.pcap` | John `hdaa` | `oida` | `S3cretHt1` | ✅ RFC2617 recompute¹ |
| `smb/oida_ntlmv2_smb.pcap` | hashcat 5600 | `oida` | `S3cretNt1` | ✅ hashcat (impacket oracle²) |
| `vnc/wireshark_vnc.pcap` (existing) | John `vnc` | — | unknown | ✅ Wireshark RFB dissector³ |
| `ospf/oida_ospf_md5.pcap` | John `net-md5` | — | `S3cretOs1` | ✅ john (re-keyed Wireshark sample⁴) |
| `rip/oida_rip_md5.pcap` | John `net-md5` | — | `quagga` | ✅ john (matches JtR vector byte-for-byte⁵) |

⁴ Public Wireshark OSPF-MD5 sample with the first router's digest re-keyed to a
known password so it cracks in CI; OSPF/RIP keyed-MD5 is JtR `net-md5`, no hashcat
mode. ⁵ Crafted from John's own `net-md5` RIPv2 test vector (password `quagga`).
Routing hashes need raw packet bytes — the scanner runs a second JSON/include_raw
pass (`_fill_routing_salts`) because pyshark can't return EK fields + raw bytes at once.

| `tacacs/oida_tacacs_encrypted.pcap` | hashcat 16100 | — | `S3cretTa1` | ✅ hashcat |
| `radius/oida_radius_chap.pcap` | hashcat 4800 | `radiususer` | `S3cretRa1` | ✅ hashcat |
| `radius/oida_radius_mschapv2.pcap` | hashcat 5500 | `msuser` | `S3cretMs1` | ✅ hashcat |

| `bacnet/oida_bacnet_passwords.pcap` | cleartext (not a hash) | — | `OIDA-ReinitPw1` / `OIDA-DccPw1` | ✅ recovered directly |

The BACnet fixture was captured from the project's `bacnet-realstack-building`
mock (port 47821) while the `oida bacnet` client sent ReinitializeDevice /
DeviceCommunicationControl requests — those carry the password **in the clear**,
so it is recovered passively (no cracking; surfaces as a plaintext credential,
not in `--hashcat`).

The TACACS+ and RADIUS fixtures are crafted (scapy) with the body encrypted /
the response computed from the known password, so they crack deterministically.
TACACS+ reads the encrypted body from `tcp.payload` (EK mode, no raw pass);
RADIUS MS-CHAPv2 derives the NetNTLMv1 8-byte challenge as
`SHA1(PeerChallenge ‖ AuthChallenge ‖ username)[:8]`.

² The impacket `smbserver.py` used to capture also prints the NetNTLMv2 hash it
receives, giving an independent oracle for the extracted line.
³ Existing fixture, password unknown; cross-checked against Wireshark's own RFB
dissector (`tshark -e vnc.auth_challenge -e vnc.auth_response`).

¹ HTTP Digest has no hashcat mode; the crackable format is John `hdaa`, which
needs a *jumbo* John build. The test proves crackability by recomputing the RFC
2617 response from the known password (exactly what `hdaa` does internally), so
it needs no jumbo John.

Run a generator (from anywhere in the repo):

```bash
bash docker/capture/capture_pgsql.sh
bash docker/capture/capture_mysql.sh
bash docker/capture/capture_http_digest.sh
bash docker/capture/capture_ntlm_smb.sh
```

All tools (servers, clients, crackers) run in throwaway containers — nothing is
installed on the host.

The known passwords above are intentionally weak so a tiny wordlist cracks them
in tests/CI without GPU.
