#!/bin/sh
# Entry point: launch the inetd-emulating socat listener on :21.
echo "[*] wu-ftpd 2.6.0 (CVE-2001-0550, ASan) starting on :21"
: > /tmp/ftpd-asan.log

# Mirror the ASan log to container stdout so `docker logs` shows crash reports.
tail -F /tmp/ftpd-asan.log &

# Per-connection fork+EXEC. NO ",stderr" option: the wrapper owns fd 2 and
# points it at /tmp/ftpd-asan.log so ASan reports are captured there.
exec socat TCP-LISTEN:21,reuseaddr,fork EXEC:/run-ftpd.sh
