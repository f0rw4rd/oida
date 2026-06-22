#!/bin/sh
# Per-connection wrapper run by socat for each accepted TCP connection.
# in.ftpd runs in inetd mode (FTP protocol on stdin/stdout). Its stderr (fd 2)
# is redirected to /tmp/ftpd-asan.log BEFORE exec, so the fd is opened by root
# and survives the daemon's chroot+setuid. AddressSanitizer writes its crash
# report to fd 2 -> it lands in /tmp/ftpd-asan.log, readable via docker exec.
exec /usr/local/sbin/in.ftpd -a 2>>/tmp/ftpd-asan.log
