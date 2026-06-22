#################################################
# Minimal Exim 4.92.1 build for CVE-2019-16928  #
# ASan/UBSan instrumented, no TLS, no Berkeley   #
#################################################

BIN_DIRECTORY=/usr/exim/bin
CONFIGURE_FILE=/usr/exim/configure
EXIM_USER=exim
EXIM_GROUP=exim
SPOOL_DIRECTORY=/var/spool/exim

# Use GDBM via the bundled NDBM emulation is fussy; instead use the
# built-in "cdb"/flat lookups only. We must pick a hints DB backend:
# tdb is not present, so use GDBM (libgdbm-dev installed) through the
# NDBM compatibility layer.
USE_GDBM=yes
DBMLIB=-lgdbm

# No TLS at all (simplest reachable EHLO path).
DISABLE_TLS=yes

# No X11 monitor.
EXIM_MONITOR=

# Lookups: keep it minimal. dnsdb not needed.
LOOKUP_LIST=

# Routers / transports we actually use.
ROUTER_ACCEPT=yes
TRANSPORT_APPENDFILE=yes

# Logging to a known place.
LOG_FILE_PATH=/var/spool/exim/log/%slog

# ---- Sanitizer injection ----
CFLAGS=-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
LFLAGS=-fsanitize=address,undefined
