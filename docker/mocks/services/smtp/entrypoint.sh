#!/bin/sh
adduser -D testuser && echo "testuser:password" | chpasswd
# Configure SASL
mkdir -p /etc/sasl2
cat > /etc/sasl2/smtpd.conf <<'EOF'
pwcheck_method: saslauthd
mech_list: LOGIN PLAIN
EOF
# Start saslauthd for password verification
saslauthd -a shadow &
# Start Postfix foreground
exec postfix start-fg
