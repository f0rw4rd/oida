#!/bin/bash
# Port forwarding script for enp0s8
# Usage: ./portforward.sh add <dest_ip> <port>
#        ./portforward.sh del <dest_ip> <port>
#        ./portforward.sh list

IFACE="enp0s8"

usage() {
    echo "Usage: $0 {add|del|list} [dest_ip] [port]"
    echo ""
    echo "Examples:"
    echo "  $0 add 172.19.12.10 11740   # Forward enp0s8:11740 -> 172.19.12.10:11740"
    echo "  $0 del 172.19.12.10 11740   # Remove forwarding"
    echo "  $0 list                      # Show current rules"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: Run as root (sudo)"
        exit 1
    fi
}

add_forward() {
    local DEST_IP="$1"
    local PORT="$2"

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    for PROTO in tcp udp; do
        # DNAT: Redirect incoming connections
        iptables -t nat -I PREROUTING 1 -i "$IFACE" -p "$PROTO" --dport "$PORT" -j DNAT --to-destination "$DEST_IP:$PORT"

        # Allow forwarded traffic
        iptables -I FORWARD 1 -i "$IFACE" -p "$PROTO" --dport "$PORT" -d "$DEST_IP" -j ACCEPT
        iptables -I FORWARD 1 -o "$IFACE" -p "$PROTO" --sport "$PORT" -s "$DEST_IP" -j ACCEPT

        # MASQUERADE return traffic
        iptables -t nat -I POSTROUTING 1 -d "$DEST_IP" -p "$PROTO" --dport "$PORT" -j MASQUERADE
    done

    echo "Added (tcp+udp): $IFACE:$PORT -> $DEST_IP:$PORT"
}

del_forward() {
    local DEST_IP="$1"
    local PORT="$2"

    for PROTO in tcp udp; do
        iptables -t nat -D PREROUTING -i "$IFACE" -p "$PROTO" --dport "$PORT" -j DNAT --to-destination "$DEST_IP:$PORT" 2>/dev/null
        iptables -D FORWARD -i "$IFACE" -p "$PROTO" --dport "$PORT" -d "$DEST_IP" -j ACCEPT 2>/dev/null
        iptables -D FORWARD -o "$IFACE" -p "$PROTO" --sport "$PORT" -s "$DEST_IP" -j ACCEPT 2>/dev/null
        iptables -t nat -D POSTROUTING -d "$DEST_IP" -p "$PROTO" --dport "$PORT" -j MASQUERADE 2>/dev/null
    done

    echo "Removed (tcp+udp): $IFACE:$PORT -> $DEST_IP:$PORT"
}

list_rules() {
    echo "=== NAT PREROUTING ==="
    iptables -t nat -L PREROUTING -n --line-numbers | grep -E "^num|$IFACE"
    echo ""
    echo "=== FORWARD ==="
    iptables -L FORWARD -n --line-numbers | head -20
    echo ""
    echo "=== NAT POSTROUTING ==="
    iptables -t nat -L POSTROUTING -n --line-numbers | head -10
}

case "$1" in
    add)
        [[ -z "$2" || -z "$3" ]] && usage
        check_root
        add_forward "$2" "$3"
        ;;
    del)
        [[ -z "$2" || -z "$3" ]] && usage
        check_root
        del_forward "$2" "$3"
        ;;
    list)
        check_root
        list_rules
        ;;
    *)
        usage
        ;;
esac
