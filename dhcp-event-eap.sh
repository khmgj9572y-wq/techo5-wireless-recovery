#!/bin/sh
umask 077
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
[ "$interface" = wlan0 ] || exit 1
valid_ipv4() {
    case "$1" in ''|*[!0-9.]*|.*|*.|*..*) return 1 ;; esac
    saved_ifs=$IFS; IFS=.; set -- $1; IFS=$saved_ifs
    [ "$#" = 4 ] || return 1
    for octet do
        case "$octet" in 0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;; *) return 1 ;; esac
        [ "$octet" -le 255 ] || return 1
    done
}
case "$1" in
    deconfig|nak|leasefail)
        rm -f /run/lease.valid /run/lease.details
        : > /etc/resolv.conf
        ip -4 route flush default dev wlan0
        ip -4 addr flush dev wlan0
        ;;
    bound|renew)
        rm -f /run/lease.valid
        count=0
        for server in $dns; do valid_ipv4 "$server" || exit 1; count=$((count+1)); done
        [ "$count" -ge 1 ] && [ "$count" -le 3 ] || exit 1
        existing=$(ip -4 -o addr show dev wlan0 scope global) || exit 1
        case "$existing" in *" inet $ip/$mask "*) ;; *) ip -4 addr flush dev wlan0 || exit 1 ;; esac
        ip -4 addr replace "$ip/$mask" dev wlan0 || exit 1
        ip link set dev wlan0 up || exit 1
        if [ -n "$router" ]; then
            for gateway in $router; do ip -4 route replace default via "$gateway" dev wlan0 || exit 1; break; done
        else
            ip -4 route flush default dev wlan0 || exit 1
        fi
        : > /etc/resolv.conf.new
        for server in $dns; do printf 'nameserver %s\n' "$server" >> /etc/resolv.conf.new; done
        mv /etc/resolv.conf.new /etc/resolv.conf || exit 1
        printf 'ip=%s\nmask=%s\nrouter=%s\ndns=%s\nserver=%s\n' "$ip" "$mask" "$router" "$dns" "$serverid" > /run/lease.details.new
        mv /run/lease.details.new /run/lease.details || exit 1
        printf '%s\n' "${lease:-unknown}" > /run/lease.valid.new
        mv /run/lease.valid.new /run/lease.valid
        ;;
    *) exit 0 ;;
esac
