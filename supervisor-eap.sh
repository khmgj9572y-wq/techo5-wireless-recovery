#!/sbin/sh
umask 077
PATH=/sbin:/bin:/usr/bin:/usr/sbin
export PATH
BASE=${T5_BASE:-/twrp-wifi}
ROOT=$(readlink -f "$BASE/rootfs")
RUN=/tmp/twrp-wifi
# Generated from validated operator input and covered by payload hashes.
. "$BASE/network-policy" || exit 1
log_state() { printf '%s\n' "$1" > "$RUN/status.new"; mv "$RUN/status.new" "$RUN/status"; }
ip4() { chroot "$ROOT" /sbin/ip -4 "$@"; }
ipt() { chroot "$ROOT" /usr/sbin/iptables-legacy "$@"; }
ip6t() { chroot "$ROOT" /usr/sbin/ip6tables-legacy "$@"; }
tcp_off() {
    if [ "$(getprop service.adb.tcp.port)" != -1 ]; then
        setprop service.adb.tcp.port -1 || return 1
        setprop ctl.restart adbd || return 1
    fi
}
firewall() {
    firewall_ok && return 0
    # This kernel lacks conntrack. Router isolation must remain stateful.
    ipt -I INPUT 1 -i wlan0 -j DROP || return 1
    ipt -N T5_EAP_IN 2>/dev/null || :
    ipt -F T5_EAP_IN || return 1
    ipt -A T5_EAP_IN -p tcp ! --syn -j ACCEPT || return 1
    ipt -A T5_EAP_IN -p udp -s "$DHCP_SERVER" --sport 67 --dport 68 -j ACCEPT || return 1
    for dns in $DNS_SERVERS; do
        ipt -A T5_EAP_IN -p udp -s "$dns" --sport 53 -j ACCEPT || return 1
    done
    ipt -A T5_EAP_IN -p udp -s "$NTP_SERVER" --sport 123 -j ACCEPT || return 1
    ipt -A T5_EAP_IN -j DROP || return 1
    ipt -C INPUT -i wlan0 -j T5_EAP_IN 2>/dev/null || ipt -A INPUT -i wlan0 -j T5_EAP_IN || return 1
    ip6t -C INPUT -i wlan0 -j DROP 2>/dev/null || ip6t -A INPUT -i wlan0 -j DROP || return 1
    ipt -D INPUT -i wlan0 -j DROP || return 1
    firewall_ok
}
firewall_ok() {
    ipt -C INPUT -i wlan0 -j T5_EAP_IN 2>/dev/null || return 1
    ipt -C T5_EAP_IN -p tcp ! --syn -j ACCEPT 2>/dev/null || return 1
    ipt -C T5_EAP_IN -p udp -s "$DHCP_SERVER" --sport 67 --dport 68 -j ACCEPT 2>/dev/null || return 1
    for dns in $DNS_SERVERS; do
        ipt -C T5_EAP_IN -p udp -s "$dns" --sport 53 -j ACCEPT 2>/dev/null || return 1
    done
    ipt -C T5_EAP_IN -p udp -s "$NTP_SERVER" --sport 123 -j ACCEPT 2>/dev/null || return 1
    ipt -C T5_EAP_IN -j DROP 2>/dev/null && ip6t -C INPUT -i wlan0 -j DROP 2>/dev/null
}
owned_pid() {
    name=$1
    [ -r "$ROOT/run/$name.pid" ] || return 1
    pid=$(cat "$ROOT/run/$name.pid")
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    case "$name" in
        wpa) expected=$ROOT/sbin/wpa_supplicant ;;
        dhcp) expected=$ROOT/bin/busybox ;;
        *) return 1 ;;
    esac
    [ "$(readlink /proc/$pid/exe)" = "$expected" ] || return 1
    if [ "$name" = dhcp ]; then
        tr '\000' ' ' < /proc/$pid/cmdline | grep -q '/sbin/udhcpc ' || return 1
    fi
    echo "$pid"
}
stop_dhcp() {
    pid=$(owned_pid dhcp) && kill "$pid" 2>/dev/null
    rm -f "$ROOT/run/dhcp.pid" "$ROOT/run/lease.valid"
    ip4 route flush default dev wlan0 >/dev/null 2>&1
    ip4 addr flush dev wlan0 >/dev/null 2>&1
    return 0
}
associated() {
    owned_pid wpa >/dev/null || return 1
    timeout 5 chroot "$ROOT" /sbin/wpa_cli -p /run/wpa -i wlan0 status 2>/dev/null | grep -q '^wpa_state=COMPLETED$'
}
leased() {
    owned_pid dhcp >/dev/null && [ -f "$ROOT/run/lease.valid" ] &&
        ip4 -o addr show dev wlan0 scope global | grep -q ' inet '
}
no_external_tcp_listener() {
    # adbd's local control socket is loopback-only; no network ADB or other listener.
    for table in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$table" ] || return 1
        while read -r index local remote state rest; do
            [ "$state" = 0A ] || continue
            case "$local" in 0100007F:*|00000000000000000000000001000000:*) ;; *) return 1 ;; esac
        done < "$table"
    done
    return 0
}
healthy() {
    [ "$(getprop ro.adb.secure)" = 1 ] && [ "$(getprop service.adb.tcp.port)" = -1 ] &&
    [ -f "$ROOT/run/eap-tls/ready" ] && firewall_ok && associated && leased && no_external_tcp_listener
}
prepare() {
    [ "$(getprop ro.product.device)" = cronos ] && [ "$(getprop ro.serialno)" = "$(cat "$BASE/eap-serial")" ] || return 1
    [ "$(uname -r)" = "$(cat "$BASE/eap-kernel")" ] || return 1
    [ "$(getprop ro.adb.secure)" = 1 ] || return 1
    (cd "$BASE" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || return 1
    for part in dev proc sys; do
        grep -q " $ROOT/$part " /proc/mounts || mount -o bind "/$part" "$ROOT/$part" || return 1
    done
    tcp_off && firewall || return 1
    /sbin/t5-identity-boot.sh || return 1
    grep -q ' /vendor ' /proc/mounts && return 1
    mkdir -p /vendor/firmware || return 1
    cp "$BASE"/firmware/* /vendor/firmware/ || return 1
    echo /vendor/firmware > /sys/module/firmware_class/parameters/path || return 1
    if ! grep -q '^wlan_mt6632_sdio ' /proc/modules; then insmod "$BASE/wlan_mt6632_sdio.ko" || return 1; fi
    [ -d /sys/class/net/wlan0 ]
}
cycle() {
    tcp_off && firewall || { log_state waiting-for-network-policy; return 1; }
    if ! owned_pid wpa >/dev/null; then
        stop_dhcp
        rm -f "$ROOT/run/wpa.pid" "$ROOT/run/wpa/wlan0"
        ifconfig wlan0 up || return 1
        chroot "$ROOT" /sbin/wpa_supplicant -B -P /run/wpa.pid -i wlan0 -D nl80211 -c /run/eap-tls/wpa.conf > "$RUN/wpa.log" 2>&1 9>&- || return 1
    fi
    if ! associated; then stop_dhcp; log_state waiting-for-eap-tls; return 1; fi
    if ! owned_pid dhcp >/dev/null; then
        rm -f "$ROOT/run/dhcp.pid" "$ROOT/run/lease.valid"
        chroot "$ROOT" /sbin/udhcpc -f -i wlan0 -p /run/dhcp.pid -t 3 -T 3 -A 10 -s /sbin/t5-dhcp-event > "$RUN/dhcp.log" 2>&1 9>&- &
    fi
    if healthy; then echo healthy > "$RUN/ready"; log_state ready; return 0; fi
    rm -f "$RUN/ready"
    log_state waiting-for-dhcp
    return 1
}
main() {
    mkdir -p "$RUN" || exit 1
    if [ "${1:-}" = --check ]; then healthy; exit $?; fi
    exec 9>"$RUN/supervisor.lock"
    flock -n 0 <&9 || exit 0
    tcp_off || exit 1
    trap 'stop_dhcp; exit 0' INT TERM
    until prepare; do log_state waiting-for-identity; sleep 10; done
    while :; do cycle || :; sleep 5; done
}
main "$@"
