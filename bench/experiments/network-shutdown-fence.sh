#!/sbin/sh
# Quiesce recovery Wi-Fi before a warm handoff. No module unload, rebind or key access.
set -eu
PATH=/sbin:/bin:/usr/bin:/usr/sbin
export PATH
BASE=${T5_BASE:-/twrp-wifi}
PROC=${T5_PROC:-/proc}
RUN=${T5_RUN:-/tmp/twrp-wifi}
SYS=${T5_SYS:-/sys}
ROOT=$(readlink -f "$BASE/rootfs")
PAUSED_PID=
fail() { echo "Wi-Fi handoff refused: $*" >&2; return 1; }
owned_pid() {
    name=$1
    [ -f "$ROOT/run/$name.pid" ] || return 1
    pid=$(cat "$ROOT/run/$name.pid")
    case "$pid" in ''|*[!0-9]*|0|1) return 1;; esac
    [ -d "$PROC/$pid" ] || return 1
    case "$name" in wpa) expected=$ROOT/sbin/wpa_supplicant;; dhcp) expected=$ROOT/bin/busybox;; *) return 1;; esac
    [ "$(readlink "$PROC/$pid/exe")" = "$expected" ] || return 1
    if [ "$name" = dhcp ]; then
        command=$(tr '\000' ' ' < "$PROC/$pid/cmdline")
        case "$command" in *'udhcpc '*' -i wlan0 '*) ;; *) return 1;; esac
    fi
    echo "$pid"
}
stop_dhcp_client() {
    [ -f "$ROOT/run/dhcp.pid" ] || return 0
    candidate=$(cat "$ROOT/run/dhcp.pid")
    case "$candidate" in ''|*[!0-9]*|0|1) fail 'invalid DHCP PID';; esac
    if [ ! -d "$PROC/$candidate" ]; then rm -f "$ROOT/run/dhcp.pid"; return 0; fi
    if pid=$(owned_pid dhcp); then
        kill -TERM "$pid"
        wait_gone "$pid" "$ROOT/bin/busybox" || fail 'DHCP client still alive'
    elif [ ! -d "$PROC/$candidate" ]; then
        : # A normal DHCP exit raced the ownership read.
    else fail 'DHCP PID is not owned'; fi
}
wait_gone() {
    pid=$1; expected=$2; n=0
    while [ -d "$PROC/$pid" ] && [ "$(readlink "$PROC/$pid/exe" 2>/dev/null)" = "$expected" ]; do
        [ "$n" -lt 10 ] || return 1
        sleep 1; n=$((n + 1))
    done
}
pause_supervisor() {
    found=
    for path in "$PROC"/[0-9]*/cmdline; do
        [ -f "$path" ] || continue
        command=$(tr '\000' ' ' < "$path")
        case "$command" in
            '/sbin/sh /sbin/t5-wifi-supervisor.sh '|'/sbin/sh /sbin/t5-wifi-supervisor.sh '*)
                [ -z "$found" ] || fail 'multiple supervisors'
                found=${path%/cmdline}; found=${found##*/};;
        esac
    done
    if [ -n "$found" ]; then
        PAUSED_PID=$found
        kill -STOP "$found"
    fi
}
resume_supervisor() {
    if [ -n "$PAUSED_PID" ] && [ -f "$PROC/$PAUSED_PID/cmdline" ] &&
       tr '\000' ' ' < "$PROC/$PAUSED_PID/cmdline" | grep -q '^/sbin/sh /sbin/t5-wifi-supervisor.sh '; then
        kill -CONT "$PAUSED_PID" 2>/dev/null || :
    fi
}
stop_service() {
    setprop ctl.stop t5_wifi
    n=0
    while [ "$(getprop init.svc.t5_wifi)" = running ]; do
        [ "$n" -lt 5 ] || fail 'init did not stop the network service'
        sleep 1; n=$((n + 1))
    done
    resume_supervisor
    n=0
    while [ -n "$PAUSED_PID" ] && [ -s "$PROC/$PAUSED_PID/cmdline" ] &&
          tr '\000' ' ' < "$PROC/$PAUSED_PID/cmdline" | grep -q '^/sbin/sh /sbin/t5-wifi-supervisor.sh '; do
        [ "$n" -lt 10 ] || fail 'supervisor remains after init stop'
        sleep 1; n=$((n + 1))
    done
    PAUSED_PID=
}
wpa_command() {
    result=$(timeout 5 chroot "$ROOT" /sbin/wpa_cli -p /run/wpa -i wlan0 "$1")
    [ "$result" = OK ] || fail "supplicant did not acknowledge $1"
}
wait_disassociated() {
    n=0
    while [ "$n" -lt 10 ]; do
        status=$(timeout 3 chroot "$ROOT" /sbin/wpa_cli -p /run/wpa -i wlan0 status) || fail 'cannot read disconnect state'
        state=$(printf '%s\n' "$status" | sed -n 's/^wpa_state=//p')
        case "$state" in DISCONNECTED|INACTIVE|INTERFACE_DISABLED)
            carrier=$(cat "$SYS/class/net/wlan0/carrier" 2>/dev/null || printf unknown)
            flags=$(cat "$SYS/class/net/wlan0/flags")
            if [ "$carrier" = 0 ] || [ $((flags & 1)) = 0 ]; then
                sleep 1
                return 0
            fi
            ;; esac
        sleep 1; n=$((n + 1))
    done
    fail 'disconnect did not reach a disassociated link state'
}
disconnect_supplicant() {
    if [ -f "$ROOT/run/wpa.pid" ]; then
        pid=$(owned_pid wpa) || fail 'supplicant PID is not owned'
        wpa_command disconnect
        wait_disassociated
        wpa_command pmksa_flush
        wpa_command terminate
        wait_gone "$pid" "$ROOT/sbin/wpa_supplicant" || fail 'supplicant still alive'
    fi
}
quiesce() {
    [ "$(getprop ro.product.device)" = cronos ] || fail 'wrong board'
    if [ -f "$BASE/eap-serial" ]; then expected_serial=$(cat "$BASE/eap-serial");
    else
        cn=$(cat "$BASE/eap-cn")
        case "$cn" in twrp-*) expected_serial=${cn#twrp-};; *) fail 'missing bound recovery identity';; esac
    fi
    [ "$(getprop ro.serialno | tr A-Z a-z)" = "$(printf '%s' "$expected_serial" | tr A-Z a-z)" ] || fail 'wrong unit'
    if [ -f "$BASE/eap-kernel" ]; then expected_kernel=$(cat "$BASE/eap-kernel"); else expected_kernel=${T5_EXPECTED_KERNEL:-}; fi
    [ -n "$expected_kernel" ] && [ "$(uname -r)" = "$expected_kernel" ] || fail 'wrong recovery kernel'
    case "$ROOT" in /tmp/*/rootfs) ;; *) fail 'unexpected runtime root';; esac
    [ "$(cat /sys/class/block/mmcblk0p11/start)" = 130048 ] || fail 'wrong recovery geometry'
    [ "$(cat /sys/class/block/mmcblk0p11/size)" = 65536 ] || fail 'wrong recovery geometry'
    pause_supervisor
    disconnect_supplicant
    stop_dhcp_client
    chroot "$ROOT" /sbin/ip -4 route flush default dev wlan0
    chroot "$ROOT" /sbin/ip -4 addr flush dev wlan0
    chroot "$ROOT" /sbin/ip link set wlan0 down
    stop_service
    [ $(( $(cat /sys/class/net/wlan0/flags) & 1 )) = 0 ] || fail 'interface remains up'
    rm -f "$ROOT/run/wpa.pid" "$ROOT/run/dhcp.pid" "$ROOT/run/lease.valid" "$RUN/ready"
    printf 'quiesced\n' > "$RUN/status"
    echo 'Supplicant disconnect/PMKSA flush acknowledged; owned processes stopped; interface down'
}
if [ "${T5_SHUTDOWN_LIBRARY:-0}" != 1 ]; then trap resume_supervisor EXIT; quiesce; fi
