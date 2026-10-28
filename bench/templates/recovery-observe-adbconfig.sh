#!/sbin/sh
# One-use bench diagnostic. Staged in cache; all recovery changes are runtime-only.
set -eu
umask 077
PATH=/sbin:/bin:/usr/bin:/usr/sbin
export PATH
JOB=${0%/*}
case "$JOB" in /cache/recovery/t5-observe-????????????????????????????????) ;; *) exit 1;; esac
(cd "$JOB" && sha256sum -c SHA256SUMS >/dev/null)
. "$JOB/binding"
[ "$(id -u)" = 0 ]
[ "$(getprop ro.product.device)" = cronos ]
[ "$(getprop ro.serialno)" = "$BENCH_SERIAL" ]
[ "$(getprop ro.twrp.version)" = "$BENCH_RECOVERY_VERSION" ]
[ "$(uname -r)" = "$BENCH_RECOVERY_KERNEL" ]
[ "$(cat /sys/class/block/mmcblk0p11/start)" = 130048 ]
[ "$(cat /sys/class/block/mmcblk0p11/size)" = 65536 ]
[ ! -L "$JOB" ]
[ "$(stat -c '%a:%u:%g' "$JOB")" = 700:0:0 ]
(cd "$JOB" && sha256sum -c SHA256SUMS >/dev/null)
mkdir "$JOB/claimed"
exec > "$JOB/trace.log" 2>&1
mark() { echo "MARK $* UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ) UPTIME=$(cut -d ' ' -f1 /proc/uptime)"; }
state() {
 mark "$1"
 for key in init.svc.adbd service.adb.root service.adb.tcp.port sys.usb.config sys.usb.state sys.usb.ffs.ready sys.usb.configfs sys.usb.controller init.svc.t5_wifi; do echo "PROP $key=$(getprop "$key")"; done
 for f in /sys/class/android_usb/android0/enable /sys/class/android_usb/android0/state /sys/class/android_usb/android0/functions /config/usb_gadget/g1/UDC /sys/class/udc/*/state /sys/class/udc/*/current_speed /sys/class/udc/*/maximum_speed /sys/class/net/wlan0/carrier /sys/class/net/wlan0/operstate; do
  [ ! -r "$f" ] || { echo "SYS $f"; cat "$f" || :; }
 done
 dmesg | grep -iE 'usb|musb|functionfs|gadget|udc|phy|wlan|sdio|btmtk' | tail -n 350 || :
 sync
}
state RECOVERY_START
sleep 10
state RECOVERY_PLUS10
sleep 10
state RECOVERY_PLUS20
mark REQUEST_ADB_ONLY_CONFIG
setprop sys.usb.config adb
sleep 8
state RECOVERY_AFTER_ADB_CONFIG
ROOT=$(readlink -f /twrp-wifi/rootfs)
case "$ROOT" in /tmp/*/rootfs) ;; *) mark NO_WIFI_RUNTIME; exit 1;; esac
n=0
while [ "$n" -lt 15 ]; do
 if timeout 2 chroot "$ROOT" /sbin/wpa_cli -p /run/wpa -i wlan0 status | grep -q '^wpa_state=COMPLETED'; then break; fi
 sleep 1
 n=$((n + 1))
done
state BEFORE_QUIESCE
[ "$(sha256sum /dev/block/mmcblk0p8 | cut -d ' ' -f1)" = "$BENCH_MISC_SHA" ]
if ! T5_EXPECTED_KERNEL="$BENCH_RECOVERY_KERNEL" /sbin/sh "$JOB/network-shutdown.sh"; then mark QUIESCE_FAILED; exit 1; fi
state AFTER_QUIESCE
mark NORMAL_INIT_REBOOT
sync
setprop sys.powerctl reboot
# Do not let ORS reach its implicit stock-recovery replacement path.
sleep 20
mark REBOOT_DID_NOT_COMPLETE
exit 1
