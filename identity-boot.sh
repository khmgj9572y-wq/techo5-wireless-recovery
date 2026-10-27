#!/sbin/sh
# This mount is read-only; credentials never enter a host-built image or userdata.
umask 077
set -e
PATH=/sbin:/bin:/usr/bin:/usr/sbin
export PATH
BASE=${T5_BASE:-/twrp-wifi}
ROOT=$(readlink -f "$BASE/rootfs")
MOUNT=/tmp/t5-identity
[ "$(getprop ro.product.device)" = cronos ]
[ "$(getprop ro.serialno)" = "$(cat "$BASE/eap-serial")" ]
[ "$(cat /sys/class/block/mmcblk0p14/start)" = 7074814 ]
[ "$(cat /sys/class/block/mmcblk0p14/size)" = 32770 ]
uuid=$(blkid /dev/block/mmcblk0p14 | sed -n 's/.*UUID="\([^"]*\)".*/\1/p')
[ "$uuid" = "$(cat "$BASE/eap-persist-uuid")" ]
mkdir -p "$MOUNT"
if ! grep -q " $MOUNT " /proc/mounts; then
    mount -t ext4 -o ro,noload,nosuid,nodev,noexec /dev/block/mmcblk0p14 "$MOUNT"
fi
grep -q "^/dev/block/mmcblk0p14 $MOUNT ext4 ro," /proc/mounts
cn=$(cat "$BASE/eap-cn")
[ "$cn" = "twrp-$(tr 'A-Z' 'a-z' < "$BASE/eap-serial")" ]
STORE=$MOUNT/techo5/$cn
[ ! -L "$MOUNT/techo5" ] && [ ! -L "$STORE" ]
[ "$(stat -c '%a:%u:%g' "$MOUNT/techo5")" = 700:0:0 ]
[ "$(stat -c '%a:%u:%g' "$STORE")" = 700:0:0 ]
mkdir -p "$ROOT/run/eap-tls"
chmod 700 "$ROOT/run/eap-tls"
rm -f "$ROOT/run/eap-tls/ready"
for name in "$cn.key" "$cn.pem" speaker-ca.pem time-floor; do
    [ -f "$STORE/$name" ] && [ ! -L "$STORE/$name" ]
    [ "$(stat -c '%a:%u:%g' "$STORE/$name")" = 600:0:0 ]
    cp "$STORE/$name" "$ROOT/run/eap-tls/$name.new"
    chmod 600 "$ROOT/run/eap-tls/$name.new"
    mv "$ROOT/run/eap-tls/$name.new" "$ROOT/run/eap-tls/$name"
done
"$ROOT/sbin/t5-identity-check" -action boot-check -dir "$ROOT/run/eap-tls" -cn "$cn" \
    -ca "$ROOT/run/eap-tls/speaker-ca.pem" -ca-sha256 "$(cat "$BASE/eap-ca-sha256")" \
    -build-floor "$(cat "$BASE/eap-build-floor")"
cp "$ROOT/etc/wpa_supplicant.conf" "$ROOT/run/eap-tls/wpa.conf"
chmod 600 "$ROOT/run/eap-tls/wpa.conf"
echo verified > "$ROOT/run/eap-tls/ready"
