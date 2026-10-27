#!/usr/bin/env python3
"""Build a private, self-contained recovery for a separately verified cronos SWDL slot.

The output contains Wi-Fi credentials. Never publish it or put it in source control.
Safety validation deliberately uses exceptions, not optimization-sensitive asserts.
"""
import argparse
import hashlib
import io
import json
import lzma
import os
import re
import stat
import struct
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARTITION_BYTES = 33554432
PAYLOAD_OFFSET = 16777216
SERVICE = b"""
# Self-contained Wi-Fi supervisor; init restarts it if it exits unexpectedly.
service t5_wifi /sbin/sh /sbin/t5-wifi-loader.sh
    class default
    seclabel u:r:recovery:s0
"""


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def align(value, size):
    require(value >= 0 and size > 0, "invalid alignment")
    return (value + size - 1) // size * size


def parse_newc(blob):
    pos, entries, names = 0, [], set()
    while True:
        start = pos
        require(pos + 110 <= len(blob), "truncated CPIO header")
        require(blob[pos:pos + 6] == b"070701", "unsupported CPIO format")
        fields = [int(blob[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
        pos += 110
        count = fields[11]
        require(1 <= count <= 4096 and pos + count <= len(blob), "invalid CPIO name")
        name = blob[pos:pos + count]
        require(name.endswith(b"\0") and b"\0" not in name[:-1], "invalid name terminator")
        name = name[:-1]
        require(not name.startswith(b"/") and b".." not in name.split(b"/"), "unsafe archive path")
        require(name not in names, "duplicate archive path")
        names.add(name)
        pos = align(pos + count, 4)
        require(pos + fields[6] <= len(blob), "truncated CPIO payload")
        data = blob[pos:pos + fields[6]]
        pos = align(pos + fields[6], 4)
        require(pos <= len(blob), "truncated CPIO padding")
        entries.append((name, fields, data, blob[start:pos]))
        if name == b"TRAILER!!!":
            require(not any(blob[pos:]), "nonzero bytes after CPIO trailer")
            return entries


def pack_newc(name, fields, data):
    f = fields.copy()
    f[6], f[11] = len(data), len(name) + 1
    require(len(f) == 13 and all(0 <= n <= 0xffffffff for n in f), "invalid CPIO fields")
    header = b"070701" + b"".join(f"{n:08x}".encode() for n in f)
    named = header + name + b"\0"
    named += bytes(align(len(named), 4) - len(named))
    return named + data + bytes(align(len(data), 4) - len(data))


def private_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(stat.S_IMODE(path.parent.stat().st_mode) == 0o700,
            "output directory must already be private (mode 700)")
    temp = path.with_suffix(path.suffix + ".partial")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def validate_destination(original, output):
    require(output.suffix.lower() == ".img", "output must use the .img extension")
    original_path = original.resolve()
    backup_root = (HERE.parent / "backups").resolve()
    for path in (output.resolve(), output.with_suffix(".json").resolve()):
        require(path != original_path, "output cannot overwrite the original image")
        require(not path.is_relative_to(backup_root), "output cannot overwrite the backup directory")


def build(original, output, *, original_sha, runtime, firmware, identity_tool, adb_keys, device_identity):
    require(re.fullmatch(r"[0-9a-f]{64}", original_sha) is not None, "expected original SHA-256 required")
    image = original.read_bytes()
    require(hashlib.sha256(image).hexdigest() == original_sha, "original SWDL checksum mismatch")
    validate_destination(original, output)
    require(len(image) == PARTITION_BYTES and image[:8] == b"ANDROID!", "wrong partition or boot format")
    ks, _, rs, _, ss, _, _, page, ds, _ = struct.unpack_from("<10I", image, 8)
    require(page == 2048 and ss == 0 and ds == 0, "unexpected boot layout")
    ro = page + align(ks, page)
    require(ro + rs <= len(image), "ramdisk out of bounds")
    kernel, ramdisk = image[page:page + ks], image[ro:ro + rs]
    require(not any(image[ro + rs:]), "unexpected partition tail")
    boot_id = lambda r: hashlib.sha1(kernel + struct.pack("<I", ks) + r + struct.pack("<III", len(r), ss, ds)).digest()
    require(boot_id(ramdisk) == image[576:596], "original boot ID mismatch")
    entries = parse_newc(lzma.decompress(ramdisk, format=lzma.FORMAT_ALONE))
    old = {e[0]: e for e in entries}
    require(b"init.rc" in old and b"prop.default" in old, "missing init configuration")
    require(b"service t5_wifi " not in old[b"init.rc"][2], "image already patched")

    assets = {}
    def add(name, mode, data=b""):
        n = name.encode()
        require(n not in old and n not in assets, "asset path collision")
        parent = name.rpartition("/")[0]
        if parent and parent.encode() not in old and parent.encode() not in assets:
            add(parent, stat.S_IFDIR | 0o700)
        assets[n] = (mode, data)

    require(runtime.is_dir(), "missing minimal runtime")
    manifest = []
    for path in sorted(runtime.rglob("*")):
        rel = path.relative_to(runtime).as_posix()
        name = "twrp-wifi/rootfs/" + rel
        if path.is_symlink():
            link = os.readlink(path)
            require(not link.startswith("/") and path.resolve().is_relative_to(runtime.resolve()), "runtime symlink escapes root")
            add(name, stat.S_IFLNK | 0o777, link.encode())
        elif path.is_dir():
            add(name, stat.S_IFDIR | 0o700)
        else:
            add(name, stat.S_IFREG | (0o755 if path.stat().st_mode & 0o111 else 0o644), path.read_bytes())
        if path.is_file():
            manifest.append(("rootfs/" + rel, hashlib.sha256(path.read_bytes()).hexdigest()))

    research = firmware
    for filename in ["EEPROM_MT7668.bin", "TxPwrLimit_MT76x8.dat", "WIFI_RAM_CODE2_SDIO_MT7668.bin", "WIFI_RAM_CODE_MT7668.bin", "mt7668_patch_e2_hdr.bin", "wifi.cfg"]:
        data = (research / filename).read_bytes()
        rel = "firmware/" + filename
        add("twrp-wifi/" + rel, stat.S_IFREG | 0o644, data)
        manifest.append((rel, hashlib.sha256(data).hexdigest()))
    data = (research / "wlan_mt6632_sdio-twrp-rates-fix.ko").read_bytes()
    add("twrp-wifi/wlan_mt6632_sdio.ko", stat.S_IFREG | 0o644, data)
    manifest.append(("wlan_mt6632_sdio.ko", hashlib.sha256(data).hexdigest()))
    wifi_config = b""
    wifi_metadata = None
    device_assets = {}
    if device_identity is not None:
        from persistent_identity import render
        wifi_config, device_assets, wifi_metadata = render(device_identity)
        binary = identity_tool.read_bytes()
        require(binary[:5] == b"\x7fELF\x01" and 1000000 < len(binary) < 6000000, "missing ARMv7 identity verifier")
        add("twrp-wifi/rootfs/sbin/t5-identity-check", stat.S_IFREG | 0o755, binary)
        manifest.append(("rootfs/sbin/t5-identity-check", hashlib.sha256(binary).hexdigest()))
        for rel, data in sorted(device_assets.items()):
            add("twrp-wifi/" + rel, stat.S_IFREG | 0o600, data)
            manifest.append((rel, hashlib.sha256(data).hexdigest()))
        add("sbin/t5-identity-boot.sh", stat.S_IFREG | 0o755, (HERE / "identity-boot.sh").read_bytes())
    for rel, data, mode in [
        ("rootfs/etc/wpa_supplicant.conf", wifi_config, 0o600),
        ("rootfs/sbin/t5-dhcp-event", (HERE / "dhcp-event-eap.sh").read_bytes(), 0o755),
    ]:
        add("twrp-wifi/" + rel, stat.S_IFREG | mode, data)
        manifest.append((rel, hashlib.sha256(data).hexdigest()))
    config = assets[b"twrp-wifi/rootfs/etc/wpa_supplicant.conf"][1]
    require(b"network={" in config and b"ctrl_interface=/run/wpa" in config, "invalid private Wi-Fi config")
    keys = adb_keys.read_bytes()
    require(len(keys.splitlines()) == 1 and len(keys.split()[0]) > 500, "invalid trusted ADB key file")
    add("adb_keys", stat.S_IFREG | 0o644, keys)
    add("sbin/t5-wifi-supervisor.sh", stat.S_IFREG | 0o755, (HERE / "supervisor-eap.sh").read_bytes())
    add("twrp-wifi/SHA256SUMS", stat.S_IFREG | 0o600, "".join(f"{digest}  {name}\n" for name, digest in sorted(manifest)).encode())

    # The bootloader cannot boot the enlarged ramdisk tested on this device.
    # Keep the boot image below 16 MiB and use the independent SWDL tail for
    # the self-contained payload. A pinned checksum in the ramdisk gates use.
    payload_assets = {n: v for n, v in assets.items() if n == b"twrp-wifi" or n.startswith(b"twrp-wifi/")}
    payload_buffer = io.BytesIO()
    with tarfile.open(fileobj=payload_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, (mode, data) in payload_assets.items():
            entry = tarfile.TarInfo(name.decode())
            entry.mode, entry.uid, entry.gid, entry.mtime = stat.S_IMODE(mode), 0, 0, 0
            if stat.S_ISDIR(mode):
                entry.type = tarfile.DIRTYPE
            elif stat.S_ISLNK(mode):
                entry.type, entry.linkname = tarfile.SYMTYPE, data.decode()
            else:
                entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data) if entry.isfile() else None)
    payload = payload_buffer.getvalue()
    payload += bytes(align(len(payload), 2048) - len(payload))
    require(PAYLOAD_OFFSET + len(payload) <= PARTITION_BYTES, "payload exceeds SWDL tail")
    payload_sha = hashlib.sha256(payload).hexdigest()
    assets = {n: v for n, v in assets.items() if n not in payload_assets}
    profile = json.loads(device_identity.read_text())
    loader = (HERE / "loader.sh.in").read_bytes().replace(b"@SERIAL@", profile["serial"].encode()).replace(b"@KERNEL@", profile["kernel_release"].encode()).replace(b"@PAYLOAD_BLOCKS@", str(len(payload) // 2048).encode()).replace(b"@PAYLOAD_SHA@", payload_sha.encode())
    require(b"@PAYLOAD_" not in loader, "unexpanded loader template")
    add("sbin/t5-wifi-loader.sh", stat.S_IFREG | 0o755, loader)
    add("twrp-wifi", stat.S_IFLNK | 0o700, b"/tmp/t5-payload/twrp-wifi")

    props = old[b"prop.default"][2]
    for name, value in [(b"ro.adb.secure", b"1"), (b"service.adb.tcp.port", b"-1")]:
        props = re.sub(rb"(?m)^" + re.escape(name) + rb"=.*\n?", b"", props)
        props = props.rstrip(b"\n") + b"\n" + name + b"=" + value + b"\n"
    changed = {b"init.rc": old[b"init.rc"][2].rstrip(b"\n") + b"\n" + SERVICE, b"prop.default": props}
    chunks = []
    inode = max(e[1][0] for e in entries) + 1
    for name, fields, data, raw in entries[:-1]:
        chunks.append(pack_newc(name, fields, changed[name]) if name in changed else raw)
    for name, (mode, data) in assets.items():
        fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        chunks.append(pack_newc(name, fields, data))
        inode += 1
    chunks.append(entries[-1][3])
    cpio = b"".join(chunks)
    cpio += bytes(align(len(cpio), 512) - len(cpio))
    new = {e[0]: e for e in parse_newc(cpio)}
    require(len(new) == len(old) + len(assets), "archive entry count changed unexpectedly")
    for name, entry in old.items():
        if name in changed:
            require(new[name][2] == changed[name], "modified entry mismatch")
        else:
            require(new[name] == entry, "unintended change to original recovery")
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 8 * 1024 * 1024, "lc": 3, "lp": 0, "pb": 2, "mode": lzma.MODE_NORMAL, "nice_len": 128, "mf": lzma.MF_BT4}]
    packed = lzma.compress(cpio, format=lzma.FORMAT_ALONE, filters=filters)
    require(lzma.decompress(packed, format=lzma.FORMAT_ALONE) == cpio, "ramdisk round-trip failed")
    require(ro + align(len(packed), page) <= PAYLOAD_OFFSET, "boot image exceeds loader boundary")
    head = bytearray(image[:ro])
    struct.pack_into("<I", head, 16, len(packed))
    head[576:608] = boot_id(packed) + bytes(12)
    result = bytes(head) + packed + bytes(PAYLOAD_OFFSET - ro - len(packed)) + payload + bytes(PARTITION_BYTES - PAYLOAD_OFFSET - len(payload))
    require(result[page:page + ks] == kernel, "kernel changed")
    expected_head = bytearray(image[:ro])
    expected_head[16:20] = head[16:20]
    expected_head[576:608] = head[576:608]
    require(bytes(expected_head) == result[:ro], "unexpected header change")
    private_write(output, result)
    metadata = {"target": "cronos-swdl-mmcblk0p11", "partition_start_sector": 130048, "partition_sectors": 65536,
                "sha256": hashlib.sha256(result).hexdigest(), "original_sha256": original_sha,
                "image_bytes": len(result), "boot_used_bytes": ro + align(len(packed), page), "ramdisk_bytes": len(packed),
                "payload_offset": PAYLOAD_OFFSET, "payload_bytes": len(payload),
                "kernel_unchanged": True, "added_entries": len(assets), "contains_credentials": True}
    if wifi_metadata is not None:
        metadata["wifi_authentication"] = wifi_metadata
    private_write(output.with_suffix(".json"), (json.dumps(metadata, indent=2) + "\n").encode())
    print(json.dumps(metadata))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("original", "output", "runtime", "firmware", "identity-tool", "adb-keys", "device-identity"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--original-sha256", required=True)
    args = parser.parse_args()
    build(args.original, args.output, original_sha=args.original_sha256,
          runtime=args.runtime, firmware=args.firmware, identity_tool=args.identity_tool,
          adb_keys=args.adb_keys, device_identity=args.device_identity)
