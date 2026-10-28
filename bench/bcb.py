#!/usr/bin/env python3
"""USB-only BCB bench test. No image flashing and no RTC recovery request."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import bench_config as settings
CFG=settings.PROFILE
HERE=settings.STATE
MISC = "/dev/block/mmcblk0p8"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def adb(target, *args, timeout=8, data=None):
    return subprocess.run(["adb", "-s", target, *args], input=data, capture_output=True, timeout=timeout)


def read(target, command):
    r = adb(target, "shell", command)
    require(r.returncode == 0, "ADB command failed")
    return r.stdout.decode().strip()


def snapshot(target):
    r = adb(target, "exec-out", "dd if=" + MISC + " bs=4096 count=128 2>/dev/null")
    require(r.returncode == 0 and len(r.stdout) == 512 * 1024, "MISC read is incomplete")
    return r.stdout


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def command_bytes(value):
    require(len(value) < 32 and b"\0" not in value, "invalid boot command")
    return value + bytes(32 - len(value))


def write_command(target, content, remote):
    require(len(content) == 32, "only the 32-byte BCB command may be written")
    r = adb(target, "shell", "-T", "umask 077; cat > " + remote, data=content)
    require(r.returncode == 0, "BCB command staging failed")
    expected = hashlib.sha256(content).hexdigest()
    require(read(target, "sha256sum " + remote).split()[0] == expected, "staged command checksum mismatch")
    # Older TWRP toybox lacks conv=fsync. A successful write followed by sync
    # and full readback is portable across this Android and recovery pair.
    read(target, "set -e; dd if=" + remote + " of=" + MISC + " bs=32 count=1; sync")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default=CFG["serial"])
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    settings.require_profile(args.execute)
    if args.execute:
        settings.require_usb_mapping()
        require(CFG["outlet"]["confirmed_for_serial"]==CFG["serial"],"Owner-confirmed power fallback required")
        import importlib.util
        power_spec=importlib.util.spec_from_file_location("bench_power_preflight",settings.SOURCE/"bench/power.py");power=importlib.util.module_from_spec(power_spec);power_spec.loader.exec_module(power);power.preflight_controls()
    require(args.serial==CFG["serial"],"Configured serial differs")
    require(read(args.serial,"getprop ro.serialno")==CFG["serial"],"Wrong physical unit")
    if args.execute:
        checkpoint = json.loads((HERE / "current-system-backup.json").read_text())
        require(checkpoint.get("verified_by")=="bench/verify_backups.py","Run Linux rollback verification first")
        require(checkpoint["independent_device_hash_verified"] and checkpoint["gzip_crc_and_full_readback_verified"], "current system backup is not verified")
        with (HERE / checkpoint["file"]).open("rb") as saved:
            require(hashlib.file_digest(saved, "sha256").hexdigest() == checkpoint["compressed_sha256"], "current system backup changed")
    devices = subprocess.run(["adb", "devices", "-l"], check=True, capture_output=True, text=True, timeout=8).stdout
    rows = [x.split() for x in devices.splitlines() if x.split() and x.split()[0] == args.serial]
    require(len(rows) == 1 and rows[0][1] == "device", "Android ADB is not connected")
    physical_usb = any(x.startswith("usb:") for x in rows[0][2:])
    require(physical_usb,"Physical USB is required; no network ADB is used")
    require(read(args.serial, "getprop ro.product.device") == CFG["model"], "wrong board")
    require(read(args.serial, "getprop ro.twrp.version") == "", "test must start in Android, not recovery")
    require(read(args.serial, "getprop ro.build.version.sdk") == "30", "unexpected Android base")
    require(read(args.serial, "id -u") == "0", "rooted debugging must be active")
    require(read(args.serial, 'tr -cd "0-9a-fA-F" < /proc/idme/mac_addr').lower().endswith(CFG["mac_suffix"]), "wrong bench unit")
    require(read(args.serial, "sha256sum /dev/block/mmcblk0p11").split()[0] ==
            CFG["recovery_sha256"],
            "reviewed network recovery image is not installed")
    require(read(args.serial, "cat /sys/class/block/mmcblk0p8/start") == "63488" and
            read(args.serial, "cat /sys/class/block/mmcblk0p8/size") == "1024", "wrong MISC geometry")
    require(read(args.serial,"uname -r")==CFG["android_kernel"],"Android kernel differs from reviewed binding")
    before = snapshot(args.serial)
    require(hashlib.sha256(before).hexdigest()==CFG["misc_sha256"],"MISC differs from reviewed baseline")
    require(before[:32] == bytes(32), "another BCB command is pending")
    if not args.execute:
        print("Android transport/root/geometry preflight passed; MISC command is empty. No writes performed.")
        return
    directory = HERE / "bcb-roundtrip"
    directory.mkdir(exist_ok=True, mode=0o700)
    require(directory.stat().st_mode & 0o777 == 0o700, "backup directory is not private")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = stamp + "-" + uuid.uuid4().hex[:8]
    save(directory / (prefix + "-misc-before.img"), before)
    remote_dir = "/data/local/tmp/t5-bcb-" + uuid.uuid4().hex
    read(args.serial, "mkdir -m 700 " + remote_dir)
    boot = command_bytes(b"boot-recovery")
    expected = boot + before[32:]
    try:
        write_command(args.serial, boot, remote_dir + "/command.bin")
        require(snapshot(args.serial) == expected, "BCB write changed unexpected bytes; do not reboot")
    except Exception:
        current = snapshot(args.serial)
        if current[32:] == before[32:] and current[:32] != before[:32]:
            write_command(args.serial, before[:32], remote_dir + "/restore-command.bin")
            require(snapshot(args.serial) == before, "BCB rollback verification failed")
        raise
    report = {"only_command_field_written": True, "physical_usb_present": physical_usb,
              "misc_before_sha256": hashlib.sha256(before).hexdigest(),
              "misc_armed_sha256": hashlib.sha256(expected).hexdigest(), "reboot_command": "adb reboot (no target)",
              "twrp_observed": False}
    save(directory / (prefix + "-armed.json"), (json.dumps(report, indent=2) + "\n").encode())
    start = time.monotonic()
    try:
        r = adb(args.serial, "reboot", timeout=15)  # Deliberately no 'recovery' argument / RTC request.
        report["reboot_command_exit"] = r.returncode
    except subprocess.TimeoutExpired:
        report["reboot_command_exit"] = "transport timeout while rebooting"
    recovery = None
    transport_states=[]
    while time.monotonic() - start < 100:
        current=subprocess.run(["adb","devices","-l"],capture_output=True,text=True,timeout=8).stdout
        rows=[x.split() for x in current.splitlines() if x.startswith(args.serial+" ")]
        state=rows[0][1] if rows else "absent"
        if not transport_states or transport_states[-1]["state"]!=state:transport_states.append({"state":state,"seconds":round(time.monotonic()-start,2)})
        for target in (args.serial,):
            try:
                if read(target, "getprop ro.twrp.version") == CFG["recovery_version"] and read(target, "id -u") == "0":
                    recovery = target
                    break
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
        if recovery:
            break
        time.sleep(2)
    report["transport_states"]=transport_states
    if recovery:
        after = snapshot(recovery)
        save(directory / (prefix + "-misc-after.img"), after)
        report.update(twrp_observed=True, recovery_seconds=round(time.monotonic() - start, 2),
                      command_cleared_on_arrival=after[:32] == bytes(32),
                      misc_after_sha256=hashlib.sha256(after).hexdigest())
        if after[:32] != before[:32]:
            require(after[:32] == boot, "an unexpected BCB command appeared; refusing to overwrite it")
            restore_dir = "/tmp/t5-bcb-restore-" + uuid.uuid4().hex
            read(recovery, "mkdir -m 700 " + restore_dir)
            write_command(recovery, before[:32], restore_dir + "/restore-command.bin")
            read(recovery, "rm " + restore_dir + "/restore-command.bin; rmdir " + restore_dir)
        final = snapshot(recovery)
        report["original_command_restored"] = final[:32] == before[:32]
        report["other_misc_fields_unchanged"] = final[32:] == before[32:]
        # Cleanup cannot erase the already-verified recovery/BCB result.
        cleanup = adb(recovery, "shell", "if [ -d " + remote_dir + " ]; then rm -f " + remote_dir + "/command.bin " + remote_dir + "/restore-command.bin; rmdir " + remote_dir + "; fi")
        report["temporary_file_cleanup_exit"] = cleanup.returncode
    else:
        report["status"] = "No recovery observed; preserve saved MISC and inspect through USB before any further action"
    save(directory / (prefix + "-result.json"), (json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps(report, indent=2))
    require(report["twrp_observed"], "BCB-only recovery boot not confirmed")


if __name__ == "__main__":
    main()
