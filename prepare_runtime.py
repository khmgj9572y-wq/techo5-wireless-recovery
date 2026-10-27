"""Extract only the required ARMv7 tools from the verified TECHO5 release."""
import argparse
import hashlib
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('output must be a new directory')
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != args.sha256:
        raise ValueError("release archive checksum mismatch")
    binaries = {"bin/busybox", "sbin/wpa_supplicant", "sbin/wpa_cli", "usr/sbin/xtables-legacy-multi", "lib/ld-musl-armhf.so.1", "lib/libc.musl-armv7.so.1"}
    libraries = {"usr/lib/libnl-3.so.200", "usr/lib/libnl-genl-3.so.200", "usr/lib/libpcsclite.so.1", "lib/libssl.so.1.1", "lib/libcrypto.so.1.1", "usr/lib/libdbus-1.so.3", "usr/lib/libxtables.so.12", "usr/lib/libip4tc.so.2", "usr/lib/libip6tc.so.2"}
    root = args.output
    with tarfile.open(args.archive, "r:gz") as archive:
        entries = {m.name.removeprefix("./"): m for m in archive}
        wanted = binaries | libraries | {n for n in entries if n.startswith("usr/lib/xtables/")}
        for name in sorted(wanted):
            if name.startswith('/') or '..' in Path(name).parts:
                raise ValueError('unsafe archive path')
            member = entries[name]
            if member.size > 64 * 1024 * 1024:
                raise ValueError('runtime member too large')
            if member.isdir():
                continue
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.extractfile(member).read())
            path.chmod(0o755 if name in binaries else 0o644)
    for name, target in {"bin/sh": "busybox", "bin/rm": "busybox", "bin/mv": "busybox", "sbin/udhcpc": "../bin/busybox", "sbin/ip": "../bin/busybox", "usr/sbin/iptables-legacy": "xtables-legacy-multi", "usr/sbin/ip6tables-legacy": "xtables-legacy-multi"}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            raise ValueError("unexpected regular file at runtime symlink")
        path.symlink_to(target)
    for name in ["dev", "proc", "sys", "run", "tmp", "etc"]:
        (root / name).mkdir(exist_ok=True)
    print("Verified minimal runtime prepared")


if __name__ == "__main__":
    main()
