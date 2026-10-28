# Wireless recovery for Echo Show 5 (2nd generation)

Source-only reference for automatic EAP-TLS Wi-Fi in TWRP on **cronos**. Recovery's Wi-Fi
is outbound only: network ADB is disabled, USB ADB remains authenticated, and readiness
requires association, a DHCP lease, the local firewall and no external TCP listeners.

This is a sanitized export of bench work, not a general recovery installer. The original
implementation passed warm and full cold-power recovery tests on one unit, including
certificate replacement, pinned RADIUS validation, automatic DHCP/DNS and authenticated USB
fallback. The generalized input handling in this export is covered by synthetic/unit tests;
it has **not** been flashed or cold-tested as a new generic build. Other Echo models have
not been validated. No image, vendor firmware, driver binary, certificate, credential,
private backup, unit log or original Git history is included.

## What is included

- `build.py`: patches a separately verified recovery ramdisk while preserving its kernel.
  The small boot image stays below 16 MiB; a hash-checked runtime payload occupies the
  bounded tail of the 32 MiB physical SWDL partition. CPIO entries and boot IDs are checked.
- `loader.sh.in`: checks model, serial, kernel release and physical geometry before reading
  the payload. No recovery alias is used.
- `supervisor-eap.sh`: retries startup/association/DHCP, checks process ownership and listeners,
  disables network ADB, and installs the recovery input firewall before Wi-Fi starts.
- `dhcp-event-eap.sh`: replaces stale addresses/routes and applies DHCP DNS, clearing the lease
  and resolver on deconfiguration.
- `persistent_identity.py` and `identity-boot.sh`: bind the selected serial, CN, persist UUID
  and CA pin; read the protected identity namespace from an ext4 read-only/noload mount;
  copy it into RAM and verify it before starting EAP-TLS.
- `identity/`: device-side P-256 key/CSR generation, CA/client-certificate verification and
  a conservative clock floor. Private keys have no export command. Tests generate temporary
  disposable material at runtime; no certificate fixtures are stored here.
- `prepare_runtime.py`: extracts only the needed tools from an operator-supplied,
  SHA-256-verified ARMv7 rootfs archive. Dependencies retain their own licenses.

## Physical scope and prerequisites

Verify all of these independently on the intended unit; matching a model name alone is
insufficient. Sector values are hardware layout facts, not unit identifiers:

| Role | Physical block device | Start sector | Sectors |
|---|---|---:|---:|
| Recovery SWDL | `/dev/block/mmcblk0p11` | 130048 | 65536 |
| Protected identity filesystem | `/dev/block/mmcblk0p14` | 7074814 | 32770 |

Sector size is 512 bytes. Recovery aliases differ between Android and TWRP. This code neither
repartitions nor formats anything. Factory calibration and other existing persist files must
remain intact. Existing private recovery backups and a proven USB rollback route are required
before any manual installation. After enrollment, do not copy a raw persist/userdata image to
a host: it would export device-held keys.

Required private operator inputs, stored outside this repository:

1. A verified original 32 MiB recovery image and its independently recorded SHA-256.
2. Matching vendor firmware and the kernel-compatible Wi-Fi module. The bench implementation
   required the association-rate fallback patch in `patches/`; this export supplies no module
   binary. Providing an incompatible module will not make another kernel supported.
3. A minimal ARMv7 runtime built from an explicitly verified archive, plus the static ARMv7
   identity helper compiled from `identity/`.
4. An authorized ADB **public** key file for USB authentication.
5. A private copy of `profile.example.json`, filled from real read-only device observations
   and network policy. The example's addresses, serial, UUID and fingerprint are placeholders.
6. A separately provisioned protected namespace described below.

The builder requires every path explicitly. Run `python3 build.py --help` for the inputs.
Create the output directory with mode 700 first. Images and metadata are written mode 600.
Do not build inside or overwrite the original backup directory. The builder does not flash.
Build the helper with `GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build` inside `identity/`;
put the output outside this repository.

## USB enrollment and boot identity

At an attended USB bench, confirm the physical unit's serial and the partition geometry.
Generate a fresh role-specific key on the speaker in a root-only RAM staging directory with
`identity`'s `init` action; obtain its CSR with `csr`. Review the serial and public-key
fingerprints before signing. Transfer only the CSR to the signer and only public certificates
back. The helper has no CA signing function and no private-key export function. Never reuse
Android's key for recovery. Android Keystore enrollment is a separate procedure.

Validate the returned certificate against the pinned CA, exact CN `twrp-<lowercase-serial>`,
P-256 public key, digitalSignature, explicit clientAuth and certificate dates. The RADIUS
certificate must validate against that CA and `domain_suffix_match`. No insecure fallback,
server-date bypass or network enrollment service is included.

On the device, provision only this namespace on the already verified persist filesystem:

```text
techo5/                            root:root 0700
  twrp-<lowercase-serial>/         root:root 0700
    twrp-<lowercase-serial>.key    root:root 0600
    twrp-<lowercase-serial>.pem    root:root 0600
    speaker-ca.pem                root:root 0600
    time-floor                    root:root 0600
```

`time-floor` is a reviewed Unix epoch lower bound, not proof of current time. Preserve and
compare existing factory-file hashes before/after provisioning, use an atomic new namespace,
flush writes and return the filesystem to read-only. No generic persist writer or automated
flasher is supplied: the original scripts were bound to one unit and are not safe to reuse
without a separate bench review.

On boot, the helper advances an earlier clock to the greater of the build floor and stored
floor, then validates the certificate chain. It never relaxes certificate dates. Coordinate
future certificate rotations with an updated floor. Persisting newly authenticated time and
its trust policy remains future work; this implementation does not run an NTP daemon.

## Network policy

Use a separate recovery network with per-role RADIUS/VLAN assignment, client isolation,
DNS/NTP and access only to the intended image store. Profile fields specify the DHCP, DNS
and NTP server addresses admitted by the local input policy. Those must agree with actual
DHCP options and router rules. IPv6 inbound Wi-Fi traffic is dropped. DNS is ordinary port 53.

The older kernel lacks the conntrack firewall match: the local policy accepts non-SYN TCP
packets and selected UDP server replies. It does **not** replace a stateful upstream firewall.
Recovery should have no network-facing service even if that router policy is misconfigured.
The supervisor checks external TCP listeners, not every possible UDP/raw socket. Confirm
listening sockets and packet behavior on the bench before rollout.

The example uses RFC 5737 documentation addresses and `example.org`; none is a deployment
configuration. Loopback encodings in listener tests are protocol constants.

## Validation

```sh
python3 -m unittest discover -v
python3 -O -m unittest discover -v
(cd identity && go test ./... && go vet ./...)
```

Tests cover synthetic boot-image round trips, checksum refusal, original-image protection,
CPIO bounds, private output permissions, identity/CA binding, DHCP state changes, missing
identity and listener rejection. They do not prove radio association on a different unit.

Before hardware rollout, keep USB connected; validate the untouched recovery rollback first,
then warm boots, full power removal, wrong identity/CA/UUID refusal, DNS renewal, association
loss and unexpected listeners. A Mac may require a device-end USB replug after a recovery
transition; working Wi-Fi does not establish a working USB fallback.

## Boundaries and future work

This repository does not implement signed multi-step OS jobs, a manifest verifier, monotonic
version state, power-cut journals, automatic recovery after a bad kernel, Android enrollment,
or general-purpose OTA. It does not write BCB or RTC recovery requests. A future reflash
engine must protect bootloader, recovery and identity physical ranges independently and be
bench-tested at every interruption point. Do not treat a hash-checked runtime payload as
signed firmware authorization.

## Wi-Fi module patch attribution

`patches/wifi-association-fallback.patch` targets the upstream
[Amazon/MediaTek Wi-Fi source](https://github.com/amazon-oss/android_kernel_amazon_mt76x8-wifi)
at commit `31d04e8`. It removes an assertion immediately before an existing supported-rate
fallback, allowing that fallback to run instead of panicking recovery on the observed AP
combination. It does not alter calibration or credentials. Build only against the unit's
matching kernel and configuration; an applied patch alone does not establish ABI compatibility.

The source context is Copyright (C) 2016 MediaTek Inc., dual GPLv2/BSD. This patch is
redistributed under that BSD option, with its original notice in
`patches/LICENSE.mediatek-bsd`; it is excluded from the repository's general MIT license.
No vendor firmware or compiled module is redistributed.

## Experimental warm-handoff and native enrollment helpers

`network-shutdown.sh` is a USB-operated RAM trial helper. It checks the bound recovery identity,
only stops its owned supervisor/supplicant/DHCP processes, requires explicit control acknowledgements,
and disconnects/flushes PMKSA before interface-down. It does not unload drivers, rebind SDIO, reboot,
flash, read keys, or modify the recovery image. It is not yet integrated into an installed exit hook;
RAM trial results must precede any claim of a reliable warm handoff. `test_network_shutdown.py`
covers PID ownership, similar-name refusal and non-OK control replies.

`identity/native` is a separate native-speaker CSR provisioning tool. It accepts only a
`spk-native-<factory-serial>` identity matching the connected cronos unit and a root-only namespace
on the explicitly mounted physical p14 vault. It never accepts recovery/Android key inputs, never
rotates existing keys and emits only public metadata. A protected existing native key/CSR is reused
idempotently; first generation occurs on the speaker. The namespace and key are software-protected.
Only the CSR and public SPKI hash are sent to the owner/CA. The native certificate is separate; existing
Android and recovery identities must stay valid during qualification and rollback. No native device
key is generated by the build system.

## Continuing on a Linux bench

For the current no-flash warm-boot USB/Wi-Fi investigation, start with
[LINUX_HANDOFF.md](LINUX_HANDOFF.md). Portable, profile-bound bench procedures are in `bench/`.
They keep operator state outside Git, require verified rollback before boot-control writes,
and leave the original runtime shutdown helper unchanged. The disconnect barrier remains an
experimental candidate; the USB issue has not been declared fixed.
