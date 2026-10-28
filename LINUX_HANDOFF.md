# Linux continuation: Show 5 warm-boot USB and Wi-Fi

This is the continuation entry point for a fresh Linux bench session. Read this before running device commands.

## Authorization and scope

The owner requested continued warm-boot USB/Wi-Fi diagnosis with remote power controls, preservation of existing keys and verified rollback, and **no flashing**. The latest request is to save the work for a fresh Linux session. It does not authorize an OS, recovery, bootloader or firmware update.

Use read-only inspection and guarded runtime tests. Do not run an unlocker, `fastbrick`, a native installer, factory reset, format, repartition, relock, or any flash command. Do not disable ADB authorization or recovery network isolation. No signing key, enrolled device private key, credential, certificate, unit identifier, site address, private image or raw diagnostic dump is included here. The portable code is host-tested and read-only-preflight-tested on the Mac; native Linux hardware validation is the next task.

## Current software and protected layout

The bench unit is an Echo Show 5 **2nd generation**, board `cronos`, running LineageOS `18.1-20260905-UNOFFICIAL-cronos` / Android 11. Its Android kernel is `4.9.337-g8d928c5176cc`. Installed TWRP is `3.7.0_9-0`, with kernel `4.9.77-g4d58c6d-dirty` and a separately built matching WLAN module.

Physical ranges are authoritative. Recovery aliases differ between Android and TWRP.

| Physical partition | Purpose | Start sector | Sectors |
| --- | --- | ---: | ---: |
| p8 | MISC / BCB | 63488 | 1024 |
| p9 | Existing Android boot | 64512 | 32768 |
| p10 | Original recovery | 97280 | 32768 |
| p11 | Installed custom TWRP / SWDL | 130048 | 65536 |
| p12 | Current system | 195584 | 6354944 |
| p14 | Protected role identities | 7074814 | 32770 |

Never overwrite p7, p10, p11 or p14 as part of these tests. Never dump current p14, userdata, or the Android Keystore to the host: enrolled private keys must remain on the speaker. The only permitted raw write implemented by the bench scripts is the backed-up **32-byte BCB command field in p8**, followed by complete readback. Images are never written.

Separate Android and recovery EAP-TLS identities remain installed. A third, separate native-role P-256 key and CSR were generated on-device, persisted with root-only permissions, and checked against both earlier public keys. The native certificate is still pending. Do not generate a replacement key. The existing CSR and its public metadata are available privately; a read-only retrieval of that CSR is sufficient if needed.

## What is saved and what stays private

Source, synthetic tests and this redacted runbook are in Git. Actual identifiers, outlet binding, network endpoints, image hashes, rollback files, certificates, host authorization keys and raw traces are not.

The owner has a separate mode-700 Mac handoff directory, `linux-private-bundle`, outside this checkout. It contains the operator profile, non-key rollback images and verification manifest, and the existing unit-bound Wi-Fi helper/source. It contains **no enrolled EAP private key, APK keystore, firmware signing key, Mac private ADB key, or HA API key**. Transfer that directory privately to the trusted bench host, never through GitHub and never to the build/CI runner.

The bundle deliberately leaves its **Linux USB mapping unverified**. The Mac's bus/port locations are not portable. Inventory the actual Linux connection and update the private profile only after matching the complete serial and physical hub/port. Preserve any other hub devices and protected ports. The outlet was confirmed by the owner to power only this Show 5; retain that serial-bound confirmation only while that physical connection remains true.

## Established results and limits

- Known-good boot/recovery/system rollback artifacts were verified independently. A full system-partition hash after the development trials still matched the saved baseline; MISC and recovery also matched. Hash values stay in the private manifest.
- The installed recovery and all existing keys were retained. Temporary cache queues and owned diagnostics were collected and removed before handoff.
- Recovery Wi-Fi can associate with the existing EAP-TLS identity. Graceful recovery-to-Android shutdown sometimes returns enrolled Android Wi-Fi, NTP and the original-key ESPHome API normally. Automatic recovery is **not qualified as reliable**; some attempts needed an existing-profile reselection from the Mac.
- Instrumented recovery boots showed `adbd=running`, FunctionFS ready, legacy gadget enabled, but UDC `musb-hdrc.0.auto` reported `not attached` and speed `UNKNOWN`. Recovery USB was not observed in those trials. Earlier ordinary UI-driven recovery entries sometimes returned USB; **ORS startup may affect initialization/timing**, so the first Linux comparison must use an ordinary recovery entry rather than the observer.
- A timed Mac USB-port window around `adb root` recovered a verified root session in three development trials, even though the client reported a reconnect timeout. This is a limited bench workaround, not a qualified device fix. Do not apply it automatically to the initial Linux baseline.
- Restarting ADB, MTP toggles, USB-only power flags, UDC `soft_connect` stop/start, vendor USB `cmode` charging/data transitions, explicit ADB configuration, and a delayed host-port reconnect did **not** establish reliable recovery USB. Some disturbed the subsequent Android USB connection. Save these as rejected hypotheses; do not run an experiment sweep.
- The vendor source explicitly warns that gadget-driver re-registration misbehaves. Do not repeat the `soft_connect` re-registration experiment without a new, specific hypothesis.
- A Wi-Fi disconnect barrier was host-tested and completed an ordered shutdown on this unit. It did not prove reliable Android network recovery. It remains in `bench/experiments/`; the root `network-shutdown.sh` baseline is unchanged.
- Remote outlet off/on plus hub-port control restored Android USB repeatedly without cable handling. Electrical USB VBUS removal has **not** been measured: a hub's power flag alone does not prove a full cold power cut.

## Host comparison and research

The Mac used ADB `37.0.1-15733141` on Darwin 27.2.0, normally with its native backend. The [official release notes](https://developer.android.com/tools/releases/platform-tools?hl=en) say 37.0.1 changed the macOS default back to native; `ADB_LIBUSB=1` enables the alternate backend. In our fresh-power comparison, IOKit saw the device but libusb ADB did not. Switching back to native restored ADB immediately. Native was restored for handoff. This rules out that alternate backend as a fix for this setup; it does not prove the Mac causes the original warm-boot fault.

The [ROM issue tracker](https://github.com/amazon-oss/releases/issues) has relevant Wi-Fi reports:

- [Hidden SSID, issue 3](https://github.com/amazon-oss/releases/issues/3): the existing enrolled profile already has `HiddenSSID=true`, so do not apply the documented missing-flag workaround blindly.
- [ANQP/off-channel stall and unsupported PNO reconnects, issue 27](https://github.com/amazon-oss/releases/issues/27): the captured failure logs checked here had no `GAS-QUERY-START` or `REMAIN_ON_CHANNEL` signature. No framework/JAR patch was applied.
- [Fast-roaming AKM support, issue 17](https://github.com/amazon-oss/releases/issues/17): infrastructure reports 802.11r disabled. Do not change AP/RADIUS policy or update the ROM on this evidence alone.

The exact USB failure remains unlocalized between the host stack and the older device gadget implementation. A native Linux host gives a cleaner comparison than a VM whose physical USB bus is still owned by macOS.

## Linux setup and first actions

Use a trusted bench machine, **separate from the CI/build runner**. Keep all firmware/APK signing on the owner's Mac/YubiKeys. Do not forward a signing agent to the bench host.

Install Python 3.11+, ADB, `usbutils` and `uhubctl`. Record exact versions; use matching ADB 37.0.1 for the strongest host comparison where available. On an ARM host, record any distribution-tool version difference. Keep the ADB server under the bench user's account; casually starting it with `sudo` selects a different host keystore. Configure narrowly scoped USB/udev permissions or a bounded `sudo -n uhubctl` command for hub control.

Authorize a new Linux host's **public** ADB key additively if needed, preserving all existing trusted keys. Never delete the speaker's key store or copy its EAP keys. Do not copy the Mac's private ADB or signing keys through Git. Authorize Android first while preserving existing keys. During the guarded first recovery boot, verify TWRP authorization separately: an `unauthorized` row still proves USB enumeration worked. Do not confuse that with an absent USB link. If recovery does not load the newly authorized public key from userdata, return through the verified power fallback and arrange an owner-approved additive RAM-only public-key authorization; never disable authentication or rewrite the recovery image to get past it.

```sh
python3 -m unittest discover -v
python3 -m unittest discover -s bench -p 'test_*.py' -v
python3 -O -m unittest discover -s bench -p 'test_*.py' -v
export T5_BENCH_PROFILE=/secure/operator-state/profile.json
python3 bench/inspect.py
```

The profile must be outside this checkout, owner-only mode 600, with a real mode-700 state directory. `bench/profile.example.json` is documentation, not an executable operator binding. Inspection does not request root, toggle power or change enrollment. Remap the Linux USB topology before setting `usb.mapped_for_serial`; never copy the Mac's topology as an active Linux mapping.

After the private artifacts have been transferred, verify them locally. The local verification reads the gzip to EOF, checks its CRC, raw size/hash and all four artifact hashes; it sends no device commands. The separate device check then reads physical p8/p9/p11/p12 and must match that verified rollback. Neither command writes the device.

```sh
python3 bench/verify_backups.py
# After ordinary authorized rooted debugging is available:
python3 bench/device_check.py
```

Do not fake the verification receipt. Recovery tests refuse to proceed without it. Do not make a new raw userdata/persist backup to substitute for missing files.

## Next controlled test

1. Identify the exact serial/model/kernel and current UID read-only. If ADB is not already root, prepare the fallback in step 2 before requesting a daemon restart. Then record whether a **plain** Linux `adb root` reconnects, before using Mac workarounds.
2. Establish a working remote-power fallback with the serial-bound outlet and newly verified USB mapping. `python3 bench/power.py` checks state only; `--execute` is the separate power action. USB electrical off remains a separate qualification item.
3. With verified backups, perform one **ordinary** BCB-only recovery entry: `python3 bench/bcb.py` is preflight; `--execute` backs up MISC, changes exactly 32 bytes, checks readback and uses a normal reboot. It does not request RTC recovery. Do not use `adb reboot recovery` or recovery-to-recovery reboot: this boot chain previously entered fastboot unexpectedly with those paths.
4. In TWRP, verify recovery version, root, physical p11 hash and full original MISC checksum. Keep network ADB off; do not bypass the recovery VLAN firewall.
5. If Linux USB is stable, stage the root `network-shutdown.sh` in `/tmp`, verify its hash, run it with the configured expected recovery kernel, and return with normal `adb reboot` (no target). Record Android USB, association/EAP, DHCP address, NTP and HA independently. Do not classify “USB absent” as “Wi-Fi failed.”
6. Repeat only after understanding failures. If Linux also fails, collect device kernel/USB state and AP/RADIUS frames with synchronized UTC bounds before another change. Do not infer that certificates are bad from a pre-EAP open-authentication failure.

The power fallback must be reachable from the new Linux host before a boot-control test; the execute preflight checks it without switching anything. If firewall policy blocks the new host, ask infrastructure for an explicit approved path rather than bypassing it.

The owner requested no repeated cable handling. Use the remote controls for resets. A one-time Linux setup/authorization may still need the owner, but do not resume an all-day manual replug loop.

## Optional instrumentation, after the ordinary baseline

`bench/observer.py` ports the Mac development harness to a private profile. Its default is preflight. `--execute` stages a one-use cache job, verifies transfers, backs up and reads back BCB, observes the round trip, and stores results outside Git. It does not install or flash an image.

The observer uses TWRP's existing ORS `cmd` runner because it survives ADB loss. A deliberate invalid stop sentinel prevents ORS's implicit stock-recovery-replacement/reboot path if the diagnostic refuses. On its normal path, the diagnostic syncs its log and requests normal init reboot, without returning successfully to ORS. Preserve this behavior; see the [upstream implementation](https://github.com/TeamWin/android_bootable_recovery/blob/android-9.0/openrecoveryscript.cpp). Check complete p12 hash and metadata after the first Linux observer run.

```sh
python3 bench/observer.py --expected-backend NATIVE
# Only after the baseline and guards are reviewed:
python3 bench/observer.py --expected-backend NATIVE --execute
python3 bench/collect.py --token <result-token> --cleanup --full-system-check
```

`--wifi-fence` selects the **experimental** disconnect barrier. Rejected USB experiments require `--allow-rejected-usb-experiment`; no rejected variant is selected by default. `--usb-window` changes host timing and requires a verified hub mapping. The Mac-only daemon workaround is `bench/adb_mode_window.py`; do not use it in the initial plain-Linux comparison. `bench/wifi_reselect.py` checks the exact existing unit-bound helper hash and selects the already-enrolled network without making a new key or profile. That helper/source stays in the private bundle, not Git.

All test outputs and operator profiles stay outside the source tree. Never attach raw traces, private profiles or images to a PR. Publish only reviewed, redacted summaries. Do not enable network shell/ADB/HTTP in recovery as a shortcut.

## Native-build work already saved

The owner-controlled build repository contains a manual rootless native Show 5 preparation workflow and source lock. Core commit `54742c1324194778be9f24abb980b1b4cd6e6b96` adds the bench update guard; Panel commit `b3bef54923811f4b12c6eb3ca2911133cbcb083c` and recovery commit `24aecab8db7984ffac144b6e763b8ca83913dc86` are the prepared firmware inputs. The native boot/rootfs were built unsigned on the dedicated builder and checked on the Mac, with an unchanged vendor-compatible kernel. They have not been booted or hardware-qualified on this unit. Wi-Fi startup/import and update installation remain blocked in those bench images pending native enrollment/qualification. These generic artifacts are distinct from a verified full-flash/rollback engine.

Do not silently bump the build source lock while testing bench-only changes. Do not install the unsigned candidate. The signed multi-reboot manifest engine, automatic bad-kernel recovery and production rollout are separate unfinished gates.

## Prompt for the new Linux session

> Read LINUX_HANDOFF.md first. Continue the cronos warm-boot USB/Wi-Fi investigation on this native Linux host. Preserve existing device identities, authorized keys and verified rollback. No flashing, re-enrollment, key rotation, network recovery listener, or AP/RADIUS policy change is authorized. Load the owner's external private profile, inspect the actual USB topology, and verify private rollback artifacts before any boot-control write. Compare one ordinary recovery round trip before applying ORS instrumentation or Mac workarounds. Report which failures reproduce on Linux. Treat the disconnect barrier as experimental. If private artifacts or authorization are missing, continue read-only inspection and ask for a secure transfer; do not create replacement keys or infer permission to install firmware.
