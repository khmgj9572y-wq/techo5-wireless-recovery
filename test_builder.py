"""Synthetic boot images only: no vendor binary, certificate or live device needed."""
import hashlib
import json
import lzma
from pathlib import Path
import stat
import struct
import tempfile
import unittest

import build


class BuilderTests(unittest.TestCase):
    def fixture(self, root):
        backup = root / 'backup'; backup.mkdir()
        out = root / 'output'; out.mkdir(mode=0o700)
        fields = [1, stat.S_IFREG | 0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
        cpio = b''.join(build.pack_newc(n, fields, data) for n, data in (
            (b'init.rc', b'on boot\n'), (b'prop.default', b'ro.adb.secure=0\n'),
            (b'TRAILER!!!', b'')))
        ramdisk = lzma.compress(cpio, format=lzma.FORMAT_ALONE)
        header = bytearray(2048); header[:8] = b'ANDROID!'
        kernel = b'synthetic-kernel'
        struct.pack_into('<10I', header, 8, len(kernel), 0, len(ramdisk), 0, 0, 0, 0, 2048, 0, 0)
        header[576:596] = hashlib.sha1(kernel + struct.pack('<I', len(kernel)) + ramdisk + struct.pack('<III', len(ramdisk), 0, 0)).digest()
        image = bytes(header) + kernel + bytes(2048-len(kernel)) + ramdisk
        image += bytes(build.PARTITION_BYTES-len(image))
        original = backup / 'original.img'; original.write_bytes(image)
        runtime = root / 'runtime'; runtime.mkdir(); (runtime/'etc').mkdir()
        firmware = root/'firmware'; firmware.mkdir()
        for name in ['EEPROM_MT7668.bin', 'TxPwrLimit_MT76x8.dat', 'WIFI_RAM_CODE2_SDIO_MT7668.bin', 'WIFI_RAM_CODE_MT7668.bin', 'mt7668_patch_e2_hdr.bin', 'wifi.cfg', 'wlan_mt6632_sdio-twrp-rates-fix.ko']:
            (firmware/name).write_bytes(b'synthetic-input')
        tool=root/'tool'; tool.write_bytes(b'\x7fELF\x01' + bytes(1000000))
        adb=root/'adb-public'; adb.write_bytes(b'X'*600 + b' test\n')
        return original, out/'recovery.img', dict(original_sha=hashlib.sha256(image).hexdigest(), runtime=runtime, firmware=firmware, identity_tool=tool, adb_keys=adb, device_identity=Path(__file__).parent/'profile.example.json')

    def test_roundtrip_preserves_kernel_and_disables_network_adb(self):
        with tempfile.TemporaryDirectory() as d:
            original, output, kwargs = self.fixture(Path(d))
            build.build(original, output, **kwargs)
            image=output.read_bytes()
            self.assertEqual(len(image),build.PARTITION_BYTES)
            self.assertEqual(image[2048:4096], original.read_bytes()[2048:4096])
            size=struct.unpack_from('<I',image,16)[0]
            tree={e[0]:e[2] for e in build.parse_newc(lzma.decompress(image[4096:4096+size],format=lzma.FORMAT_ALONE))}
            self.assertIn(b'ro.adb.secure=1\n',tree[b'prop.default'])
            self.assertIn(b'service.adb.tcp.port=-1\n',tree[b'prop.default'])
            self.assertNotIn(b'@SERIAL@',tree[b'sbin/t5-wifi-loader.sh'])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            self.assertTrue(json.loads(output.with_suffix('.json').read_text())['kernel_unchanged'])

    def test_checksum_refusal_and_original_protection(self):
        with tempfile.TemporaryDirectory() as d:
            original,output,kwargs=self.fixture(Path(d))
            kwargs['original_sha']='0'*64
            with self.assertRaises(ValueError):build.build(original,output,**kwargs)
            self.assertFalse(output.exists())
            with self.assertRaises(ValueError):build.validate_destination(original,original)

    def test_malformed_cpio_and_output_permissions(self):
        with self.assertRaises(ValueError):build.parse_newc(b'070701')
        fields=[1,stat.S_IFREG|0o600,0,0,1,0,0,0,0,0,0,0,0]
        with self.assertRaises(ValueError):build.parse_newc(build.pack_newc(b'../escape',fields,b''))
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o755)
            with self.assertRaises(ValueError):build.private_write(root/'out.img',b'x')


if __name__=='__main__':unittest.main()
