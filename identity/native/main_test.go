package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeKeyIsSeparateIdempotentAndNeverExported(t *testing.T) {
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	a, e := initialize(d, "spk-native-example01")
	if e != nil {
		t.Fatal(e)
	}
	b, e := initialize(d, "spk-native-example01")
	if e != nil {
		t.Fatal(e)
	}
	if a["public_key_sha256"] != b["public_key_sha256"] || a["csr_sha256"] != b["csr_sha256"] || a["private_key_exported"] != false {
		t.Fatal("identity changed or was exported")
	}
	for _, cn := range []string{"twrp-example01", "spk-example01", "spk-native-../escape"} {
		if _, e = initialize(d, cn); e == nil {
			t.Fatal("wrong role accepted")
		}
	}
}
func TestNativeVaultRejectsLinksAndOpenPermissions(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(d, link)
	if _, e := initialize(link, "spk-native-example01"); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Chmod(d, 0755)
	if _, e := initialize(d, "spk-native-example01"); e == nil {
		t.Fatal("public directory accepted")
	}
}
