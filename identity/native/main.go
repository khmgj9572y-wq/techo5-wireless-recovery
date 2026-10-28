// Native-role USB provisioning. Private keys are generated and retained on the device.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func guardDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("vault directory must be a real mode-700 directory")
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || int(s.Uid) != os.Geteuid() {
		return errors.New("vault directory owner mismatch")
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, errors.New("key must be a real mode-600 file")
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || int(s.Uid) != os.Geteuid() {
		return nil, errors.New("key owner mismatch")
	}
	return os.ReadFile(path)
}
func writeNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func initialize(dir, cn string) (map[string]any, error) {
	if !regexp.MustCompile(`^spk-native-[a-z0-9]+$`).MatchString(cn) || len(cn) > 64 {
		return nil, errors.New("native CN must bind one lowercase factory serial")
	}
	if e := guardDir(dir); e != nil {
		return nil, e
	}
	keyPath := filepath.Join(dir, cn+".key")
	raw, e := readPrivate(keyPath)
	var key *ecdsa.PrivateKey
	if os.IsNotExist(e) {
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, e
		}
		if e = writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); e != nil {
			return nil, e
		}
	} else {
		if e != nil {
			return nil, e
		}
		b, rest := pem.Decode(raw)
		if b == nil || b.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("invalid protected key container")
		}
		parsed, e := x509.ParsePKCS8PrivateKey(b.Bytes)
		if e != nil {
			return nil, e
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("native key must be P-256")
		}
	}
	csrPath := filepath.Join(dir, cn+".csr.pem")
	csrPEM, e := os.ReadFile(csrPath)
	if os.IsNotExist(e) {
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
		if e != nil {
			return nil, e
		}
		csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		if e = writeNew(csrPath, csrPEM); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid stored CSR")
	}
	request, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil {
		return nil, e
	}
	if e = request.CheckSignature(); e != nil {
		return nil, e
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		return nil, e
	}
	if request.Subject.CommonName != cn || !bytes.Equal(pub, request.RawSubjectPublicKeyInfo) {
		return nil, errors.New("CSR does not match the native key and name")
	}
	return map[string]any{"schema": 1, "cn": cn, "algorithm": "EC P-256", "public_key_sha256": digest(pub), "csr_sha256": digest(csrPEM), "private_key_exported": false, "software_protected": true}, nil
}
func deviceGuard(dir, cn string) error {
	if os.Geteuid() != 0 {
		return errors.New("device root required")
	}
	get := func(k string) string {
		b, e := exec.Command("getprop", k).Output()
		if e != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	if get("ro.product.device") != "cronos" || cn != "spk-native-"+strings.ToLower(get("ro.serialno")) {
		return errors.New("native identity does not match the connected Show 5")
	}
	if filepath.Clean(dir) != "/tmp/t5-native-vault/techo5/"+cn {
		return errors.New("only the separately mounted native p14 namespace is allowed")
	}
	if err := guardDir(filepath.Dir(dir)); err != nil {
		return errors.New("protected identity parent is missing, linked or has unsafe permissions")
	}
	for name, want := range map[string]string{"start": "7074814", "size": "32770"} {
		b, e := os.ReadFile("/sys/class/block/mmcblk0p14/" + name)
		if e != nil || strings.TrimSpace(string(b)) != want {
			return errors.New("wrong physical persist geometry")
		}
	}
	mounts, e := os.ReadFile("/proc/mounts")
	if e != nil {
		return e
	}
	found := false
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) > 3 && f[0] == "/dev/block/mmcblk0p14" && f[1] == "/tmp/t5-native-vault" && f[2] == "ext4" && strings.Contains(","+f[3]+",", ",rw,") {
			found = true
		}
	}
	if !found {
		return errors.New("native vault must be the verified p14 mount, not userdata")
	}
	return nil
}
func main() {
	dir := flag.String("dir", "", "on-device native namespace")
	cn := flag.String("cn", "", "spk-native-<factory-serial>")
	flag.Parse()
	fail := func(e error) { fmt.Fprintln(os.Stderr, "Refused:", e); os.Exit(1) }
	if e := deviceGuard(*dir, *cn); e != nil {
		fail(e)
	}
	m, e := initialize(*dir, *cn)
	if e != nil {
		fail(e)
	}
	out, _ := json.Marshal(m)
	fmt.Println(string(out))
}
