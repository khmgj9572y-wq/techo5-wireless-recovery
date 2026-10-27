package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCN = "twrp-example01"

func TestInitializeReusesProtectedKeyAndCSR(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	first, err := initialize(dir, testCN)
	if err != nil {
		t.Fatal(err)
	}
	second, err := initialize(dir, testCN)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("identity changed on second invocation")
	}
	key, err := loadKey(filepath.Join(dir, testCN+".key"))
	if err != nil {
		t.Fatal(err)
	}
	csr, err := os.ReadFile(filepath.Join(dir, testCN+".csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, testCN+".key"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("key permissions")
	}
	metadataBytes, _ := json.Marshal(first)
	if bytes.Contains(metadataBytes, []byte("PRIVATE KEY")) || bytes.Contains(csr, []byte("PRIVATE KEY")) || first.PrivateKeyExported || !first.LabRAMOnly {
		t.Fatal("unexpected private material or metadata")
	}
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := validateCSR(csr, wrong, testCN); err == nil {
		t.Fatal("accepted mismatched key")
	}
	if _, err := validateCSR(csr, key, "twrp-other"); err == nil {
		t.Fatal("accepted mismatched name")
	}
	block, _ := pem.Decode(csr)
	block.Bytes[len(block.Bytes)-1] ^= 1
	if _, err := validateCSR(pem.EncodeToMemory(block), key, testCN); err == nil {
		t.Fatal("accepted corrupt CSR signature")
	}
}

func TestUnsafePathsAndIdentity(t *testing.T) {
	for _, cn := range []string{"TWRP-test", "twrp-../a", "twrp-a\n", "twrp-", "twrp-a\"b", "twrp-" + strings.Repeat("a", 65)} {
		if validCN(cn) == nil {
			t.Fatalf("accepted CN %q", cn)
		}
	}
	base := t.TempDir()
	target := filepath.Join(base, "target")
	os.Mkdir(target, 0700)
	link := filepath.Join(base, "link")
	os.Symlink(target, link)
	if protectedDir(link) == nil {
		t.Fatal("accepted symlink directory")
	}
	dir := filepath.Join(base, "identity")
	if _, err := initialize(dir, testCN); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, testCN+".key")
	os.Chmod(keyPath, 0644)
	if _, err := loadKey(keyPath); err == nil {
		t.Fatal("accepted public key-file permissions")
	}
	os.Chmod(keyPath, 0600)
	os.Rename(keyPath, keyPath+".original")
	os.Symlink(keyPath+".original", keyPath)
	if _, err := loadKey(keyPath); err == nil {
		t.Fatal("accepted symlink key")
	}
	if err := writeNew(keyPath+".original", []byte("overwrite")); err == nil {
		t.Fatal("overwrote existing key")
	}
}

func fixtureCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPinnedCAAndClientValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if _, err := initialize(dir, testCN); err != nil {
		t.Fatal(err)
	}
	key, _ := loadKey(filepath.Join(dir, testCN+".key"))
	ca, caKey, caPEM := fixtureCA(t)
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, caPEM, 0600)
	if _, err := readCA(caPath, digest(ca.Raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := readCA(caPath, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted wrong CA pin")
	}
	client := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: testCN}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	save := func(public *ecdsa.PublicKey) {
		t.Helper()
		der, err := x509.CreateCertificate(rand.Reader, client, ca, public, caKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, testCN+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	save(&key.PublicKey)
	if err := verifyClient(dir, testCN, ca); err != nil {
		t.Fatal(err)
	}
	otherCA, _, _ := fixtureCA(t)
	if verifyClient(dir, testCN, otherCA) == nil {
		t.Fatal("accepted wrong issuer")
	}
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	save(&wrong.PublicKey)
	if verifyClient(dir, testCN, ca) == nil {
		t.Fatal("accepted wrong public key")
	}
	client.Subject.CommonName = "twrp-other"
	save(&key.PublicKey)
	if verifyClient(dir, testCN, ca) == nil {
		t.Fatal("accepted wrong CN")
	}
	client.Subject.CommonName = testCN
	client.NotAfter = time.Now().Add(-time.Second)
	save(&key.PublicKey)
	if verifyClient(dir, testCN, ca) == nil {
		t.Fatal("accepted expired certificate")
	}
	client.NotAfter = time.Now().Add(time.Minute)
	client.KeyUsage = x509.KeyUsageKeyEncipherment
	save(&key.PublicKey)
	if verifyClient(dir, testCN, ca) == nil {
		t.Fatal("accepted certificate without digitalSignature")
	}
	client.KeyUsage = x509.KeyUsageDigitalSignature
	client.ExtKeyUsage = nil
	save(&key.PublicKey)
	if verifyClient(dir, testCN, ca) == nil {
		t.Fatal("accepted certificate without explicit clientAuth")
	}
}

func TestClockFloorRejectsCorruptionAndNeverLowersBuildFloor(t *testing.T) {
	for _, stored := range []string{"", "0", "-1", "9999999999", "1793076000 junk", "not a time"} {
		if _, err := clockFloor([]byte(stored), 1793076000); err == nil {
			t.Fatalf("accepted %q", stored)
		}
	}
	got, err := clockFloor([]byte("1793075000\n"), 1793076000)
	if err != nil || got != 1793076000 {
		t.Fatal(got, err)
	}
	got, err = clockFloor([]byte("1793077000\n"), 1793076000)
	if err != nil || got != 1793077000 {
		t.Fatal(got, err)
	}
}

func TestRenamedRequestKeepsExistingKeyAndCreatesNoFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if _, err := initialize(dir, testCN); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, testCN+".key")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0500)
	os.Chmod(keyPath, 0400)
	defer os.Chmod(dir, 0700)
	const newCN = "twrp-example02"
	request, err := renamedRequest(dir, testCN, newCN)
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCSR(request, key, newCN); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(keyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key modified")
	}
	if bytes.Contains(request, []byte("PRIVATE KEY")) {
		t.Fatal("private material exported")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("request action created files")
	}
	if _, err := renamedRequest(dir, "twrp-missing", newCN); err == nil {
		t.Fatal("missing key must not cause key generation")
	}
	if _, err := renamedRequest(dir, "../outside", newCN); err == nil {
		t.Fatal("unsafe source identity accepted")
	}
}
