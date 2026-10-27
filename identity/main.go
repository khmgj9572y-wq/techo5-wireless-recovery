// Lab-only helper: private keys are written locally and never printed/exported.
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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type metadata struct {
	CN                 string `json:"cn"`
	Algorithm          string `json:"algorithm"`
	PublicSPKISHA256   string `json:"public_spki_sha256"`
	CSRSHA256          string `json:"csr_sha256"`
	PrivateKeyExported bool   `json:"private_key_exported"`
	LabRAMOnly         bool   `json:"lab_ram_only"`
}

func digest(value []byte) string { h := sha256.Sum256(value); return hex.EncodeToString(h[:]) }

func validCN(cn string) error {
	if len(cn) > 64 || !regexp.MustCompile(`^twrp-[a-z0-9]+(?:-[a-z0-9]+)*$`).MatchString(cn) {
		return errors.New("lab CN must be twrp-<lowercase-id>, at most 64 characters")
	}
	return nil
}

func protectedDir(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("lab directory must be a real mode-700 directory")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return errors.New("lab directory owner mismatch")
	}
	return nil
}

func privateRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key must be a private regular file")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, errors.New("key owner does not match helper user")
	}
	return os.ReadFile(path)
}

func writeNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := privateRead(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key container")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("could not parse protected private key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("lab key must be EC P-256")
	}
	return key, nil
}

func initialize(dir, cn string) (metadata, error) {
	var out metadata
	if err := validCN(cn); err != nil {
		return out, err
	}
	if err := protectedDir(dir); err != nil {
		return out, err
	}
	path := filepath.Join(dir, cn+".key")
	key, err := loadKey(path)
	if os.IsNotExist(err) {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return out, err
		}
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return out, err
		}
		if err = writeNew(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	}
	csrPath := filepath.Join(dir, cn+".csr.pem")
	csrPEM, err := os.ReadFile(csrPath)
	if os.IsNotExist(err) {
		data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
		if err != nil {
			return out, err
		}
		csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: data})
		if err = writeNew(csrPath, csrPEM); err != nil {
			return out, err
		}
	} else if err != nil {
		return out, err
	}
	return validateCSR(csrPEM, key, cn)
}

func validateCSR(csrPEM []byte, key *ecdsa.PrivateKey, cn string) (metadata, error) {
	var out metadata
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return out, errors.New("invalid stored CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != cn {
		return out, errors.New("stored CSR signature/identity mismatch")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return out, err
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, publicDER) {
		return out, errors.New("stored CSR/key mismatch")
	}
	return metadata{CN: cn, Algorithm: "EC P-256", PublicSPKISHA256: digest(publicDER), CSRSHA256: digest(csrPEM), LabRAMOnly: true}, nil
}

// Reissue a public request with a new approved name; never copy or rotate the key.
func renamedRequest(dir, sourceCN, newCN string) ([]byte, error) {
	if err := validCN(sourceCN); err != nil {
		return nil, err
	}
	if err := validCN(newCN); err != nil {
		return nil, err
	}
	key, err := loadKey(filepath.Join(dir, sourceCN+".key"))
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: newCN}, SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, err
	}
	request := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := validateCSR(request, key, newCN); err != nil {
		return nil, err
	}
	return request, nil
}

func readCA(path, expected string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected exactly one CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("invalid self-signed lab CA")
	}
	if digest(cert.Raw) != strings.ToLower(strings.ReplaceAll(expected, ":", "")) {
		return nil, errors.New("CA fingerprint mismatch")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errors.New("lab CA is not valid at the device clock")
	}
	return cert, nil
}

func verifyClient(dir, cn string, ca *x509.Certificate) error {
	key, err := loadKey(filepath.Join(dir, cn+".key"))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, cn+".pem"))
	if err != nil {
		return err
	}
	var chain []*x509.Certificate
	for len(bytes.TrimSpace(data)) != 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("invalid client certificate chain")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		chain = append(chain, cert)
		data = rest
	}
	if len(chain) == 0 || chain[0].IsCA || chain[0].Subject.CommonName != cn {
		return errors.New("client certificate identity mismatch")
	}
	clientAuth := false
	for _, usage := range chain[0].ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			clientAuth = true
		}
	}
	if chain[0].KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("client certificate must permit digital signatures")
	}
	if !clientAuth {
		return errors.New("client certificate must explicitly permit client authentication")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(chain[0].RawSubjectPublicKeyInfo, publicDER) {
		return errors.New("client certificate/key mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

// A lower bound, not proof of current time. It never relaxes certificate dates.
func clockFloor(stored []byte, buildFloor int64) (int64, error) {
	if len(stored) > 32 || buildFloor < 1700000000 || buildFloor > 2114380800 {
		return 0, errors.New("invalid clock floor")
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(stored)), 10, 64)
	if err != nil || value < 1700000000 || value > 2114380800 {
		return 0, errors.New("invalid stored clock floor")
	}
	if value < buildFloor {
		value = buildFloor
	}
	return value, nil
}

func main() {
	action := flag.String("action", "version", "version, init, csr, request-csr, verify-client, or boot-check")
	dir := flag.String("dir", "", "on-device RAM lab directory")
	cn := flag.String("cn", "", "twrp-<lowercase-id>")
	sourceCN := flag.String("source-cn", "", "existing on-device identity for request-csr")
	caPath := flag.String("ca", "", "public lab CA file")
	fingerprint := flag.String("ca-sha256", "", "pinned public CA fingerprint")
	buildFloor := flag.Int64("build-floor", 0, "trusted build-time lower bound")
	flag.Parse()
	fail := func(err error) { fmt.Fprintln(os.Stderr, "Refused:", err); os.Exit(1) }
	if *action == "version" {
		fmt.Println(`{"tool":"t5-lab-certtool","version":3,"private_key_export":false}`)
		return
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Clean(*dir), "/tmp/") {
		fail(errors.New("lab operations require device root and a RAM path under /tmp"))
	}
	if err := validCN(*cn); err != nil {
		fail(err)
	}
	if *action == "boot-check" {
		stored, err := privateRead(filepath.Join(*dir, "time-floor"))
		if err != nil {
			fail(err)
		}
		floor, err := clockFloor(stored, *buildFloor)
		if err != nil {
			fail(err)
		}
		if time.Now().Unix() < floor {
			value := syscall.NsecToTimeval(floor * int64(time.Second))
			if err := syscall.Settimeofday(&value); err != nil {
				fail(errors.New("cannot apply clock floor"))
			}
		}
	}
	ca, err := readCA(*caPath, *fingerprint)
	if err != nil {
		fail(err)
	}
	switch *action {
	case "request-csr":
		if err := validCN(*sourceCN); err != nil {
			fail(err)
		}
		if err := verifyClient(*dir, *sourceCN, ca); err != nil {
			fail(err)
		}
		request, err := renamedRequest(*dir, *sourceCN, *cn)
		if err != nil {
			fail(err)
		}
		if _, err := os.Stdout.Write(request); err != nil {
			fail(err)
		}
	case "init":
		result, err := initialize(*dir, *cn)
		if err != nil {
			fail(err)
		}
		resultJSON, _ := json.Marshal(result)
		fmt.Println(string(resultJSON))
	case "csr":
		key, err := loadKey(filepath.Join(*dir, *cn+".key"))
		if err != nil {
			fail(err)
		}
		data, err := os.ReadFile(filepath.Join(*dir, *cn+".csr.pem"))
		if err != nil {
			fail(err)
		}
		if _, err = validateCSR(data, key, *cn); err != nil {
			fail(err)
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			fail(errors.New("CSR contains unexpected private material"))
		}
		os.Stdout.Write(data)
	case "verify-client", "boot-check":
		if err := verifyClient(*dir, *cn, ca); err != nil {
			fail(err)
		}
		fmt.Println(`{"client_certificate_verified":true}`)
	default:
		fail(errors.New("unknown action"))
	}
}
