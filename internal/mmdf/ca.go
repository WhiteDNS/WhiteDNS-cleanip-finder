package mmdf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	CACommonName   = "WhiteDNS MMDF Root CA"
	CACertFilename = "mmdf_ca.crt"
	CAKeyFilename  = "mmdf_ca.key"
	NSSNickname    = "WhiteDNS MMDF CA"
)

type Status struct {
	Backend         string
	CertPath        string
	KeyPath         string
	CAFilesPresent  bool
	IsInstalled     *bool
	FingerprintSHA1 string
}

func CertPath(dataDir string) string { return filepath.Join(dataDir, CACertFilename) }
func KeyPath(dataDir string) string  { return filepath.Join(dataDir, CAKeyFilename) }

func BackendAvailable() string {
	if _, err := exec.LookPath("openssl"); err == nil {
		return "openssl"
	}
	return "stdlib"
}

func EnsureCAFiles(dataDir string) (string, string, error) {
	certPath := CertPath(dataDir)
	keyPath := KeyPath(dataDir)
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath, nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", "", err
	}

	if err := generateCA(certPath, keyPath); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func StatusSummary(dataDir string) (Status, error) {
	certPath := CertPath(dataDir)
	keyPath := KeyPath(dataDir)
	status := Status{
		Backend:        BackendAvailable(),
		CertPath:       certPath,
		KeyPath:        keyPath,
		CAFilesPresent: fileExists(certPath) && fileExists(keyPath),
	}
	if status.CAFilesPresent {
		if fp, err := certFingerprint(certPath); err == nil {
			status.FingerprintSHA1 = fp
		}
		installed, known := isInstalled(certPath)
		if known {
			status.IsInstalled = &installed
		}
	}
	return status, nil
}

func InstallCA(dataDir string) (map[string]any, error) {
	if _, _, err := EnsureCAFiles(dataDir); err != nil {
		return map[string]any{"ok": false, "message": fmt.Sprintf("Could not generate CA: %v", err)}, nil
	}

	certPath := CertPath(dataDir)
	switch runtime.GOOS {
	case "windows":
		return installWindows(certPath)
	case "darwin":
		return installMacOS(certPath)
	case "linux":
		return installLinux(certPath)
	default:
		return map[string]any{"ok": false, "message": "Unsupported platform"}, nil
	}
}

func generateCA(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   CACommonName,
			Organization: []string{"WhiteDNS"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}
	return nil
}

func certFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	fp := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(fp[:])), nil
}

func isInstalled(certPath string) (bool, bool) {
	return false, false
}

func installWindows(certPath string) (map[string]any, error) {
	cmd := exec.Command("certutil", "-addstore", "-f", "Root", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		return map[string]any{"ok": false, "requires_elevation": true, "message": msg}, nil
	}
	return map[string]any{"ok": true, "message": "CA added to Trusted Root Certification Authorities."}, nil
}

func installMacOS(certPath string) (map[string]any, error) {
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		return map[string]any{"ok": false, "requires_elevation": true, "message": msg}, nil
	}
	return map[string]any{"ok": true, "message": "CA installed into System keychain."}, nil
}

func installLinux(certPath string) (map[string]any, error) {
	locations := []struct{ dest, refresh string }{}
	if _, err := os.Stat("/usr/local/share/ca-certificates"); err == nil {
		locations = append(locations, struct{ dest, refresh string }{"/usr/local/share/ca-certificates/whitedns-mmdf-ca.crt", "update-ca-certificates"})
	}
	if _, err := os.Stat("/etc/pki/ca-trust/source/anchors"); err == nil {
		locations = append(locations, struct{ dest, refresh string }{"/etc/pki/ca-trust/source/anchors/whitedns-mmdf-ca.crt", "update-ca-trust"})
	}
	if len(locations) == 0 {
		return map[string]any{"ok": false, "message": "No supported Linux trust-store location found."}, nil
	}

	if os.Geteuid() != 0 {
		return map[string]any{"ok": false, "requires_elevation": true, "message": "Root privileges required. Re-run as root or install the cert manually."}, nil
	}

	for _, loc := range locations {
		data, err := os.ReadFile(certPath)
		if err != nil {
			return map[string]any{"ok": false, "message": err.Error()}, nil
		}
		if err := os.WriteFile(loc.dest, data, 0o644); err != nil {
			return map[string]any{"ok": false, "message": err.Error()}, nil
		}
		_ = exec.Command(loc.refresh).Run()
	}
	return map[string]any{"ok": true, "message": "CA copied into system trust-store locations."}, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
