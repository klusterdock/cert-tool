package cert

import (
	"cert-tool/pkg/file"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/thoas/go-funk"
)

const (
	CertificatePEMType = "CERTIFICATE"
)

func GenerateCA(commonName string, days int, timeToleration time.Duration, key crypto.Signer) (*x509.Certificate, error) {
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now.Add(-timeToleration).UTC(),
		NotAfter:              now.Add(time.Duration(days*24)*time.Hour + timeToleration).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		DNSNames:              []string{commonName},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, errors.Wrapf(err, `create certificate for self-signed ca "%s"`, commonName)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrapf(err, `parse DER data for self-signed ca "%s"`, commonName)
	}

	return cert, nil
}

func SignCertificate(commonName string, orgs, alterNames []string,
	forServer, forClient bool,
	days int, timeToleration time.Duration,
	key crypto.Signer, ca *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, error) {

	var dnsNames = []string{commonName}
	var ipAddrs []net.IP

	ipKeys := make(map[string]struct{})
	for _, name := range alterNames {
		if ip := net.ParseIP(name); ip != nil {
			ipStr := ip.String()
			if _, ok := ipKeys[ipStr]; !ok {
				ipKeys[ipStr] = struct{}{}
				ipAddrs = append(ipAddrs, ip)
			}
		} else {
			if !funk.ContainsString(dnsNames, name) {
				dnsNames = append(dnsNames, name)
			}
		}
	}

	var usage []x509.ExtKeyUsage
	if forServer {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	if forClient {
		usage = append(usage, x509.ExtKeyUsageClientAuth)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: orgs,
		},
		NotBefore:             now.Add(-timeToleration).UTC(),
		NotAfter:              now.Add(time.Duration(days*24)*time.Hour + timeToleration).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usage,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, ca, key.Public(), caKey)
	if err != nil {
		return nil, errors.Wrapf(err, `create certificate for self-signed ca "%s"`, commonName)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrapf(err, `parse DER data for self-signed ca "%s"`, commonName)
	}
	return cert, nil
}

func LoadCertData(data []byte) (*x509.Certificate, error) {
	for data != nil {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf(`failed to decode PEM data`)
		}

		if block.Type == CertificatePEMType {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, `parse certificate from PEM data`)
			}
			return cert, nil

		}
	}
	return nil, fmt.Errorf(`no certificate found`)
}

func LoadCert(certfile string) (*x509.Certificate, error) {
	data, err := os.ReadFile(certfile)
	if err != nil {
		return nil, errors.Wrapf(err, `read certificate file "%s"`, certfile)
	}

	cert, err := LoadCertData(data)
	if err != nil {
		return nil, errors.Wrapf(err, `load certificate from file "%s"`, certfile)
	}

	return cert, nil
}

func SaveCert(cert *x509.Certificate, certfile string, append bool) error {
	var f *os.File
	var err error
	if append {
		f, err = file.OpenExistFileToWrite(certfile, fs.FileMode(0600))
	} else {
		f, err = file.OpenFileToWrite(certfile, fs.FileMode(0600))
	}

	if err != nil {
		return err
	}

	if err := pem.Encode(f, &pem.Block{
		Type:  CertificatePEMType,
		Bytes: cert.Raw,
	}); err != nil {
		f.Close()
		return errors.Wrapf(err, `pem encode certificate to "%s"`, certfile)
	}

	if err := f.Close(); err != nil {
		return errors.Wrapf(err, `close "%s"`, certfile)
	}
	return nil
}

func CertToPEM(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  CertificatePEMType,
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block)
}
