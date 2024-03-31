package cert

import (
	"cert-tool/pkg/file"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"reflect"

	"github.com/pkg/errors"
	"github.com/thoas/go-funk"
)

const (
	ECPrivateKeyPEMType  = "EC PRIVATE KEY"
	RSAPrivateKeyPEMType = "RSA PRIVATE KEY"
)

func GenerateRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func SaveRSAPrivateKey(key *rsa.PrivateKey, keyfile string) error {
	f, err := file.OpenFileToWrite(keyfile, fs.FileMode(0600))
	if err != nil {
		return err
	}

	if err := pem.Encode(f, &pem.Block{
		Type:  RSAPrivateKeyPEMType,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		f.Close()
		return errors.Wrapf(err, `pem encode rsa private key to "%s"`, keyfile)
	}

	if err := f.Close(); err != nil {
		return errors.Wrapf(err, `close "%s"`, keyfile)
	}
	return nil
}

func GetAllECBitSizes() []int {
	return []int{224, 256, 384, 521}
}

func GetAllECBitSizesString() []string {
	return funk.Map(GetAllECBitSizes(), func(i int) string {
		return fmt.Sprintf("%d", i)
	}).([]string)
}

func GenerateECPrivateKey(bits int) (*ecdsa.PrivateKey, error) {
	var c elliptic.Curve
	switch bits {
	case 521:
		c = elliptic.P521()
	case 384:
		c = elliptic.P384()
	case 256:
		c = elliptic.P256()
	case 224:
		c = elliptic.P224()
	default:
		return nil, fmt.Errorf("unsupport bits: %d", bits)
	}
	return ecdsa.GenerateKey(c, rand.Reader)
}

func SaveECPrivateKey(key *ecdsa.PrivateKey, keyfile string) error {
	f, err := file.OpenFileToWrite(keyfile, fs.FileMode(0600))
	if err != nil {
		return err
	}

	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return errors.Wrapf(err, `marshal ec private key for "%s"`, keyfile)
	}

	if err := pem.Encode(f, &pem.Block{
		Type:  ECPrivateKeyPEMType,
		Bytes: derBytes,
	}); err != nil {
		f.Close()
		return errors.Wrapf(err, `pem encode ec private key to "%s"`, keyfile)
	}

	if err := f.Close(); err != nil {
		return errors.Wrapf(err, `close "%s"`, keyfile)
	}
	return nil
}

func LoadPrivateKey(keyfile string) (crypto.Signer, error) {
	data, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, errors.Wrapf(err, `read file "%s"`, keyfile)
	}
	for data != nil {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.Errorf(`failed to decode PEM block from file "%s"`, keyfile)
		}

		switch block.Type {
		case RSAPrivateKeyPEMType:
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, `parse PKCS1 private key in file "%s"`, keyfile)
			}
			return key, nil
		case ECPrivateKeyPEMType:
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.Wrapf(err, `parse EC private key in file "%s"`, keyfile)
			}
			return key, nil
		}
	}
	return nil, errors.Errorf(`no private key found in file "%s"`, keyfile)
}

func PrivateKeyToPEM(key any) ([]byte, error) {
	switch val := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  RSAPrivateKeyPEMType,
			Bytes: x509.MarshalPKCS1PrivateKey(val),
		}), nil

	case *ecdsa.PrivateKey:
		derBytes, err := x509.MarshalECPrivateKey(val)
		if err != nil {
			return nil, errors.Wrap(err, `marshal ec private key`)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  ECPrivateKeyPEMType,
			Bytes: derBytes,
		}), nil
	default:
		return nil, fmt.Errorf(`unknown private key type: %s`, reflect.TypeOf(key).String())
	}
}
