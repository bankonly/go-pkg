package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

type RSAConfig struct {
	Filename        string
	DestinationPath string // Private key destination path
	BackupPath      string // BackupDir destination path
}

func NewRSA(cfg RSAConfig) error {
	pkFilePath := cfg.Filename + ".rsa"
	pbkFilePath := cfg.Filename + ".pub"

	// Generate keypair
	pk, err := GenerateRSAKeyPair(2048)
	if err != nil {
		return err
	}

	pkStr, err := PrivateKeyToString(pk)
	if err != nil {
		return err
	}

	pbkStr, err := PublicKeyToString(&pk.PublicKey)
	if err != nil {
		return err
	}

	cfg.BackupPath = cfg.BackupPath + time.Now().Format("2006-01-02 15:04") + "/"

	// Check if file is already existed
	if _, err := os.Stat(cfg.DestinationPath + pkFilePath); err == nil {
		os.MkdirAll(cfg.BackupPath, 0755)

		file, err := os.ReadFile(cfg.DestinationPath + pkFilePath)
		if err != nil {
			return err
		}

		if err = os.WriteFile(cfg.BackupPath+pkFilePath, file, 0755); err != nil {
			return err
		}
	}

	if _, err := os.Stat(cfg.DestinationPath + pbkFilePath); err == nil {
		os.MkdirAll(cfg.BackupPath, 0755)
		file, err := os.ReadFile(cfg.DestinationPath + pbkFilePath)
		if err != nil {
			return err
		}
		if err = os.WriteFile(cfg.BackupPath+pbkFilePath, file, 0755); err != nil {
			return err
		}
	}

	os.Remove(pkFilePath)
	os.Remove(pbkFilePath)

	if err = os.WriteFile(cfg.DestinationPath+pkFilePath, []byte(pkStr), 0755); err != nil {
		return err
	}
	if err = os.WriteFile(cfg.DestinationPath+pbkFilePath, []byte(pbkStr), 0755); err != nil {
		return err
	}
	return nil
}

// Generate RSA key pair
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Encrypt RSA
func EncryptRSA(publicKey *rsa.PublicKey, data []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}

// Decrypt RSA
func DecryptRSA(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	decryptedData, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}

// encode public key to string
func PublicKeyToString(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pemString := string(pem.EncodeToMemory(pemBlock))
	return pemString, nil
}

// Private key to string
func PrivateKeyToString(privateKey *rsa.PrivateKey) (string, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	pemString := string(pem.EncodeToMemory(pemBlock))
	return pemString, nil
}

// Parse RSA key to valid type
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("failed_to_parse_key")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed_to_convert_key")
	}

	return publicKey, nil
}

// Parse RSA key to valid type
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed_to_encode_key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
