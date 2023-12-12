package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
)

type RSAConfig struct {
	PKFilename  string
	PBKFilename string
	PKDestPath  string // Private key destination path
	PBKDeskPath string // Public key destination path
	BackupPath  string // BackupDir destination path
}

func NewRSA(cfg RSAConfig) {
	pkFilePath := cfg.PKFilename
	pbkFilePath := cfg.PBKFilename

	// Generate keypair
	pk, err := GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatal(err)
	}

	pkStr, err := PrivateKeyToString(pk)
	if err != nil {
		log.Fatal(err)
	}

	pbkStr, err := PublicKeyToString(&pk.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Check if file is already existed
	if _, err := os.Stat(pkFilePath); err == nil {
		os.MkdirAll(cfg.BackupPath, 0755)

		file, err := os.ReadFile(pkFilePath)
		if err != nil {
			log.Fatal(err)
		}

		os.WriteFile(cfg.BackupPath+cfg.PKFilename, file, 0700)
	}

	if _, err := os.Stat(pbkFilePath); err == nil {
		os.MkdirAll(cfg.BackupPath, 0755)
		file, err := os.ReadFile(pbkFilePath)
		if err != nil {
			log.Fatal(err)
		}
		os.WriteFile(cfg.BackupPath+cfg.PBKFilename, file, 0700)
	}

	os.Remove(pkFilePath)
	os.Remove(pbkFilePath)
	os.WriteFile(pkFilePath, []byte(pkStr), 0700)
	os.WriteFile(pbkFilePath, []byte(pbkStr), 0755)
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
