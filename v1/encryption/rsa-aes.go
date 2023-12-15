package encryption

import (
	"crypto/rand"

	"github.com/bankonly/go-pkg/v1/common"
)

var (
	_publicKey  string
	_privateKey string
)

// Set Key for future usage
func SetRSAKey(privateKey string, publicKey string) {
	_publicKey = publicKey
	_privateKey = privateKey
}

func GetPrivateKey() string {
	return _publicKey
}

func GetPublicKey() string {
	return _privateKey
}

type RSAEncAESRandomKeyResponse struct {
	EncryptKey    string
	EncryptedData *EncryptAESResult
}

func RSAEncAESRandomKeyClient(publicKey string, data string) (*RSAEncAESRandomKeyResponse, error) {
	key, err := GenerateRandomAESKey()
	if err != nil {
		return nil, err
	}

	keyStr := GenKeyFromByte(key)

	// Encrypt key
	encryptedKey, err := EncryptRSA(publicKey, []byte(keyStr))
	if err != nil {
		return nil, err
	}

	// Encrypt Data
	encryptedData, err := EncryptAES(keyStr, data)
	if err != nil {
		return nil, err
	}

	return &RSAEncAESRandomKeyResponse{
		EncryptKey:    common.Base64Encode(encryptedKey),
		EncryptedData: &encryptedData,
	}, nil
}

func RSAEncAESRandomKey(data string) (*RSAEncAESRandomKeyResponse, error) {
	key, err := GenerateRandomAESKey()
	if err != nil {
		return nil, err
	}

	keyStr := GenKeyFromByte(key)

	// Encrypt key
	encryptedKey, err := EncryptRSA(_publicKey, []byte(keyStr))
	if err != nil {
		return nil, err
	}

	// Encrypt Data
	encryptedData, err := EncryptAES(keyStr, data)
	if err != nil {
		return nil, err
	}

	return &RSAEncAESRandomKeyResponse{
		EncryptKey:    common.Base64Encode(encryptedKey),
		EncryptedData: &encryptedData,
	}, nil
}

func RSADecAESRandomKey(encryptKey string, cipertext string, iv string) (string, error) {
	keyDecoded, err := common.Base64Decode(encryptKey)
	if err != nil {
		return "", err
	}

	// Decrypt key from rsa encryption
	keyByte, err := DecryptRSA(_privateKey, []byte(keyDecoded))
	if err != nil {
		return "", err
	}

	// Decrypt data
	data, err := DecryptAES(string(keyByte), cipertext, iv)
	if err != nil {
		return "", err
	}

	return data, nil
}

func GenerateRandomAESKey() ([]byte, error) {
	key := make([]byte, 32) // AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
