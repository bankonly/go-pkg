package encryption

import (
	"crypto/rand"
	"strings"

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

func RSADecAESRandomKey(encryptKey string, cipherText string, iv string) (string, error) {
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
	data, err := DecryptAES(string(keyByte), cipherText, iv)
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

func ToAuthorization(enk, data, iv string) string {
	str := data + "/+8$90" + enk + "/+8$90" + iv
	return str
}

func FromAuthorization(authorization string) (data, enk, iv string) {
	authorization = strings.Replace(authorization, "Bearer ", "", 1)
	splitCipherText := strings.Split(authorization, "/+8$90")
	if len(splitCipherText) != 3 {
		return "", "", ""
	}

	dataResult := splitCipherText[0]
	enkResult := splitCipherText[1]
	vector := splitCipherText[2]

	return enkResult, dataResult, vector
}
