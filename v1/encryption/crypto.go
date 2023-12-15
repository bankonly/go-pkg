package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
)

// encrypt result option
type EncryptAESResult struct {
	Data   string
	IvInfo GenerateIVResult
}

func GenKeyFromByte(key []byte) string {
	keyByte := []byte(key)
	md5Hash := md5.Sum(keyByte)
	md5Key := hex.EncodeToString(md5Hash[:])
	return md5Key
}

func EncryptAES(key, plaintext string) (EncryptAESResult, error) {
	var result EncryptAESResult

	ivInfo, err := GenerateIV() // Generate IV
	if err != nil {
		return result, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return result, err
	}

	// Create a stream cipher with the IV
	stream := cipher.NewCTR(block, ivInfo.IvByte)
	cipherText := make([]byte, len(plaintext))
	stream.XORKeyStream(cipherText, []byte(plaintext))

	encryptedData := hex.EncodeToString(cipherText)                          // Encrypt to hex
	encryptedData = base64.StdEncoding.EncodeToString([]byte(encryptedData)) // Encrypt to base64

	// Final result encryption
	result.IvInfo = ivInfo
	result.Data = encryptedData
	return result, nil
}

func DecryptAES(key, cipherText, iv string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Decode string from base64
	base64StrDecoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// Decode string from base64
	base64IvDecoded, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", err
	}

	// Decode string from hex
	hexStrDecoded, err := hex.DecodeString(string(base64StrDecoded))
	if err != nil {
		return "", err
	}

	// Decode string from hex
	hexIvDecoded, err := hex.DecodeString(string(base64IvDecoded))
	if err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, hexIvDecoded)
	plaintext := make([]byte, len(hexStrDecoded))
	stream.XORKeyStream(plaintext, hexStrDecoded)
	return string(plaintext), nil
}

// Define IV result option
type GenerateIVResult struct {
	IvByte   []byte
	IvString string
	IvHex    string
}

func GenerateIV() (GenerateIVResult, error) {
	var result GenerateIVResult
	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return result, err
	}

	ivString := hex.EncodeToString(iv) // Encrypt to hex
	result.IvHex = ivString

	ivString = base64.StdEncoding.EncodeToString([]byte(ivString)) // Encrypt to base64

	result.IvByte = iv
	result.IvString = ivString
	return result, nil
}
