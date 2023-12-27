package common

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"strconv"
)

/* Short func for []byte(string)  */
func Byte(str string) []byte {
	return []byte(str)
}

/* Generate random string */
func RandomString(length int) string {
	var letters = []rune("ZXCVBNMASDFGHJKLQWERTYUIOPzxcvbnmasdfghjkllqwertyuiop1234567890")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

/* Generate random string */
func RandomNumber(length int) string {
	var letters = []rune("1234567890")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

/* Convert unit to string */
func UintToString(value int) string {
	return strconv.Itoa(int(value))
}

// Json string
func JsonStringify(data interface{}) (string, error) {
	result, err := json.Marshal(data)
	return string(result), err
}

// Json decode
func JsonDecode(value string, output any) error {
	err := json.Unmarshal([]byte(value), output)
	return err
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func DeleteElement(slice []int, index int) []int {
	return append(slice[:index], slice[index+1:]...)
}

func IsError(err error) bool {
	return err != nil
}
