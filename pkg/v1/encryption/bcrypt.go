package encryption

import "golang.org/x/crypto/bcrypt"

// Generate hash string
func BcryptHash(value string) (string, error) {
	hashedStr, err := bcrypt.GenerateFromPassword([]byte(value), 13)
	return string(hashedStr), err
}

// Compare hashed password
func BcryptVerify(hashedStr, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedStr), []byte(plaintext)) == nil
}
