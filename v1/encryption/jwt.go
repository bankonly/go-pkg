package encryption

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JWT payload
type Payload struct {
	ID string `json:"id"`
	jwt.StandardClaims
}

func JWTGenToken(id, key string, expireInHour int) (string, error) {
	var jwtToken string
	var err error

	payload := Payload{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(expireInHour)).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	jwtToken, err = token.SignedString([]byte(key))
	return jwtToken, err
}

// Verify token
func JWTVerify(token, key string) (string, error) {
	var userId string

	parseToken, _ := jwt.ParseWithClaims(token, &Payload{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if parseToken == nil { /* If user does not provide token */
		return userId, errors.New("invalid_token")
	}

	/* Check if token has invalid type */
	if claims, ok := parseToken.Claims.(*Payload); ok && parseToken.Valid {
		return claims.ID, nil
	}

	return userId, errors.New("invalid_token")
}
