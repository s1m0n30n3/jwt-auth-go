package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionId int64
}

type key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]key{}

func (user *UserClaims) Valid() error {
	if !user.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if user.SessionId == 0 {
		return fmt.Errorf("Invalid session ID")
	}

	return nil
}

func main() {
	password := "123456789"

	hashedPassword, err := hashPassword(password)
	if err != nil {
		panic(err)
	}

	err = comparePassword(hashedPassword, password)
	if err != nil {
		fmt.Println("Not logged in.")
	}
	log.Println("Logged in.")
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt from password: %w", err)
	}
	return bs, nil
}

func comparePassword(hashedPassword []byte, password string) error {
	err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid Password: %w", err)
	}
	return nil
}

func singMessage(message []byte) ([]byte, error) {
	h := hmac.New(sha512.New, keys[currentKid].key)

	_, err := h.Write(message)
	if err != nil {
		return nil, fmt.Errorf("Error while hashing message: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSignature(message, signature []byte) (bool, error) {
	newSignature, err := singMessage(message)
	if err != nil {
		return false, fmt.Errorf("Error in checkSignature while getting signature message: %w", err)
	}
	same := hmac.Equal(newSignature, signature)
	return same, nil
}

func createToken(claim *UserClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claim)

	signedToken, err := token.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token: %w", err)
	}
	return signedToken, nil
}

func parseToken(signedToken string) (*UserClaims, error) {
	claims := &UserClaims{}
	t, err := jwt.ParseWithClaims(signedToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid Key ID")
		}

		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid key id")
		}

		return k.key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}

	return t.Claims.(*UserClaims), nil
}

func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating key: %w", err)
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generate kid: %w", err)
	}

	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}

	currentKid = uid.String()

	return nil
}
