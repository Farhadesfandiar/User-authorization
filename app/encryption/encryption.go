package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"src/app/jwttoken"
	"src/app/mongo"

	"github.com/confetti-framework/contract/inter"
)

func AuthenricatorDecoder(request inter.Request) (string, bool) {
	devid := request.Header("deviceid")
	encodedBody, err := jwttoken.PayloadFetcher(request)
	if err != nil {
		return "Failed", false
	}
	secret := mongo.SecretFetcher(devid)
	if secret == "" {
		return "Failed", false
	}

	decodedBody, err := Decrypt(string(encodedBody), secret)
	if err != nil {
		return "Failed", false
	}
	return decodedBody, true

}
func AuthAndDecoder(devid string, token string) (string, bool) {

	secret := mongo.SecretFetcher(devid)
	if secret == "" {
		return "Failed", false
	}

	decodedBody, err := Decrypt(string(token), secret)
	if err != nil {
		return "Failed", false
	}
	return decodedBody, true

}

// encrypt encrypts plain string with a secret key and returns encrypt string.
func Encrypt(plainData string, secret string) (string, error) {
	secretKey := []byte(secret)[0:32]
	cipherBlock, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func Decrypt(encodedData string, sec string) (string, error) {
	secret := []byte(sec)[0:32]
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}
