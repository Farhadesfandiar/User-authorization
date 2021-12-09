package jwttoken

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/confetti-framework/contract/inter"
	"github.com/dgrijalva/jwt-go"
)

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}
var secretKey = []byte(os.Getenv("SECRET_KEY"))

func Hasher(textin string) string {

	h := sha1.New()
	h.Write([]byte(textin))
	hashed := hex.EncodeToString(h.Sum(nil))

	return hashed
}

func CodeGenerator(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)

	if n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}

func CreateToken(body []byte) (string, error) {

	// var response inter.Response
	expirationTime := time.Now().Add(time.Minute * 60)

	claims := &Claims{
		Body: body,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)

	if err != nil {

		return "", err

	}

	return tokenString, err
}

func VerifyToken(tokenString string) (bool, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	return token.Valid, err
}

func TokenVerifier(userid string, request inter.Request) ErrorStruct {

	var response ErrorStruct

	//____________fetching token
	TokenHeader := request.Header("auth-token")
	//__________Extracting token string from header TokenHeader
	// var authorizationToken = strings.Split(TokenHeader, " ")[1]
	//__________verifying token
	VarifiedToken, _ := VerifyToken(TokenHeader)

	if !VarifiedToken {
		response.Code = 400
		response.Message = "Authentication-failed!"
		return response

	} else {
		response.Code = 200
		response.Message = "Authentication-ok"
	}

	return response
}

func JwtTokenChecker(request inter.Request) ([]byte, error) {
	tk := request.Header("auth-token")
	var empty = []byte{}
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tk, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if token.Valid {
		return claims.Body, nil
	}
	return empty, err

}

// func TokenGenerate(userid []byte) ErrorStruct {
// 	// mongo.Init()
// 	var response ErrorStruct

// 	token, err := CreateToken(userid)
// 	if err != nil {
// 		response.Code = 400
// 		response.Token = "failed!"
// 		response.UserID = userid
// 		return response
// 	}
// 	response.Code = 200
// 	response.Token = token
// 	response.UserID = userid

// 	return response
// }

// json payload token
func PayloadFetcher(request inter.Request) ([]byte, error) {
	tk := request.Header("auth-token")
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tk, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if token.Valid {
		return claims.Body, nil
	}
	return claims.Body, err

}
