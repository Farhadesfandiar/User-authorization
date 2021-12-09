package jwttoken

import "github.com/dgrijalva/jwt-go"

type Claims struct {
	Body []byte
	jwt.StandardClaims
}

type ErrorStruct struct {
	Code     int
	Message  string
	Token    string
	UserID   string
	DevToken string
}
