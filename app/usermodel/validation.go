package usermodel

import (
	"regexp"
	"unicode"
)

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+$")
var phoneRegex = regexp.MustCompile("^[(]{0,1}[0-9]{1,4}[)]{0,1}[0-9]*$")

//Email validation function
func IsEmailValid(e string) bool {
	if len(e) < 3 && len(e) > 254 {
		return false
	}
	return emailRegex.MatchString(e)
}

//Password validation function
func IsPasswordValid(pass string) bool {
	var (
		upp, low, num, sym bool
		tot                uint8
	)

	for _, char := range pass {
		switch {
		case unicode.IsUpper(char):
			upp = true
			tot++
		case unicode.IsLower(char):
			low = true
			tot++
		case unicode.IsNumber(char):
			num = true
			tot++
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			sym = true
			tot++
		default:
			return false
		}
	}

	if !upp || !low || !num || !sym || tot < 8 {
		return false
	}

	return true
}

func IsphoneValid(phoneNumber string) bool {
	if len(phoneNumber) < 4 || len(phoneNumber) > 15 {
		return false
	}
	return phoneRegex.MatchString(phoneNumber)
}
