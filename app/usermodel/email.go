package usermodel

import (
	"net/smtp"
	"src/app/jwttoken"
	"src/app/mongo"

	// "strings"

	"github.com/kamva/mgm/v3"
)

func ConfirmEmail(userEmailCon string) bool {

	var userEmail string = userEmailCon

	//__________________Generating & hashing the randome verification code
	rndmCode := jwttoken.CodeGenerator(6)
	hashedCode := jwttoken.Hasher(rndmCode)

	//__________________Fetching the "ObjectID" from "users" collection
	userid := mongo.UserIdFetcherEmail(userEmailCon)

	//__________________Record the generated code in "Codes" collection
	code := mongo.CodeInsertByEmail(userid, userEmailCon, hashedCode)
	err := mgm.Coll(code).Create(code)
	if err != nil {
		return false
	}

	//__________________Sender info
	from := "tigerbhai888@gmail.com"
	password := "Cr@ck3r.Bh4!8496712"

	// _________________Receiver email address
	to := []string{
		userEmail,
	}

	// _________________SMTP configurations
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	//__________________Message of the email
	subject := "<b>Important</b>"
	body := "your verification code is " + rndmCode
	message := []byte(subject + body)

	//__________________Authentication & Send
	auth := smtp.PlainAuth("", from, password, smtpHost)
	err = smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	return err == nil
}
