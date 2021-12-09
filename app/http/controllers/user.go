package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"src/app/encryption"
	"src/app/jwttoken"
	"src/app/mongo"
	"src/app/usermodel"
	"strings"

	"github.com/confetti-framework/contract/inter"
	"github.com/confetti-framework/foundation/http/outcome"
	"github.com/kamva/mgm/v3"
)

func Register(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	userContact := request.Parameter("contact").String()
	isEmail := strings.Contains(userContact, "@")

	//___________ Continue based on mobile or email
	if isEmail {

		response = registerByEmail(request)

	} else {

		response = registerByPhone(request)
	}

	// out, err := json.Marshal(response)
	// if err != nil {
	// 	return outcome.Json("Something Wrong!")
	// }
	return outcome.Json(response.Message).
		Status(response.Code)
}

func registerByEmail(request inter.Request) usermodel.ErrorStruct {
	var userData usermodel.UserParams
	var userContact string
	userData.Password = request.Parameter("password").String()
	userData.Contact = request.Parameter("contact").String()
	userContact = userData.Contact
	pass := userData.Password

	var response = usermodel.ErrorStruct{

		Code: http.StatusInternalServerError, Message: "Security breach ! check your credentials",
	}

	if userContact == "" {

		response.Code = 403
		response.Message = "Pleaser enter the email address"
		return response

	} else {

		response.Code = http.StatusBadRequest
		if !(usermodel.IsEmailValid(userContact)) {

			response.Code = 406
			response.Message = "Email syntax is invalid"
			return response
		}
	}

	if !usermodel.IsPasswordValid(pass) {

		response.Code = 422
		response.Message = "Password must meets the requirements"
		return response

	}

	//_____________________________Hashing the pass

	hashedPass := jwttoken.Hasher(pass)

	//____________________________Initialize MongoDB connection
	conn := mongo.Init()

	if conn {

		//_______________________Check for duplication

		_, userExist := mongo.UserQuerybyEmail(userContact)

		if userExist {
			response.Code = 412
			response.Message = "This email address is registered already!"
			return response

		} else {

			//____________________Add user data  in temporary users collection

			tempuser := mongo.NewTempUser(userContact, hashedPass, 0)
			err := mgm.Coll(tempuser).Create(tempuser)

			if err != nil {

				response.Code = 430
				response.Message = "This email registered already! But not confirmed. Click on resend!"
				return response

			}

			//____________________Sending the confirmation Email
			isEmailSent := usermodel.ConfirmEmail(userContact)
			if !isEmailSent {
				response.Code = 500
				response.Message = "The email was not able to sent. Please try again later"
				return response
			}
		}

	} else {

		response.Code = 500
		response.Message = "Mongo connection failed!!"
		return response
	}

	response.Code = 200
	response.Message = "A Confirmation Code has been sent to your email"

	return response
}

func registerByPhone(request inter.Request) usermodel.ErrorStruct {

	var userData usermodel.UserParams
	var userContact string
	userData.Password = request.Parameter("password").String()
	countryID := request.Parameter("countryid").Int()
	userData.Contact = request.Parameter("contact").String()
	userContact = userData.Contact
	pass := userData.Password

	var response = usermodel.ErrorStruct{

		Code: http.StatusInternalServerError, Message: "Security breach ! check your credentials",
	}

	if userContact == "" {
		response.Code = 403
		response.Message = "Pleaser enter the phone number"
		return response

	} else {

		response.Code = http.StatusBadRequest

		if !usermodel.IsphoneValid(userContact) {
			response.Code = 406
			response.Message = "Phone number syntax is invalid"
			return response

		}
	}

	if !usermodel.IsPasswordValid(pass) {
		response.Code = 422
		response.Message = "Password must meets the requirements"
		return response

	}

	//___________________________Hashing the pass

	hashedPass := jwttoken.Hasher(pass)

	//___________________________Initialize MongoDB connection

	conn := mongo.Init()

	if conn {

		//________________________Check for duplication

		_, userExist := mongo.UserQuerybyPhone(userContact)
		if userExist {
			response.Code = 412
			response.Message = "This phone number is registered already!"
			return response

		} else {
			//____________________Add user data  in "users" collection

			tempuser := mongo.NewTempUser(userContact, hashedPass, countryID) //_____user := mongo.NewUserByPhone(userContact, hashedPass)
			err := mgm.Coll(tempuser).Create(tempuser)

			if err != nil {
				response.Code = 430
				response.Message = "This phone number is registered already! but not confirmed!"
				return response
			}

			//_____________________Sending the confirmation SMS

			isSmsSent := usermodel.SendSmsRegister(countryID, userContact)
			if !isSmsSent {
				response.Code = 500
				response.Message = "The sms was not able to sent. Please try later"
				return response
			}

		}

	} else {
		//_________________________Connection to Mongo server Failed
		response.Code = 500
		response.Message = "Mongo connection failed!!"
		return response

	}

	response.Code = 200
	response.Message = "The Code has been sent to your phone by sms"
	return response
}

func CodeEvaluatorRegister(request inter.Request) inter.Response {
	var confCode usermodel.ConfirmationCode
	var currDevice mongo.Device
	var oldExist bool = false
	var olduser mongo.User
	var originCode string
	var updateDone bool
	var userid string

	var tokenCode int
	var tokenStruct usermodel.TokenResponse
	var response = usermodel.ErrorStruct{
		Code: http.StatusInternalServerError, Message: "Security breach ! check your credentials",
	}

	confCode.ConfirmCode = request.Parameter("confirmcode").String()
	confCode.Contact = request.Parameter("contact").String()
	devID := request.Header("deviceid")
	userContact := confCode.Contact

	//__________________ Continue based on mobile or email

	isEmail := strings.Contains(userContact, "@")

	if isEmail {

		olduser, oldExist = mongo.UserQuerybyEmail(userContact)

	} else {

		olduser, oldExist = mongo.UserQuerybyPhone(userContact)
	}

	//TODO:will no more need to this, functions (EmailCodeEvalutor/MobileCodeEvalutor)

	if olduser.Email == userContact {
		fmt.Println("email")
	}
	//____________________If the user is not new

	if oldExist {
		userid = olduser.ID.Hex()

		//___________________if the Device ID is empty, will create a token for device
		devID, _ := usermodel.RandToken(devID)

		//________________Get the generated code from DB
		code, exist := mongo.CodeFetcher(userContact)
		if !exist {

			response.Code = 400
			response.Message = "The entered code has been expired! Click on Resend"
			return outcome.Json(response.Message).
				Status(response.Code)
		}
		originCode = code.Code
		receivedCode := jwttoken.Hasher(confCode.ConfirmCode)

		if receivedCode == originCode {

			//____________ Add Device info in device coll
			currDevice = usermodel.GetUserAgent(devID, userid, request)
			currDevice.SecretKey = originCode
			device := mongo.NewDevice(currDevice)
			err := mgm.Coll(device).Create(device)

			if err != nil {

				response.Code = 200
				response.Message = "The confirmation code is accepted. The device registeration has failed"

			}

			var tokenStr string
			//____________ Logged in & send the jwt token

			response.Code = 200
			response.Message = "The confirmation code is accepted. Logged in successfully"
			tokenStruct.UserID = userid
			tokenStruct.DeviceID = devID
			body, _ := json.Marshal(tokenStruct)
			EncodedBody, err := encryption.Encrypt(string(body), device.SecretKey)
			if err != nil {
				return outcome.Json("The confirmation code is accepted, but token couldn't be generated!").
					Status(400)
			}
			tokenStr, tokenCode = TokenGenerate([]byte(EncodedBody))

			if tokenCode == 400 {
				return outcome.Json("The confirmation code is accepted, but token couldn't be generated!").
					Status(400)
			}

			//____________ TODO : Send the device token in header to device

			return outcome.Json(response.Message).
				Status(response.Code).
				Header("auth-token", tokenStr)

		} else {

			response.Code = 401
			response.Message = "The confirmation code is wrong!"
			// return outcome.Json(response)

		}

	} else {

		newUserInfo, userExist := mongo.TempUserExist(userContact)

		//_______________If the user is new

		if userExist {

			//________________Get the generated code from DB

			code, exist := mongo.CodeFetcher(userContact)

			if !exist {

				response.Code = 402
				response.Message = "The entered code has been expired! Click on"
				return outcome.Json(response.Message).
					Status(response.Code)
			}
			originCode = code.Code
			password := newUserInfo.Password
			receivedCode := jwttoken.Hasher(confCode.ConfirmCode)
			isEmail := strings.Contains(userContact, "@")

			if receivedCode == originCode {

				if isEmail {

					user := mongo.NewUserByEmail(userContact, password)
					err := mgm.Coll(user).Create(user)
					if err != nil {
						response.Code = 412
						response.Message = "This email is already registered!"
						return outcome.Json(response.Message).
							Status(response.Code)
					}

					userid = mongo.UserIdFetcherEmail(userContact)
					updateDone = mongo.EmailConfirmor(userContact)
					// userID = mongo.UserIdFetcherEmail(confCode.Email) //TODO

				} else {
					countryid := code.CountryID
					user := mongo.NewUserByPhone(userContact, password, countryid)
					err := mgm.Coll(user).Create(user)
					if err != nil {
						response.Code = 412
						response.Message = "This phone number is already registered!"
						return outcome.Json(response.Message).
							Status(response.Code)
					}
					userid = mongo.UserIdFetcherPhone(userContact)
					updateDone = mongo.ConfirmorPhone(userContact)
					// userID = mongo.UserIdFetcherPhone(confCode.Phone)
				}

				if updateDone {
					mongo.TempUserDelete(userContact)
					mongo.CodeDelete(userContact)
					//____________ Add Device info in device coll

					devID, _ := usermodel.RandToken(devID)
					currDevice = usermodel.GetUserAgent(devID, userid, request)
					currDevice.SecretKey = originCode
					device := mongo.NewDevice(currDevice)
					err := mgm.Coll(device).Create(device)

					if err != nil {

						response.Code = 200
						response.Message = "he confirmation code is accepted. The device registeration has failed"
						return outcome.Json(response.Message).
							Status(response.Code)
					}

					//_____________ Delete the code from coll
					response.Code = 200
					response.Message = "The confirmation code is accepted. You can log in now"
					response.DevID = devID
				} else {

					response.Code = 400
					response.Message = "The confirmation code is not accepted! Please try with a new code"
					return outcome.Json(response.Message).
						Status(response.Code)
				}

			} else {

				response.Code = 400
				response.Message = "The entered code is not correct!"

			}

		} else {

			response.Code = 400
			response.Message = "Please register by your email or phone!"
			// return outcome.Json(response)
		}
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token).
			Header("userid", response.UserID).
			Header("devtoken", response.DevID)
	}

	return outcome.Json(response.Message).
		Status(response.Code).
		Header("auth-token", response.Token).
		Header("userid", response.UserID).
		Header("devtoken", response.DevID)
}

func Login(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	userContact := request.Parameter("contact").String()
	isEmail := strings.Contains(userContact, "@")
	response.Token = "Authentication Failed!"
	response.Code = 400

	//__________________ Continue based on mobile or email

	if isEmail {

		response = userLoginByEmail(request)

	} else {

		response = userLoginByPhone(request)
	}

	return outcome.Json(response.Message).
		Status(response.Code).
		Header("auth-token", response.Token)
}

func userLoginByEmail(request inter.Request) usermodel.ErrorStruct {

	var user mongo.User
	var exist bool = false
	var tokenStruct usermodel.TokenResponse

	//___________________ Initializing esponse struct (Default code 400)

	var response = usermodel.ErrorStruct{

		Code: http.StatusInternalServerError, Message: "Security breach ! check your credentials",
	}
	devID := request.Header("deviceid")
	// devToken,_ := usermodel.RandToken(devID, 9)
	// devToken := request.Header("devtoken")
	userContact := request.Parameter("contact").String()
	p := request.Parameter("password").String()
	rcvdpass := jwttoken.Hasher(p)

	//___________________ Query the user (if it exists)

	user, exist = mongo.UserQuerybyEmail(userContact)

	if exist {

		if rcvdpass == user.Password {

			//___________ Check if the device is new

			userid := user.ID.Hex()
			theDevice, deviceExist := usermodel.DeviceExist(devID, userid, request)

			if deviceExist {

				//________ Logged in & send the jwt token
				response.Code = 200
				response.Message = "Logged in successfully"

				tokenStruct.UserID = userid
				tokenStruct.DeviceID = devID
				body, _ := json.Marshal(tokenStruct)
				encryptBody, err := encryption.Encrypt(string(body), theDevice.SecretKey)

				if err != nil {
					response.Code = 400
					response.Message = "The auth token could not be generated!"
					return response
				}

				token, tokenCode := TokenGenerate([]byte(encryptBody))
				if tokenCode == 400 {
					response.Code = 400
					response.Message = "The auth token could not be generated!"
					return response

				}
				response.Code = 200
				response.Token = token
				response.Message = "Logged in succefully, find auth-token in the header"

			} else {

				isEmailSent := usermodel.ConfirmEmail(userContact)

				if !isEmailSent {
					response.Code = 400
					response.Message = "This email address is not registered, please first register!"
				} else {

					response.Code = 200
					response.Message = "This is a new device. A confirmation code has been sent to your email address"
				}
			}

		} else {
			response.Code = 400
			response.Message = "Wrong Passworld!"
		}

	} else {
		response.Code = 400
		response.Message = "Wrong email address!"
	}

	return response
}

func userLoginByPhone(request inter.Request) usermodel.ErrorStruct {
	var user mongo.User
	var exist bool = false
	var tokenStruct usermodel.TokenResponse
	//___________ Initializing response struct (Default code 400)

	var response = usermodel.ErrorStruct{

		Code: http.StatusInternalServerError, Message: "Security breach ! check your credentials",
	}

	userContact := request.Parameter("contact").String()
	p := request.Parameter("password").String()
	devID := request.Header("deviceid")
	// devToken := request.Header("devtoken")
	rcvdpass := jwttoken.Hasher(p)

	//____________ Query the user

	user, exist = mongo.UserQuerybyPhone(userContact)

	if exist {
		if rcvdpass == user.Password {

			userid := user.ID.Hex()
			theDevice, deviceExist := usermodel.DeviceExist(devID, userid, request)
			if deviceExist {

				response.Code = 200
				response.Message = "Logged in successfully"
				tokenStruct.UserID = userid
				tokenStruct.DeviceID = devID
				body, _ := json.Marshal(tokenStruct)
				encryptedBody, err := encryption.Encrypt(string(body), theDevice.SecretKey)
				if err != nil {
					response.Code = 400
					response.Message = "The auth token could not be generated!"
					return response
				}
				token, tokenCode := TokenGenerate([]byte(encryptedBody))
				if tokenCode == 400 {
					response.Code = 400
					response.Message = "The auth token could not be generated!"
					return response

				}
				response.Code = 200
				response.Token = token
				response.Message = "Logged in succefully, find auth-token in the header"

			} else {

				//_________Send a confirmation code

				isSmsSent := usermodel.SendSmsRegister(user.CountryID, userContact)
				if !isSmsSent {

					response.Code = 400
					response.Message = "This phone number is not registered, please register first !"

				} else {

					response.Code = 200
					response.Message = "This is a new phone. A confirmation code has been sent by sms"
				}
			}

		} else {
			response.Code = 400
			response.Message = "Wrong Passworld!"
		}

	} else {
		response.Code = 400
		response.Message = "Wrong phone number!"
	}

	return response
}

func ChangePassword(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	var body usermodel.TokenResponse
	devid := request.Header("deviceid")
	encryptedBody, err := jwttoken.JwtTokenChecker(request)
	if err != nil {
		response.Code = 400
		response.Message = "Not authorized"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)
	}
	decodedBody, auth := encryption.AuthAndDecoder(devid, string(encryptedBody))
	if !auth {
		response.Code = 4
		response.Message = "This device is not authorized! Please login again"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)

	}
	ok := json.Unmarshal([]byte(decodedBody), &body)
	if ok != nil {
		return outcome.Json("Couldn't unmarshal json to struct").
			Status(response.Code)
	}
	// userid := body.UserID
	var exist bool
	var user mongo.User

	//______________________________________________
	// TODO: add new function for forgot password to check both email and phon are confirmed, ask customer to which one wants to code be sent?
	//______________________________________________

	// userContact := request.Parameter("contact").String()
	// isEmail := strings.Contains(userContact, "@")

	// if isEmail {

	// 	//___________The user exist or not
	// 	user, exist = mongo.UserQuerybyEmail(userContact)

	// } else {

	// 	//____________The user exist or not
	// 	user, exist = mongo.UserQuerybyPhone(userContact)

	// }

	// fmt.Println(user)
	user, exist = mongo.UserQuerybyUserID(body.UserID)

	if exist {

		//_________Sending the confirmation email
		if user.EmailConf {

			isEmailSent := usermodel.ConfirmEmail(user.Email)

			if !isEmailSent {
				//_____________________any error occured
				response.Code = 411
				response.Message = "The email was not able to sent. Please try later"

			} else {
				response.Code = 200
				response.Message = "The confirmation email has been sent"
			}
		} else if user.PhoneConf {
			//_________Sending the confirmation SMS
			isSmsSent := usermodel.SendSmsRegister(user.CountryID, user.Phone)

			if !isSmsSent {
				response.Code = 411
				response.Message = "The sms was not able to sent. Please try later"

			} else {
				response.Code = 200
				response.Message = "The confirmation sms has been sent"

			}

		}
	} else {
		response.Code = 405
		response.Message = "This account is not registered!"
	}

	return outcome.Json(response.Message).
		Status(response.Code).
		Header("auth-token", response.Token)
}

func PasswordConformcode(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	var conCode usermodel.ConfirmationCode
	var body usermodel.TokenResponse
	devid := request.Header("deviceid")
	conCode.ConfirmCode = request.Parameter("confirmcode").String()
	var userContact string = request.Parameter("contact").String()
	code, exist := mongo.CodeFetcher(userContact)
	if !exist {

		response.Code = 402
		response.Message = "The entered code has been expired!"
		return outcome.Json(response.Message).
			Status(response.Code)
	}
	encryptedBody, err := jwttoken.JwtTokenChecker(request)
	if err != nil {
		response.Code = 400
		response.Message = "Not authorized"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)
	}
	decodedBody, auth := encryption.AuthAndDecoder(devid, string(encryptedBody))
	if !auth {
		response.Code = 400
		response.Message = "This device is not authorized! Please login again"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)

	}
	ok := json.Unmarshal([]byte(decodedBody), &body)
	if ok != nil {
		return outcome.Json("Couldn't unmarshal json to struct").
			Status(response.Code)
	}
	// userid := body.UserID
	//____________________________________

	// if er != nil {
	// 	return outcome.Json("Authentication failed!").
	// 		Status(400).
	// 		Header("auth-token", "failed")
	// }

	//_________________________________________orignal code has two return "Error" or Code

	originCode := code.Code
	recvdCode := jwttoken.Hasher(conCode.ConfirmCode)

	if recvdCode == originCode {

		// return outcome.RedirectPermanent("/")

		response.Code = 200
		response.Message = "The code has been accepted, Redirect to change pass"
		return outcome.Json(response.Message).
			Status(response.Code)

	} else {

		response.Code = 401
		response.Message = "The code is not correct!"

	}

	return outcome.Json(response.Message).
		Status(response.Code)

}
func ApplyChangePassword(request inter.Request) inter.Response {
	var body usermodel.TokenResponse
	var response usermodel.ErrorStruct
	devid := request.Header("deviceid")
	encryptedBody, err := jwttoken.JwtTokenChecker(request)
	if err != nil {
		response.Code = 400
		response.Message = "Not authorized"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)
	}
	decodedBody, auth := encryption.AuthAndDecoder(devid, string(encryptedBody))
	if !auth {
		response.Code = 400
		response.Message = "This device is not authorized! Please login again"
		return outcome.Json(response.Message).
			Status(response.Code).
			Header("auth-token", response.Token)

	}
	ok := json.Unmarshal([]byte(decodedBody), &body)
	if ok != nil {
		return outcome.Json("Couldn't unmarshal json to struct").
			Status(response.Code)
	}
	userid := body.UserID

	// var err bool
	//_________________________fetching form input
	var newPassword string = request.Parameter("newpass").String()
	var conPassword string = request.Parameter("confpass").String()
	// var userContact string = request.Parameter("contact").String()

	if !usermodel.IsPasswordValid(newPassword) { //Password Validation
		response.Code = 422
		response.Message = "Password must meets the requirements"

	} else {
		if newPassword == conPassword {
			newPass := jwttoken.Hasher(newPassword)
			passChangeOk := mongo.ForgotPassUpdatorByID(userid, newPass)

			if passChangeOk {
				response.Code = 200
				response.Message = "Password updated sucessfully"
			} else {
				response.Code = 420
				response.Message = "Internal error occured while updating the password please try again later"
			}
		} else {
			response.Code = 421
			response.Message = "Password must be the same"
		}
	}

	return outcome.Json(response.Message).
		Status(response.Code)
}

func TokenGenerate(body []byte) (string, int) {
	// mongo.Init()

	token, err := jwttoken.CreateToken(body)
	if err != nil {
		return "failed", 400
	}

	return token, 200
}

func ForgotPassword(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	var user mongo.User
	var exist bool
	userContact := request.Parameter("contact").String()
	isEmail := strings.Contains(userContact, "@")

	if isEmail {

		//___________The user exist or not
		user, exist = mongo.UserQuerybyEmail(userContact)

	} else {

		//____________The user exist or not
		user, exist = mongo.UserQuerybyPhone(userContact)

	}

	if exist {

		//_________Sending the confirmation email

		if user.EmailConf {

			isEmailSent := usermodel.ConfirmEmail(user.Email)

			if !isEmailSent {

				response.Code = 411
				response.Message = "The email was not able to sent. Please try later"

			} else {
				response.Code = 200
				response.Message = "The confirmation email has been sent"
			}
		} else if user.PhoneConf {
			//_________Sending the confirmation SMS
			isSmsSent := usermodel.SendSmsRegister(user.CountryID, user.Phone)

			if !isSmsSent {
				response.Code = 411
				response.Message = "The sms was not able to sent. Please try later"

			} else {
				response.Code = 200
				response.Message = "The confirmation sms has been sent"

			}

		}
	} else {
		response.Code = 405
		response.Message = "This account is not registered!"
	}

	return outcome.Json(response).
		Status(response.Code)
}

func ForgotPassConfirm(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	var conCode usermodel.ConfirmationCode
	//________________________request form parameter
	conCode.ConfirmCode = request.Parameter("confirmcode").String()
	var userContact string = request.Parameter("contact").String()

	code, exist := mongo.CodeFetcher(userContact)
	//_________________________________________orignal code has two return "Error" or Code
	if !exist {

		response.Code = 402
		response.Message = "The entered code has been expired!"
		return outcome.Json(response)
	}

	recvdCode := jwttoken.Hasher(conCode.ConfirmCode)
	originCode := code.Code
	if recvdCode == originCode {

		// return outcome.RedirectPermanent("/")

		response.Code = 200
		response.Message = "The code has been accepted, Redirect to change pass"
		return outcome.Json(response.Message).
			Status(response.Code)

	} else {

		response.Code = 401
		response.Message = "The code is not correct!"

	}

	return outcome.Json(response.Message).
		Status(response.Code)
}

func ForgetPassApply(request inter.Request) inter.Response {
	var response usermodel.ErrorStruct
	var ok bool
	//_________________________fetching form input
	var newPassword string = request.Parameter("newpass").String()
	var conPassword string = request.Parameter("confpass").String()
	var userContact string = request.Parameter("contact").String()

	if !usermodel.IsPasswordValid(newPassword) { //Password Validation
		response.Code = 422
		response.Message = "Password must meets the requirements"

	} else {
		if newPassword == conPassword {
			newPass := jwttoken.Hasher(newPassword)
			isEmail := strings.Contains(userContact, "@")
			if isEmail {
				ok = mongo.ForgotPassUpdatorByEmail(userContact, newPass)
			} else {
				ok = mongo.ForgotPassUpdatorByPhone(userContact, newPass)
			}
			// passChangeOk := mongo.ForgotPassUpdatorByID(userid, newPass)

			if ok {
				response.Code = 200
				response.Message = "Password updated sucessfully"
			} else {
				response.Code = 500
				response.Message = "Internal error occured while updating the password please try again later"
			}
		} else {
			response.Code = 421
			response.Message = "Password must be the same"
		}
	}

	return outcome.Json(response.Message).
		Status(response.Code)
}
