package usermodel

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"src/app/jwttoken"
	"src/app/mongo"
	"strconv"
	"strings"

	"github.com/kamva/mgm/v3"
)

type Countrys struct {
	Countrys []Country `json:"countries"`
}

type Country struct {
	ID           string `json:"id"`
	Country_code string `json:"country_code"`
	Phone_code   string `json:"phone_code"`
}

func SendSms(phoneNumber string) bool {

	//__________________Generating the randome verification code
	rndmCode := jwttoken.CodeGenerator(6)
	hashedCode := jwttoken.Hasher(rndmCode)
	//__________________Fetching the "ObjectID" from "users" collection

	userid := mongo.UserIdFetcherPhone(phoneNumber)

	//__________________Record the generated code in "Codes" collection

	code := mongo.CodeInsertByPhone(userid, phoneNumber, hashedCode, 247)
	err := mgm.Coll(code).Create(code)
	if err != nil {
		return false
	}

	// Set variable values
	const username string = "uuuuuu"
	const password string = "455454545"
	var message string = "Your verificaion code is : " + rndmCode
	var receiver string = phoneNumber //the phone number without zero. e.g: 5338370264
	gatewayURL := "sms_provider_url"

	urlStr := gatewayURL

	// Params
	v := url.Values{}
	v.Set("user", username)
	v.Set("password", password)
	v.Set("gsm", receiver)
	v.Set("text", message)
	rb := *strings.NewReader(v.Encode())

	client := &http.Client{}
	req, _ := http.NewRequest("POST", urlStr, &rb)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Make request
	res, err := client.Do(req)

	fmt.Println(res.Status)

	return err == nil
}

func SendSmsRegister(Countryid int, phoneNumber string) bool {

	//__________________Generating the randome verification code
	rndmCode := jwttoken.CodeGenerator(6)
	hashedCode := jwttoken.Hasher(rndmCode)
	//__________________Fetching the "ObjectID" from "users" collection

	userid := mongo.UserIdFetcherPhone(phoneNumber)

	if Countryid == 247 || Countryid == 223 {
		return SendSms(phoneNumber)

	} else {
		countryCode := strconv.Itoa(Countryid)
		phoneCode := JSONFileReader(countryCode)

		//__________________Record the generated code in "Codes" collection

		fullphone := phoneCode + phoneNumber
		code := mongo.CodeInsertByPhone(userid, fullphone, hashedCode, Countryid)
		err := mgm.Coll(code).Create(code)
		if err != nil {
			return false
		}

		//_____________________for internationals_____________________
		const username string = "smsuser"
		const password string = "smspass"
		var message string = "Your verificaion code is : " + rndmCode

		var receiver string = fullphone //the phone number without zero. e.g: 5338370264
		fmt.Println(receiver)
		gatewayURL := "your_sms_provider_url"
		// Set variable values

		urlStr := gatewayURL

		// Params
		v := url.Values{}
		v.Set("user", username)
		v.Set("password", password)
		v.Set("gsm", receiver)
		v.Set("text", message)
		rb := *strings.NewReader(v.Encode())

		client := &http.Client{}
		req, _ := http.NewRequest("POST", urlStr, &rb)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		// Make request
		res, err := client.Do(req)

		fmt.Println(res.Status)

		if err != nil {

			return false
		}
	}
	return true
}

func JSONFileReader(Countryid string) string {
	//___________________remove all Console prints after testing
	jsonFile, err := os.Open("app/usermodel/country.json")

	if err != nil {
		fmt.Println(err)
	}

	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var coun Countrys

	json.Unmarshal(byteValue, &coun)
	var phoneCode string
	var countryID string
	for i := 0; i < len(coun.Countrys); i++ {
		if coun.Countrys[i].ID == Countryid {
			fmt.Println("ID -->: " + coun.Countrys[i].ID)
			fmt.Println("Country Code  -->: " + coun.Countrys[i].Country_code)
			fmt.Println("Phone Code -->: " + coun.Countrys[i].Phone_code)
			fmt.Println("-----------------------------------------------------------")

			countryID = coun.Countrys[i].ID
			phoneCode = coun.Countrys[i].Phone_code
		}

	}
	fmt.Println(countryID)
	fmt.Println(phoneCode)
	return phoneCode
}
