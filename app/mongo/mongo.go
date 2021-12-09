package mongo

import (
	"context"
	"time"

	"github.com/kamva/mgm/v3"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func Init() bool {
	// Setup the mgm default config
	err := mgm.SetDefaultConfig(nil, "DBname", options.Client().ApplyURI("mongodb://localhost:27017"))
	// root:12345@
	return err == nil
}

//______Temporary User collection which keeps user info for max 24 hrs. After receiving the confirmed code the user will be deleted if still exist
type TempUser struct {
	mgm.DefaultModel `bson:",inline"`
	Contact          string `json:"contact" bson:"contact"`
	Password         string `json:"password" bson:"password"`
}

type User struct {
	mgm.DefaultModel `bson:",inline"`
	Email            string `json:"email" bson:"email"`
	Password         string `json:"password" bson:"password"`
	Phone            string `json:"phone" bson:"phone"`
	KYC              string `json:"kyc" bson:"kyc"`
	Invit            string `json:"invite" bson:"invite"`
	AccountConf      bool   `json:"accountconf" bson:"accountconf"`
	EmailConf        bool   `json:"emailconf" bson:"emailconf"`
	PhoneConf        bool   `json:"phonconf" bson:"phonconf"`
	KYCConf          bool   `json:"kycconf" bson:"kycconf"`
}

type Code struct {
	mgm.DefaultModel `bson:",inline"`
	Userid           string `json:"userid" bson:"userid"`
	Contact          string `json:"contact" bson:"contact"`
	Code             string `json:"code" bson:"code"`
	CountryID        int    `json:"countryid" bson:"countryid"`
}

type Device struct {
	mgm.DefaultModel `bson:",inline"`
	Userid           string `json:"userid" bson:"userid"`
	Browser          string `json:"browsername" bson:"browsername"`
	Platform         string `json:"platform" bson:"platform"`
	OSName           string `json:"osname" bson:"osname"`
	OSVersion        string `json:"osversion" bson:"osversion"`
	DeviceType       string `json:"devicetype" bson:"devicetype"`
	IP               string `json:"ip" bson:"ip"`
	// Country          string `json:"country" bson:"country"`
	DeviceID  string `json:"deviceid" bson:"deviceid"`
	SecretKey string `json:"secret" bson:"secret"`
}
type TempPass struct {
	mgm.DefaultModel `bson:",inline"`
	Userid           string `json:"userid" bson:"userid"`
	Contact          string `json:"contact" bson:"contact"`
}

func NewTempPass(userid string, contact string) *TempPass {
	return &TempPass{
		Userid:  userid,
		Contact: contact,
	}
}

func NewDevice(device Device) *Device {
	return &Device{

		Userid:     device.Userid,
		Browser:    device.Browser,
		Platform:   device.Platform,
		OSName:     device.OSName,
		OSVersion:  device.OSVersion,
		DeviceType: device.DeviceType,
		IP:         device.IP,
		// Country:    device.Country,
		DeviceID:  device.DeviceID,
		SecretKey: device.SecretKey,
	}
}

func NewTempUser(contact string, pass string, countryID int) *TempUser {
	return &TempUser{
		Contact:  contact,
		Password: pass,
	}
}

func NewUserByEmail(email string, pass string) *User {
	return &User{
		Email:    email,
		Password: pass,
	}
}

func NewUserByPhone(phone string, pass string, countryid int) *User {
	return &User{
		Phone:    phone,
		Password: pass,
	}
}

func CodeInsertByEmail(userid string, email string, code string) *Code {
	return &Code{
		Userid:  userid,
		Contact: email,
		Code:    code,
	}
}

func CodeInsertByPhone(userid string, phone string, code string, countryID int) *Code {
	return &Code{
		Userid:    userid,
		Contact:   phone,
		Code:      code,
		CountryID: countryID,
	}
}

func UserIdFetcherEmail(useremail string) string {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"email": useremail}).Decode(&user)
	if err != nil {
		return "Error"
	}

	return user.ID.Hex()
}

func UserIdFetcherPhone(phoneNumber string) string {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"phone": phoneNumber}).Decode(&user)
	if err != nil {
		return "Error"
	}

	return user.ID.Hex()
}

func CodeFetcher(contact string) (Code, bool) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	code := &Code{}
	coll := mgm.Coll(code)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"contact": contact}).Decode(&code)
	if err != nil {
		return *code, false
	}

	return *code, true
}

func CodeFetcherPhone(phoneNumber string) string {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	code := &Code{}
	coll := mgm.Coll(code)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"contact": phoneNumber}).Decode(&code)
	if err != nil {
		return "Error"
	}

	return code.Code
}

func EmailConfirmor(email string) bool {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"email": email}).Decode(&user)
	if err != nil {
		return false
	}

	user.EmailConf = true
	err = mgm.Coll(user).Update(user)

	return err == nil
}

func ConfirmorPhone(phone string) bool {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"phone": phone}).Decode(&user)
	if err != nil {
		return false
	}

	user.PhoneConf = true
	err = mgm.Coll(user).Update(user)

	return err == nil
}

func UserQuerybyEmail(userContact string) (User, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"email": userContact}).Decode(&user)
	if err != nil {
		return *user, false
	}

	return *user, true
}

func UserQuerybyPhone(userContact string) (User, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"phone": userContact}).Decode(&user)
	if err != nil {
		return *user, false
	}

	return *user, true
}

func TempUserExist(contact string) (TempUser, bool) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	tempUser := &TempUser{}
	coll := mgm.Coll(tempUser)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"contact": contact}).Decode(&tempUser)
	if err != nil {
		return *tempUser, false
	}

	return *tempUser, true
}

func TempUserDelete(contact string) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	tempUser := &TempUser{}
	coll := mgm.Coll(tempUser)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"contact": contact}).Decode(&tempUser)
	if err == nil {
		mgm.Coll(tempUser).Delete(tempUser)
	}
}

func CodeDelete(contact string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	code := &Code{}
	coll := mgm.Coll(code)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"contact": contact}).Decode(&code)
	if err == nil {
		mgm.Coll(code).Delete(code)
	}
}

func DeviceExist(currentDev Device) (Device, bool) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	device := &Device{}
	coll := mgm.Coll(device)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"userid": currentDev.Userid, "deviceid": currentDev.DeviceID}).Decode(&device)

	if err != nil {
		return *device, false
	}
	return *device, true
}

func ForgotPassUpdatorByEmail(contact string, pass string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"email": contact}).Decode(&user)
	if err != nil {
		return false
	}

	user.Password = pass
	err = mgm.Coll(user).Update(user)

	return err == nil
}

func ForgotPassUpdatorByPhone(contact string, pass string) bool {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	user := &User{}
	coll := mgm.Coll(user)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{
		"phone": contact}).Decode(&user)
	if err != nil {
		return false
	}

	user.Password = pass
	err = mgm.Coll(user).Update(user)

	return err == nil
}

func UserQuerybyUserID(userid string) (User, bool) {

	user := &User{}
	coll := mgm.Coll(user)
	var err = coll.FindByID(userid, user)

	if err != nil {
		return *user, false
	}

	return *user, true
}

func ForgotPassUpdatorByID(userid string, pass string) bool {
	user := &User{}
	coll := mgm.Coll(user)
	var err = coll.FindByID(userid, user)
	if err != nil {
		return false
	}

	user.Password = pass
	err = mgm.Coll(user).Update(user)

	return err == nil
}

func SecretFetcher(deviceID string) string {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	device := &Device{}
	coll := mgm.Coll(device)
	defer cancel()
	var err = coll.FindOne(ctx, bson.M{"deviceid": deviceID}).Decode(&device)
	if err != nil {
		return ""
	}
	return device.SecretKey
}
