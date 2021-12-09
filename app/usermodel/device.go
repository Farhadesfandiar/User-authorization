package usermodel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"src/app/mongo"

	"github.com/avct/uasurfer"
	"github.com/confetti-framework/contract/inter"
)

func DeviceExist(devid string, userid string, request inter.Request) (mongo.Device, bool) {

	device := GetUserAgent(devid, userid, request)
	deviceDB, exist := mongo.DeviceExist(device)
	if exist {
		device.SecretKey = deviceDB.SecretKey
		return device, true
	}
	return device, false

}

func GetUserAgent(devid string, userid string, request inter.Request) mongo.Device {
	var device mongo.Device
	ua := request.Header("User-Agent")
	ip, _, _ := net.SplitHostPort(request.Source().RemoteAddr)
	parseua := uasurfer.Parse(ua)
	device.Userid = userid
	device.Browser = parseua.Browser.Name.String()
	device.Platform = parseua.OS.Platform.String()
	device.OSName = parseua.OS.Name.String()
	device.OSVersion = fmt.Sprintf(device.OSVersion, parseua.OS.Version.Major)
	device.DeviceType = parseua.DeviceType.String()
	device.IP = ip
	device.DeviceID = devid
	return device

}

func RandToken(devid string) (string, error) {
	if devid == "" {
		bytes := make([]byte, 16)
		if _, err := rand.Read(bytes); err != nil {
			return "", err
		}
		return hex.EncodeToString(bytes), nil
	}
	return devid, nil
}
