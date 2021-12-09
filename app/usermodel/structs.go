package usermodel

type TokenResponse struct {
	UserID   string
	DeviceID string
}

type ErrorStruct struct {
	Code    int
	Message string
	Token   string
	UserID  string
	DevID   string
}

type SuccessResponse struct {
	Code     int
	Message  string
	Response interface{}
}

type UserParams struct {
	Contact  string `json:"contact"`
	Password string `json:"password"`
	// EmailOrPhone string `json:"emailorphone"`
	// Phone        string `json:"phone"`
}

// type TokenResponse struct {
// 	AuthToken string
// 	// Email     string
// }

type UserDetails struct {
	Email    string
	Password string
}

type ConfirmationCode struct {
	ConfirmCode string `json:"confirmcode"`
	Contact     string `json:"contact"`
	// Phone        string `json:"phone"`
	// EmailOrPhone string `json:"emailorphone"`
}
