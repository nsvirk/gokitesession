package kitesession

import "fmt"

// PrintUser prints the user information.
func PrintUser(user *User) {
	fmt.Println("================================================================")
	fmt.Println("Kite User")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("User Id      	: %s\n", user.UserId)
	fmt.Printf("Password     	: %s\n", user.Password)
	fmt.Printf("TwoFa Secret  	: %s\n\n", user.TwoFaSecret)
	fmt.Printf("API Key      	: %s\n", user.APIKey)
	fmt.Printf("API Secret   	: %s\n\n", user.APISecret)
	fmt.Println("================================================================")
}

// PrintUserSession prints the user session information.
func PrintUserSession(sessionType string, userSession *UserSession) {
	fmt.Println("================================================================")
	fmt.Printf("%s User Session\n", sessionType)
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("user_id        : %s\n", userSession.UserID)
	fmt.Printf("user_name      : %s\n", userSession.UserName)
	fmt.Printf("user_shortname : %s\n", userSession.UserShortName)
	fmt.Printf("avatar_url     : %s\n", userSession.AvatarURL)
	fmt.Printf("user_type      : %s\n", userSession.UserType)
	fmt.Printf("email          : %s\n", userSession.Email)
	fmt.Printf("broker         : %s\n", userSession.Broker)
	fmt.Printf("meta           : %v\n", userSession.Meta)
	fmt.Printf("products       : %v\n", userSession.Products)
	fmt.Printf("order_types    : %v\n", userSession.OrderTypes)
	fmt.Printf("exchanges      : %v\n", userSession.Exchanges)
	fmt.Printf("access_token   : %s\n", userSession.AccessToken)
	fmt.Printf("refresh_token  : %s\n", userSession.RefreshToken)
	fmt.Printf("enctoken       : %s\n", userSession.Enctoken)
	fmt.Printf("kf_session     : %s\n", userSession.KfSession)
	fmt.Printf("public_token   : %s\n", userSession.PublicToken)
	fmt.Printf("login_time     : %s\n", userSession.LoginTime)
	fmt.Println("================================================================")
}

// PrintOMSSessionValidity prints whether the OMS session is valid.
func PrintOMSSessionValid(isValid bool) {
	fmt.Println("================================================================")
	fmt.Println("Is OMS Session Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("OMS Session Valid : %t\n\n", isValid)
	fmt.Println("================================================================")
}

// PrintAPISessionValidity prints whether the API session is valid.
func PrintAPISessionValid(isValid bool) {
	fmt.Println("================================================================")
	fmt.Println("Is API Session Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("API Session Valid : %t\n\n", isValid)
	fmt.Println("================================================================")
}
