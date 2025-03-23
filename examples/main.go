package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	kitesession "github.com/nsvirk/gokitesession"
)

// Main function for demonstration
func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	userId := os.Getenv("KITE_USER_ID")
	password := os.Getenv("KITE_PASSWORD")
	totpSecret := os.Getenv("KITE_TOTP_SECRET")
	apiKey := os.Getenv("KITE_API_KEY")
	apiSecret := os.Getenv("KITE_API_SECRET")

	printKiteUser(userId, password, totpSecret, apiKey, apiSecret)

	if userId == "" || password == "" || totpSecret == "" {
		log.Fatal("Missing environment variables")
	}

	client, err := kitesession.NewKiteSessionClient()
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	// Generate session
	session, err := client.GenerateSession(userId, password, totpSecret, apiKey, apiSecret)
	if err != nil {
		fmt.Printf("Error generating session: %v\n", err)
		return
	}
	printKiteSession(session)

	// Validate session
	isValid := client.IsValidEnctoken(session.Enctoken)
	printOMSSessionValid(isValid)

	isValid = client.IsValidAccessToken(apiKey, session.AccessToken)
	printAPISessionValid(isValid)

}

func printKiteUser(userId, password, totpSecret, apiKey, apiSecret string) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Kite User")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("User Id      	: %s\n", userId)
	fmt.Printf("Password     	: %s\n", password)
	fmt.Printf("TwoFa Secret  	: %s\n", totpSecret)
	fmt.Printf("API Key      	: %s\n", apiKey)
	fmt.Printf("API Secret   	: %s\n", apiSecret)
	fmt.Println("")
}

func printKiteSession(ks *kitesession.KiteSession) {
	fmt.Println("--------------------------------------------------------------")
	if ks.APIKey == "" {
		fmt.Println("Kite OMS Session")
	} else {
		fmt.Println("Kite API Session")
	}
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("user_id        : %s\n", ks.UserID)
	fmt.Printf("user_name      : %s\n", ks.UserName)
	fmt.Printf("user_shortname : %s\n", ks.UserShortname)
	fmt.Printf("public_token   : %s\n", ks.PublicToken)
	fmt.Printf("kf_session     : %s\n", ks.KFSession)
	fmt.Printf("enctoken       : %s\n", ks.Enctoken[:32]+"...")
	fmt.Printf("login_time     : %s\n", ks.LoginTime)
	fmt.Printf("user_type      : %s\n", ks.UserType)
	fmt.Printf("email          : %s\n", ks.Email)
	fmt.Printf("broker         : %s\n", ks.Broker)
	fmt.Printf("exchanges      : %v\n", ks.Exchanges)
	fmt.Printf("products       : %v\n", ks.Products)
	fmt.Printf("order_types    : %v\n", ks.OrderTypes)
	fmt.Printf("avatar_url     : %s\n", ks.AvatarURL)
	fmt.Printf("api_key        : %s\n", ks.APIKey)
	fmt.Printf("access_token   : %s\n", ks.AccessToken)
	fmt.Printf("refresh_token  : %s\n", ks.RefreshToken)
	fmt.Printf("meta           : %v\n", ks.Meta)
	fmt.Println("")
}

func printOMSSessionValid(isValid bool) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Is OMS Session Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("OMS Session Valid : %t\n", isValid)
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("")
}

func printAPISessionValid(isValid bool) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Is API Session Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("API Session Valid : %t\n", isValid)
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("")
}
