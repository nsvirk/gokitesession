package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	kitesession "github.com/nsvirk/gokitesession"
)

// go run examples/main.go
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

	if userId == "" || password == "" || totpSecret == "" {
		log.Fatal("Missing environment variables")
	}

	printKiteUser(userId, password, totpSecret, apiKey, apiSecret)

	// generate kitesession
	client, err := kitesession.NewClient()
	if err != nil {
		log.Fatal("Error creating client: ", err)
	}

	kiteSession, err := client.GenerateSession(userId, password, totpSecret, apiKey, apiSecret)
	if err != nil {
		fmt.Println("--------------------------------")
		fmt.Printf("error: %+v\n", err)
		fmt.Printf("error_code: %v\n", client.KiteSessionError.ErrorCode)
		fmt.Printf("error_type: %v\n", client.KiteSessionError.ErrorType)
		fmt.Printf("error_message: %v\n", client.KiteSessionError.Message)
		fmt.Println("--------------------------------")
		return
	}

	printKiteSession(kiteSession)

}

// printKiteUser prints the kite user details
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

// printKiteSession prints the kite session details
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
	fmt.Println("--------------------------------------------------------------")
}
