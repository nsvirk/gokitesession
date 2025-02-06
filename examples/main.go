package main

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	kitesession "github.com/nsvirk/gokitesession"
)

func main() {
	user, err := getUser()
	if err != nil {
		log.Fatal(err)
	}
	printUser(user)

	// Initialize kiteauth client
	ka := kitesession.New(user.APIKey)

	// Generate API session
	apiSession, err := ka.GenerateUserSession(*user)
	if err != nil {
		log.Fatal(err)
	}

	// Check if API session is valid
	isAPISessionValid := ka.IsAccessTokenValid(apiSession.AccessToken)

	// Clear API key and secret
	user.APIKey = ""
	user.APISecret = ""

	// Generate OMS session
	omsSession, err := ka.GenerateUserSession(*user)
	if err != nil {
		log.Fatal(err)
	}

	// Check if OMS session is valid
	isOMSSessionValid := ka.IsEnctokenValid(omsSession.Enctoken)

	// Print API session
	kitesession.PrintUserSession("API", apiSession)
	kitesession.PrintAPISessionValid(isAPISessionValid)

	// Print OMS session
	kitesession.PrintUserSession("OMS", omsSession)
	kitesession.PrintOMSSessionValid(isOMSSessionValid)

}

// getUser retrieves the user configuration from environment variables.
func getUser() (*kitesession.User, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	userId := os.Getenv("KITE_USER_ID")
	password := os.Getenv("KITE_PASSWORD")
	twofaSecret := os.Getenv("KITE_TWOFA_SECRET")
	apiKey := os.Getenv("KITE_API_KEY")
	apiSecret := os.Getenv("KITE_API_SECRET")

	if userId == "" || password == "" || twofaSecret == "" {
		return nil, fmt.Errorf("KITE_USER_ID, KITE_PASSWORD, and KITE_TWOFA_SECRET environment variables must be set")
	}

	if apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("KITE_API_KEY and KITE_API_SECRET environment variables must be set")
	}

	return &kitesession.User{
		UserId:      userId,
		Password:    password,
		TwoFaSecret: twofaSecret,
		APIKey:      apiKey,
		APISecret:   apiSecret,
	}, nil
}

// printUser prints the user information.
func printUser(user *kitesession.User) {
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
