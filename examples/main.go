// Package main provides an example of using the kitesession package.
package main

import (
	"fmt"
	"log"
	"os"

	kitesession "github.com/nsvirk/gokitesession"
)

// Config holds the configuration data for the Kite session.
type Config struct {
	UserID     string
	Password   string
	TOTPSecret string
}

func main() {
	// Get configuration from environment variables
	config, err := getConfig()
	if err != nil {
		log.Fatalf("Error getting configuration: %v", err)
	}

	// Create a new Kite session client
	ks := kitesession.New()
	ks.SetDebug(false)

	// Generate TOTP value
	totpValue, err := kitesession.GenerateTOTPValue(config.TOTPSecret)
	if err != nil {
		log.Fatalf("Error generating TOTP value: %v", err)
	}

	// Print input values
	printInputValues(config.UserID, config.Password, totpValue)

	// Generate a new kite session
	kiteSession, err := ks.GenerateSession(config.UserID, config.Password, totpValue)
	if err != nil {
		log.Fatalf("Error generating session: %v", err)
	}

	// Print session information
	printSessionInfo(kiteSession)

	// Check if the enctoken is valid
	isValid, err := ks.CheckEnctokenValid(kiteSession.Enctoken)
	if err != nil {
		log.Fatalf("Error checking enctoken validity: %v", err)
	}

	// Print enctoken validity
	printEnctokenValidity(isValid)

}

// getConfig retrieves the configuration from environment variables.
func getConfig() (*Config, error) {
	userID := os.Getenv("KITE_USER_ID")
	password := os.Getenv("KITE_PASSWORD")
	totpSecret := os.Getenv("KITE_TOTP_SECRET")

	if userID == "" || password == "" || totpSecret == "" {
		return nil, fmt.Errorf("KITE_USER_ID, KITE_PASSWORD, and KITE_TOTP_SECRET environment variables must be set")
	}

	return &Config{
		UserID:     userID,
		Password:   password,
		TOTPSecret: totpSecret,
	}, nil
}

// printInputValues prints the input values used for authentication.
func printInputValues(userID, password, totpValue string) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("User Inputs")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("User ID      	: %s\n", userID)
	fmt.Printf("Password     	: %s\n", password)
	fmt.Printf("TOTP Value   	: %s\n\n", totpValue)
}

// printSessionInfo prints the session information.
func printSessionInfo(kiteSession *kitesession.KiteSession) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Kite Session")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("user_id        : %s\n", kiteSession.UserId)
	fmt.Printf("user_name      : %s\n", kiteSession.UserName)
	fmt.Printf("user_shortname : %s\n", kiteSession.UserShortname)
	fmt.Printf("enctoken       : %s\n", kiteSession.Enctoken)
	fmt.Printf("public_token   : %s\n", kiteSession.PublicToken)
	fmt.Printf("kf_session     : %s\n", kiteSession.KfSession)
	fmt.Printf("login_time     : %s\n", kiteSession.LoginTime)
	fmt.Printf("avatar_url     : %s\n\n", kiteSession.AvatarUrl)
}

// printEnctokenValidity prints whether the enctoken is valid.
func printEnctokenValidity(isValid bool) {
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Check Enctoken Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("Enctoken Valid : %t\n\n", isValid)
	fmt.Println("--------------------------------------------------------------")
}
