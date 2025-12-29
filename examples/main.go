package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	kitesession "github.com/nsvirk/gokitesession"
)

// go run examples/main.go
func main() {
	// Get environment variables
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Getting environment variables...")
	fmt.Println("--------------------------------------------------------------")

	userId := os.Getenv("KITE_USER_ID")
	password := os.Getenv("KITE_PASSWORD")
	totpSecret := os.Getenv("KITE_TOTP_SECRET")
	apiKey := os.Getenv("KITE_API_KEY")
	apiSecret := os.Getenv("KITE_API_SECRET")

	fmt.Println("KITE_USER_ID: ", userId)
	fmt.Println("KITE_PASSWORD: ", password)
	fmt.Println("KITE_TOTP_SECRET: ", totpSecret)
	fmt.Println("KITE_API_KEY: ", apiKey)
	fmt.Println("KITE_API_SECRET: ", apiSecret)

	if userId == "" || password == "" || totpSecret == "" {
		log.Fatal("Missing required environment variables: KITE_USER_ID, KITE_PASSWORD, KITE_TOTP_SECRET")
	}

	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Generating Kite session...")
	fmt.Println("--------------------------------------------------------------")

	// Create client
	client, err := kitesession.NewClient()
	if err != nil {
		log.Fatal("Error creating client: ", err)
	}

	// Use context for timeout control
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate session with context
	kiteSession, err := client.GenerateSession(
		ctx, userId, password, totpSecret, apiKey, apiSecret,
	)
	if err != nil {
		fmt.Println("--------------------------------------------------------------")
		fmt.Printf("Error generating session: %v\n", err)
		if client.KiteSessionError != nil {
			fmt.Printf("Kite API Error [%d] %s: %s\n",
				client.KiteSessionError.ErrorCode,
				client.KiteSessionError.ErrorType,
				client.KiteSessionError.Message,
			)
		}
		fmt.Println("--------------------------------------------------------------")
		return
	}

	printKiteSession(kiteSession)

}

// printKiteSession prints the kite session details (safely, without exposing full tokens)
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
	// Show public token safely (truncated for security)
	if len(ks.PublicToken) > 10 {
		fmt.Printf("public_token   : %s...%s\n", ks.PublicToken[:5], ks.PublicToken[len(ks.PublicToken)-5:])
	} else {
		fmt.Printf("public_token   : %s\n", ks.PublicToken)
	}

	// Show tokens safely (truncated for security)
	if len(ks.Enctoken) > 32 {
		fmt.Printf("enctoken       : %s... (%d chars)\n", ks.Enctoken[:32], len(ks.Enctoken))
	} else {
		fmt.Printf("enctoken       : %s\n", ks.Enctoken)
	}

	fmt.Printf("login_time     : %s\n", ks.LoginTime)
	fmt.Printf("user_type      : %s\n", ks.UserType)
	fmt.Printf("email          : %s\n", ks.Email)
	fmt.Printf("broker         : %s\n", ks.Broker)
	fmt.Printf("exchanges      : %v\n", ks.Exchanges)
	fmt.Printf("products       : %v\n", ks.Products)
	fmt.Printf("order_types    : %v\n", ks.OrderTypes)
	fmt.Printf("avatar_url     : %s\n", ks.AvatarURL)

	// For API sessions, show API details
	if ks.APIKey != "" {
		fmt.Printf("api_key        : %s\n", ks.APIKey)

		// Show access token safely (truncated)
		if len(ks.AccessToken) > 20 {
			fmt.Printf("access_token   : %s... (%d chars)\n", ks.AccessToken[:20], len(ks.AccessToken))
		} else {
			fmt.Printf("access_token   : %s\n", ks.AccessToken)
		}

		// Show refresh token safely (truncated)
		if len(ks.RefreshToken) > 20 {
			fmt.Printf("refresh_token  : %s... (%d chars)\n", ks.RefreshToken[:20], len(ks.RefreshToken))
		} else {
			fmt.Printf("refresh_token  : %s\n", ks.RefreshToken)
		}
	}

	fmt.Printf("meta           : %v\n", ks.Meta)
	fmt.Println("")
	fmt.Println("--------------------------------------------------------------")
}
