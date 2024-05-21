package main

import (
	"fmt"
	"log"
	"os"

	kitesession "github.com/nsvirk/gokitesession"
)

var (
	userId     = os.Getenv("KITE_USER_ID")
	password   = os.Getenv("KITE_PASSWORD")
	totpSecret = os.Getenv("KITE_TOTP_SECRET")
)

func main() {

	// Create a new Kite session instance
	ks := kitesession.New(userId)

	// Set debug mode
	ks.SetDebug(true)

	// Generate totp value
	totpValue, err := ks.GenerateTotpValue(totpSecret)
	if err != nil {
		log.Printf("Error generating totp value: %v", err)
		return
	}
	// Check the inputs values
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Kite User")
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("User ID     	: ", userId)
	fmt.Println("Password     	: ", password)
	fmt.Println("Totp Value  	: ", totpValue)
	fmt.Println("")

	// Get kite session data
	session, err := ks.GenerateSession(password, totpValue)
	if err != nil {
		log.Printf("Error generating session: %v", err)
		return
	}

	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Kite Session")
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("user_id     	: ", session.UserId)
	fmt.Println("public_token	: ", session.PublicToken)
	fmt.Println("kf_session   	: ", session.KfSession)
	fmt.Println("enctoken    	: ", session.Enctoken)
	fmt.Println("login_time  	: ", session.LoginTime)
	fmt.Println("username   	: ", session.Username)
	fmt.Println("user_shortname	: ", session.UserShortname)
	fmt.Println("avatar_url  	: ", session.AvatarURL)
	fmt.Println("")
	// fmt.Println(session)

	// Check if the enctoken is valid
	isValid := ks.CheckEnctokenValid(session.Enctoken)
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Check Enctoken Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Enctoken Valid	: ", isValid)
	fmt.Println("")
	fmt.Println("--------------------------------------------------------------")

}