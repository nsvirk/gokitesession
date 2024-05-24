# Kite API Session Client

> The Go client to generate user tokens automatically for using with KiteConnect and Kiteticker API.

## Usage Instructions

### Required:

- **userId** : Your kite user_id
- **password** : Your kite password
- **totpSecret** : Its a value which you can copy while setting your external 2FA TOTP

#### Obtaining 2FA TOTP Secret

- Set up External 2FA TOTP Auth by going to "My Profile > Settings > Account Security > External 2FA TOTP" and copy the value, while setting.

## Installation

```
go get github.com/nsvirk/gokitesession
```

## Sample code

```go
package main

import (
	"fmt"
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
		fmt.Printf("Error generating totp value: %v", err)
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
		fmt.Printf("Error generating session: %v", err)
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
	isValid, err := ks.CheckEnctokenValid(session.Enctoken)
	if err != nil {
		fmt.Printf("Error checking enctoken valid: %v", err)
		return
	}

	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Check Enctoken Valid")
	fmt.Println("--------------------------------------------------------------")
	fmt.Println("Enctoken Valid	: ", isValid)
	fmt.Println("")
	fmt.Println("--------------------------------------------------------------")
}

```
