# Kite Session Client for Zerodha

[![Go Reference](https://pkg.go.dev/badge/github.com/nsvirk/gokitesession.svg)](https://pkg.go.dev/github.com/nsvirk/gokitesession)

> The Go package to generate session tokens automatically for using with KiteConnect and KiteTicker API.
>
> Can be used as a standalone library in other Go applications.
>
> - If API Key and API Secret are provided → generates `access_token` (API session)
> - If API Key and API Secret are empty → generates `enctoken` (OMS session)

## Features

- ✅ Automated login with username, password, and TOTP 2FA
- ✅ Supports both OMS and API session generation
- ✅ Context-aware for timeout and cancellation control
- ✅ Comprehensive error handling
- ✅ Type-safe with proper Go types
- ✅ Well documented with godoc comments
- ✅ Clean, modern API with context support

## Installation

```bash
go get github.com/nsvirk/gokitesession
```

## Quick Start

### Basic Usage (OMS Session)

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    kitesession "github.com/nsvirk/gokitesession"
)

func main() {
    client, err := kitesession.NewClient()
    if err != nil {
        log.Fatal(err)
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Generate OMS session (no API key/secret)
    session, err := client.GenerateSession(
        ctx,
        "your_user_id",
        "your_password",
        "your_totp_secret",
        "",  // empty API key for OMS session
        "",  // empty API secret for OMS session
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Enctoken: %s\n", session.Enctoken)
    fmt.Printf("User: %s (%s)\n", session.UserName, session.Email)
}
```

### API Session Usage

```go
// Generate API session (with API key/secret)
session, err := client.GenerateSession(
    ctx,
    "your_user_id",
    "your_password",
    "your_totp_secret",
    "your_api_key",      // API key for API session
    "your_api_secret",   // API secret for API session
)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Access Token: %s\n", session.AccessToken)
fmt.Printf("Enctoken: %s\n", session.Enctoken)
```

## Configuration

### Required Environment Variables

- **KITE_USER_ID** : Your Kite user ID
- **KITE_PASSWORD** : Your Kite password
- **KITE_TOTP_SECRET** : TOTP secret for 2FA (see below how to obtain)
- **KITE_API_KEY** : API Key from Kite Developer account (optional, for API sessions)
- **KITE_API_SECRET** : API Secret from Kite Developer account (optional, for API sessions)

### Obtaining TOTP Secret

1. Go to Kite web: My Profile > Settings > Account Security
2. Click on "External 2FA TOTP"
3. **Copy the secret** shown during setup (before scanning QR code)
4. Use this secret as `KITE_TOTP_SECRET`

### Sample .env File

```env
KITE_USER_ID=AB1234
KITE_PASSWORD=your_password_here
KITE_TOTP_SECRET=ABCDEFGHIJKLMNOP
KITE_API_KEY=your_api_key
KITE_API_SECRET=your_api_secret
```

## Examples

See [examples/main.go](examples/main.go) for a complete working example.

Run the example:

```bash
# Make sure you have a .env file with your credentials
go run examples/main.go
```

## Security Best Practices

1. **Never hardcode credentials** - Always use environment variables or secure vaults
2. **Never commit credentials** - Add `.env` to your `.gitignore`
3. **Never log credentials** - Be careful with logging and error messages
4. **Use HTTPS only** - This library uses HTTPS by default
5. **Rotate tokens regularly** - Generate new sessions periodically
6. **Keep secrets secure** - Store TOTP secret and passwords securely

## Error Handling

The library provides detailed error information:

```go
session, err := client.GenerateSession(ctx, ...)
if err != nil {
    // Check for specific error from Kite API
    if client.KiteSessionError != nil {
        fmt.Printf("Kite Error [%d] %s: %s\n",
            client.KiteSessionError.ErrorCode,
            client.KiteSessionError.ErrorType,
            client.KiteSessionError.Message,
        )
    } else {
        fmt.Printf("Error: %v\n", err)
    }
    return
}
```

## API Documentation

For detailed API documentation, see:

- [pkg.go.dev Documentation](https://pkg.go.dev/github.com/nsvirk/gokitesession)
- [Source Code](https://github.com/nsvirk/gokitesession)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This is an unofficial library and is not affiliated with or endorsed by Zerodha. Use at your own risk.
