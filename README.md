# Zerodha Kite User Session client

> The Go package to generate authentication tokens automatically for using with KiteConnect and Kiteticker API.
> Can be used as a standalone library in other Go apps.
> If API Key and API Secret are available then generates `access_token` else generates `enctoken`

## Usage Instructions as a standalone library

### Required:

- **userId** : Your kite user_id
- **password** : Your kite password
- **twoFaSecret** : Its a value which you can copy while setting your external 2FA Authentication
- **apiKey** : API Key obtained using Kite Developer account
- **apiSecret** : API Secret obtained using Kite Developer account

#### Obtaining Two FA Secret

- Set up External 2FA Auth by going to "My Profile > Settings > Account Security > External 2FA TOTP" and copy the value, while setting.

## Installation

```
go get github.com/nsvirk/gokiteauth
```

## Sample code

```
See `examples/main.go`
```
