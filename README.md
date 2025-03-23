# Kite Session client for Zerodha

> The Go package to generate session tokens automatically for using with KiteConnect and Kiteticker API.
> Can be used as a standalone library in other Go apps.
> If API Key and API Secret are available then generates `access_token` else generates `enctoken`

## Usage Instructions as a standalone library

### Required

- **KITE_USER_ID** : Your kite user_id
- **KITE_PASSWORD** : Your kite password
- **KITE_TOTP_SECRET** : Its a value which you can copy while setting your external 2FA Authentication
- **KITE_API_KEY** : API Key obtained using Kite Developer account
- **KITE_API_SECRET** : API Secret obtained using Kite Developer account

#### Obtaining Two FA Secret

- Set up External 2FA Auth by going to "My Profile > Settings > Account Security > External 2FA TOTP" and copy the value, while setting.

## Import

```go
go get github.com/nsvirk/gokitesession
```

## Sample code

```md
See `examples/main.go`
```
