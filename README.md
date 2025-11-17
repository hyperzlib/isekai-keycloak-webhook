# Isekai! keycloak webhook
Send event to http api!

## Configure
Goto Admin Console -> User Federation, add 'webhook' provider, and set your webhook endpoints on config page

## Signature
The webhook request will contain a header `X-Signature` which is the HMAC SHA256 signature of the request body using the secret you set in config page.

## Request body example
### LOGIN
```json
{
    "realmId": "master",
    "clientId": "account-console",
    "ipAddress": "127.0.0.1",
    "details": {
        "auth_method": "openid-connect",
        "auth_type": "code",
        "response_type": "code",
        "redirect_uri": "http://localhost:8080/admin/master/console/#/realms/master",
        "consent": "no_consent_required",
        "code_id": "0896dff6-ab1c-4d49-bb5e-5cc7121aa203",
        "response_mode": "fragment",
        "username": "username"
    },
    "id": "deafaa0c-cad9-42cf-a0ab-52cffd3a8c7b",
    "time": 1643981424517,
    "sessionId": "0896dff6-ab1c-4d49-bb5e-5cc7121aa203",
    "type": "LOGIN",
    "error": null,
    "userId": "cb71f742-787d-4bb8-9a36-d919a8321030"
}
```
### UPDATE_PROFILE
```json
{
    "realmId": "master",
    "clientId": "account",
    "userInfo": {
        "sub": "cb71f742-787d-4bb8-9a36-d919a8321030",
        "email_verified": "false",
        "name": "firstName updatedLastName",
        "preferred_username": "username",
        "locale": "en",
        "given_name": "firstName",
        "family_name": "updatedLastName",
        "email": "hyperzlib@outlook.com"
    },
    "ipAddress": "127.0.0.1",
    "details": {
        "previous_last_name": "lastName",
        "context": "ACCOUNT",
        "updated_last_name": "updatedLastName"
    },
    "id": "2b2ced26-725e-4ffb-95b2-cdb7348ee10e",
    "time": 1643981431664,
    "sessionId": null,
    "type": "UPDATE_PROFILE",
    "error": null,
    "userId": "cb71f742-787d-4bb8-9a36-d919a8321030"
}
```