# WebEPJ Sample Application

This application demonstrates the integration between an ASP.NET Core MVC application and the SFM client application.

The sample demonstrates:

- HelseID authentication using Authorization Code with PKCE.
- Pushed Authorization Requests (PAR).
- Single-tenant and multi-tenant organization context.
- DPoP-protected HelseID token requests.
- DPoP-protected SFM Session Gateway requests.
- SFM session creation, renewal, termination, and patient ticket creation.
- Opening a patient in the SFM client through `window.postMessage`.

For support, refer to the [support contact information](https://e-resept.atlassian.net/wiki/spaces/SFMDOK/pages/2160492666/Kontaktinformasjon).

For additional SFM integration information, refer to the [SFM full version documentation](https://e-resept.atlassian.net/wiki/spaces/SFMDOK/pages/2160492688/SFM+Fullversjon).

## Requirements

- .NET SDK 10.
- Access to a HelseID test environment.
- HelseID clients registered for the sample application.
- Access to the SFM Session Gateway and SFM client application.
- A redirect URI registered in HelseID that matches the local application URL.

The solution uses .NET 10 and central package management. Package versions are defined in `Directory.Packages.props`, and common build settings are defined in `Directory.Build.props`.

## Configuration

The main configuration is in `WebEpj/appsettings.json`.

Required settings:

- `SfmSessionGatewayEndpoint`: the SFM Session Gateway base URL.
- `Authentication:Endpoint`: the HelseID authority and discovery endpoint.
- `Authentication:OrganizationSfmId`: the HelseID client used for single-tenant organization login.
- `Authentication:EpjVendorId`: the HelseID client used for multi-tenant EPJ vendor login.
- `Authentication:SignedOutRedirectUri`: the redirect URI used after logout.
- `Authentication:Scopes`: requested scopes. `e-helse:sfm.api/sfm.api2` is required for Session Gateway calls.
- `Authentication:TokenRenewCheckInMinutes`: the token renewal threshold.

The sample embeds these key files in the WebEpj assembly:

- `HelseIdClientRsaPrivateKey.pem`: the organization client assertion key for single-tenant authentication.
- `HelseIdClientEpjVenderPrivateKey.json`: the EPJ vendor key for multi-tenant client assertions and DPoP proofs.

The public keys corresponding to these private keys must be registered with the appropriate HelseID clients. Do not use these sample keys in production.

## Authentication Flow

### Single-tenant login

1. Select the single-tenant login option.
2. The application stores the tenant context in the ASP.NET session.
3. ASP.NET Core starts Authorization Code with PKCE.
4. PAR is required, so the authorization parameters are sent to the HelseID PAR endpoint first.
5. The PAR request is authenticated with a short-lived `private_key_jwt` client assertion.
6. HelseID returns a `request_uri`, and the browser is redirected using that reference.
7. The authorization code is redeemed with PKCE and DPoP.

### Multi-tenant login

1. Enter the parent and optional child organization identifiers.
2. The values are stored in the ASP.NET session.
3. The authorization request includes the organization context in the signed `authorization_details` request object.
4. The request object is signed with `PS256` and has a short lifetime.
5. The authorization code is redeemed using the EPJ vendor client and the same PKCE and DPoP flow.

The request object contains HelseID authorization details for the organization and the configured SFM journal identifier.

## PAR

PAR is enabled with `PushedAuthorizationBehavior.Require`. The HelseID discovery document must expose a pushed authorization request endpoint.

The HelseID clients must support Authorization Code with PKCE, PAR, `private_key_jwt` authentication, the configured redirect URI, and all scopes listed in `Authentication:Scopes`.

Client assertions and request objects are short-lived and use `PS256`. Their lifetime is 10 seconds, matching the SFM implementation.

## DPoP

DPoP is used for authorization code redemption, refresh token redemption, and SFM Session Gateway requests.

The sample reuses the embedded `HelseIdClientEpjVenderPrivateKey.json` for DPoP. No separate `DPoPKey` configuration value is required.

Each proof contains the actual HTTP method and URL. Token-bound proofs also include the access-token hash (`ath`). Requests use:

```http
Authorization: DPoP <access-token>
DPoP: <dpop-proof>
```

If HelseID responds with `use_dpop_nonce`, the token request is retried once with the returned nonce.

## SFM Session Flow

After authentication:

1. The application creates an SFM session with `POST /api/v2/Session/create`.
2. The SFM session code, nonce, API address, and portal metadata are passed to the SFM client.
3. The SFM client is loaded in the iframe.
4. The application sends a `login` message through `iframe.contentWindow.postMessage`.
5. The application requests a patient ticket with `POST /api/v2/PatientTicket`.
6. The ticket is sent to the SFM client with a `setPatient` message.
7. Session renewal uses `POST /api/v2/Session/refresh`.
8. Logout uses `POST /api/v2/Session/end` before HelseID sign-out.

The browser message integration is implemented in `WebEpj/Views/Home/Authenticate.cshtml`.

## Running the Sample

1. Configure `WebEpj/appsettings.json` for the target HelseID and SFM test environment.
2. Confirm that the embedded keys match the public keys registered in HelseID.
3. Confirm that the redirect URI is registered and matches the local callback configuration.
4. Restore and build the solution:

```bash
dotnet restore WebEpj.slnx
dotnet build WebEpj.slnx
```

5. Start the application:

```bash
dotnet run --project WebEpj/WebEpj.csproj
```

6. Open the displayed local URL.
7. Test single-tenant login.
8. Test multi-tenant login with valid organization identifiers.
9. Select an SFM portal and open a patient.
10. Confirm that session creation, patient ticket creation, SFM login, and `setPatient` complete successfully.

## Troubleshooting

### PAR fails with `invalid_client`

- Confirm that discovery exposes the PAR endpoint.
- Confirm that the client ID matches the selected tenant mode.
- Confirm that the correct public key is registered.
- Confirm that the client assertion uses `PS256` and has not expired.
- Confirm that the system clock is accurate.

### Token redemption fails with `invalid_client`

- Confirm that the authorization code, redirect URI, and PKCE verifier belong to the same request.
- Confirm that the client assertion audience uses the HelseID issuer.
- Confirm that the correct organization or EPJ vendor key is used.

### DPoP validation fails

- Confirm that the EPJ vendor public key is registered for the client.
- Confirm that the proof uses the exact request URL and HTTP method.
- Confirm that the access token uses the `DPoP` authorization scheme.
- Check whether HelseID returned a DPoP nonce and verify that the retry was performed.

### Session Gateway calls fail

- Confirm that the access token contains `e-helse:sfm.api/sfm.api2`.
- Confirm that `SfmSessionGatewayEndpoint` points to the correct environment.
- Confirm that the Session Gateway supports the `/api/v2` endpoints.
- Check the HTTP status and response body logged by the Session Gateway client.

### The SFM client does not open the patient

- Confirm that the patient ticket request succeeded.
- Confirm that the iframe is loaded before sending the message.
- Confirm that the `setPatient` message contains the returned ticket.
- Inspect browser console messages from the SFM client.
