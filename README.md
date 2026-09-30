# WebEPJ Sample App


For support on this code see contact information here:\
https://e-resept.atlassian.net/wiki/spaces/SFMDOK/pages/2160492666/Kontaktinformasjon

For more technical info on SFM integration:\
https://e-resept.atlassian.net/wiki/spaces/SFMDOK/pages/2160492688/SFM+Fullversjon

 
<br>
<br>


This application samples the integration between an ASP.Net Core MVC application (WebEpj) and the SFM Angular client application.

Sampled functionalities:

- OpenId Authentication using HelseId.
- Creating a new SFM Session (see HomeController.Index())
- Renewing a SFM Session token to keep the session alive (see HomeController.RefreshTokenAsync() and OnValidatePrincipal CookieAuthenticationEvents event)
- Request a patient ticket from SFM (see HomeController.LoadTicketAsync)
- Start, login and load a patient using SFM client (see javascript functions under Index.cshtml)

What needs to be configured:
- appSettings:Authentication -> HelseId related settings
- appSettings:SfmSessionGatewayEndpoint -> The SFM session gateway endpoint
- HelseIdClientRsaPrivateKey.pem file -> This is the HelseId Client private key

## HelseID PAR login

The sample requires .NET 10 and uses the native ASP.NET Core OpenID Connect PAR implementation. The login flow is Authorization Code with PKCE, and PAR is required rather than optional.

Before running the sample:

- The HelseID discovery document configured by `Authentication:Endpoint` must advertise a `pushed_authorization_request_endpoint`.
- `Authentication:OrganizationSfmId` and `Authentication:EpjVendorId` must identify clients registered for PAR and `private_key_jwt` client authentication.
- The configured redirect URI must match the HelseID client registration.
- The organization and EPJ vendor private keys embedded by the sample must match the public keys registered for the respective HelseID clients.
- The scopes in `Authentication:Scopes` must be assigned to the clients in the target HelseID environment.

During login, the middleware sends the authorization parameters to the HelseID PAR endpoint. This includes the signed `request` object containing organization context for the multi-tenant flow. The PAR request is authenticated with a short-lived client assertion, using the organization key for single-tenant login and the EPJ vendor key for multi-tenant login. HelseID returns a `request_uri`, and the browser is redirected to the authorization endpoint with that reference. Authorization code redemption remains handled by the existing WebEPJ flow.

## DPoP Session Service calls

The Session Service calls use DPoP with the `e-helse:sfm.api/sfm.api2` scope. The demo uses one dedicated DPoP private JWK, configured as `Authentication:DPoPKey`, and keeps it separate from the HelseID client assertion keys.

The DPoP proof is generated for each request with the actual HTTP method and URL and includes the access-token hash (`ath`). Requests use `Authorization: DPoP <access-token>` and the `DPoP` header. The Session Service paths use the `/api/v2` API.


 


