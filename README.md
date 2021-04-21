# WebEPJ Sample App

This application samples the integration between an ASP.Net Core MVC application (WebEpj) and the SFM Angular client application.

Sampled functionalities:

- OpenId Authentication using HelseId.
- Creating a new SFM Session (see HomeController.Index())
- Renewing a SFM Session token to keep the session alive (see HomeController.RefreshTokenAsync() and OnValidatePrincipal CookieAuthenticationEvents event)
- Request a patient ticket from SFM (see HomeController.LoadTicketAsync)
- Start, login and load a patient using SFM client (see javascript functions under Index.cshtml)

What needsrto be configured:
- appSettings:Authentication -> HelseId related settings
- appSettings:SfmSessionGatewayEndpoint -> The SFM session gateway endpoint
- HelseIdClientRsaPrivateKey.pem file -> This is the HelseId Client private key
 