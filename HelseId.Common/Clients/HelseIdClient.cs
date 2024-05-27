using HelseId.Common.Browser;
using HelseId.Common.Oidc;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using static HelseId.Common.Jwt.JwtGenerator;

namespace HelseId.Common.Clients
{
    public interface IHelseIdClient
    {
        Task<LoginResult> Login(bool isMultiTenant);
        Task<TokenResponse> ClientCredentialsSignIn(bool isMultiTenant);
        Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code, string codeVerifier, bool isMultiTenant);
        Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken, bool isMultiTenant);
        Task<TokenResponse> TokenExchange(string accessToken, bool isMultiTenant);
    }

    public class HelseIdClient : IHelseIdClient
    {
        private readonly HelseIdClientOptions _options;
        private OidcClient oidcClient;

        public HelseIdClient(HelseIdClientOptions options)
        {
            options.Check();

            _options = options;
            if (_options.Browser == null)
            {
                _options.Browser = new SystemBrowser(_options.RedirectUri);
            }
            oidcClient = new OidcClient(_options);

        }

        public void SetClientId(string clientId)
        {
            if (oidcClient?.Options != null)
            {
                oidcClient.Options.ClientId = clientId;
            }
        }

        public async Task<LoginResult> Login(bool isMultiTenant)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var result = await oidcClient.LoginAsync(new LoginRequest()
            {
                BackChannelExtraParameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                FrontChannelExtraParameters = GetFrontChannelExtraParameters()
            });

            return result;
        }

        public async Task<TokenResponse> ClientCredentialsSignIn(bool isMultiTenant)
        {

            // TODO: Rewrite for new IdentityModel, use extension methods on HttpClient
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco, isMultiTenant);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestClientCredentialsAsync(_options.Scope, extraParams);

            return result;
        }

        private object GetBackChannelExtraParameters(DiscoveryResponse disco, bool isMultiTenant,
            string token = null)
        {
            Oidc.ClientAssertion assertion = null;
            if (_options.SigningMethod == SigningMethod.RsaSecurityKey)
            {
                assertion = Oidc.ClientAssertion.CreateWithRsaKeys(_options.ClientId, disco.TokenEndpoint, isMultiTenant);
            }
            if (_options.SigningMethod == SigningMethod.X509EnterpriseSecurityKey)
            {
                assertion = Oidc.ClientAssertion.CreateWithEnterpriseCertificate(_options.ClientId, disco.TokenEndpoint, _options.CertificateThumbprint);
            }

            var payload = new
            {
                token,
                assertion?.client_assertion,
                assertion?.client_assertion_type,
            };
            return payload;
        }

        public async Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code, string codeVerifier,
            bool isMultiTenant)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco, isMultiTenant);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestAuthorizationCodeAsync(code, _options.RedirectUri, codeVerifier, extraParams);

            return result;
        }

        public async Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken, bool isMultiTenant)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco, isMultiTenant);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestRefreshTokenAsync(refreshToken, extraParams);

            return result;
        }

        private object GetFrontChannelExtraParameters()
        {
            var preselectIdp = _options.PreselectIdp;

            if (string.IsNullOrEmpty(preselectIdp))
                return null;

            return new { acr_values = preselectIdp, prompt = "Login" };
        }

        public async Task<TokenResponse> TokenExchange(string accessToken, bool isMultiTenant)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new ArgumentNullException("AccessToken");
            }

            var disco = await DiscoveryClient.GetAsync(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);
            var client = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);

            var payload = GetBackChannelExtraParameters(disco, isMultiTenant, accessToken);

            // send custom grant to token endpoint, return response
            var response = await client.RequestCustomGrantAsync("token_exchange", _options.Scope, payload);

            return response;
        }
    }
}
