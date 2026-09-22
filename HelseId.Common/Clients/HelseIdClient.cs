using HelseId.Common.Browser;
using HelseId.Common.Oidc;
using HelseId.Common.DPoP;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using System;
using System.Net.Http;
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
        private readonly IDPoPProofCreator dPoPProofCreator;

        public HelseIdClient(HelseIdClientOptions options, IDPoPProofCreator dPoPProofCreator = null)
        {
            options.Check();

            _options = options;
            this.dPoPProofCreator = dPoPProofCreator;
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

            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            using var httpClient = new HttpClient();
            var result = await httpClient.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                Scope = _options.Scope,
                Parameters = GetBackChannelExtraParameters(disco, isMultiTenant)
            });

            return result;
        }

        private Parameters GetBackChannelExtraParameters(DiscoveryDocumentResponse disco, bool isMultiTenant,
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

            var parameters = new Parameters();
            if (!string.IsNullOrEmpty(token))
            {
                parameters.Add("token", token);
            }
            if (assertion != null)
            {
                parameters.Add("client_assertion", assertion.client_assertion);
                parameters.Add("client_assertion_type", assertion.client_assertion_type);
            }
            return parameters;
        }

        public async Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code, string codeVerifier,
            bool isMultiTenant)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            using var httpClient = new HttpClient();
            var result = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                Code = code,
                RedirectUri = _options.RedirectUri,
                CodeVerifier = codeVerifier,
                Parameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                DPoPProofToken = CreateTokenEndpointProof(disco.TokenEndpoint)
            });

            if (IsDpopNonceError(result) && !string.IsNullOrWhiteSpace(result.DPoPNonce))
            {
                result = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
                {
                    Address = disco.TokenEndpoint,
                    ClientId = _options.ClientId,
                    ClientSecret = _options.ClientSecret,
                    Code = code,
                    RedirectUri = _options.RedirectUri,
                    CodeVerifier = codeVerifier,
                    Parameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                    DPoPProofToken = CreateTokenEndpointProof(disco.TokenEndpoint, result.DPoPNonce)
                });
            }

            return result;
        }

        public async Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken, bool isMultiTenant)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            using var httpClient = new HttpClient();
            var result = await httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                RefreshToken = refreshToken,
                Parameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                DPoPProofToken = CreateTokenEndpointProof(disco.TokenEndpoint)
            });

            if (IsDpopNonceError(result) && !string.IsNullOrWhiteSpace(result.DPoPNonce))
            {
                result = await httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest
                {
                    Address = disco.TokenEndpoint,
                    ClientId = _options.ClientId,
                    ClientSecret = _options.ClientSecret,
                    RefreshToken = refreshToken,
                    Parameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                    DPoPProofToken = CreateTokenEndpointProof(disco.TokenEndpoint, result.DPoPNonce)
                });
            }

            return result;
        }

        private string CreateTokenEndpointProof(string tokenEndpoint, string nonce = null)
        {
            return dPoPProofCreator?.CreateProof(tokenEndpoint, "POST", nonce);
        }

        private static bool IsDpopNonceError(TokenResponse response)
        {
            return response?.Error == "use_dpop_nonce";
        }

        private Parameters GetFrontChannelExtraParameters()
        {
            var preselectIdp = _options.PreselectIdp;

            if (string.IsNullOrEmpty(preselectIdp))
                return null;

            return new Parameters
            {
                { "acr_values", preselectIdp },
                { "prompt", "Login" }
            };
        }

        public async Task<TokenResponse> TokenExchange(string accessToken, bool isMultiTenant)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                throw new ArgumentNullException("AccessToken");
            }

            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var payload = GetBackChannelExtraParameters(disco, isMultiTenant, accessToken);
            payload.Add("scope", _options.Scope);

            // send custom grant to token endpoint, return response
            using var httpClient = new HttpClient();
            var response = await httpClient.RequestTokenAsync(new TokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                GrantType = "token_exchange",
                Parameters = payload
            });

            return response;
        }
    }
}
