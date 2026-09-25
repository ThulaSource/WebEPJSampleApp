using System;
using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;
using Duende.IdentityModel.OidcClient;
using HelseId.Common.Browser;
using HelseId.Common.DPoP;
using HelseId.Common.Oidc;
using static HelseId.Common.Jwt.JwtGenerator;

namespace HelseId.Common.Clients
{
    public interface IHelseIdClient
    {
        Task<LoginResult> Login(bool isMultiTenant);
        Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code, string codeVerifier, bool isMultiTenant);
        Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken, bool isMultiTenant);
    }

    public class HelseIdClient : IHelseIdClient
    {
        private readonly HelseIdClientOptions _options;
        private OidcClient oidcClient;
        private readonly IDPoPProofCreator dPoPProofCreator;
        private readonly IHttpClientFactory httpClientFactory;

        public HelseIdClient(HelseIdClientOptions options, IDPoPProofCreator dPoPProofCreator, IHttpClientFactory httpClientFactory)
        {
            options.Check();

            _options = options;
            this.dPoPProofCreator = dPoPProofCreator;
            this.httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
            if (_options.Browser == null)
            {
                _options.Browser = new SystemBrowser(_options.RedirectUri);
            }
            oidcClient = new OidcClient(_options);

        }

        public async Task<LoginResult> Login(bool isMultiTenant)
        {
            using var httpClient = httpClientFactory.CreateClient();
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority, httpClient);
            if (disco.IsError) throw new Exception(disco.Error);

            var result = await oidcClient.LoginAsync(new LoginRequest()
            {
                BackChannelExtraParameters = GetBackChannelExtraParameters(disco, isMultiTenant),
                FrontChannelExtraParameters = GetFrontChannelExtraParameters()
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
            using var httpClient = httpClientFactory.CreateClient();
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority, httpClient);
            if (disco.IsError) throw new Exception(disco.Error);

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
            using var httpClient = httpClientFactory.CreateClient();
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority, httpClient);
            if (disco.IsError) throw new Exception(disco.Error);

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

    }
}
