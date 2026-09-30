using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Duende.IdentityModel;
using HelseId.Common.Extensions;
using HelseId.Common.RequestObjects;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace HelseId.Common.Jwt
{
    public class JwtGenerator
    {
        public enum SigningMethod
        {
            None, X509SecurityKey, RsaSecurityKey, X509EnterpriseSecurityKey
        }

        private const double DefaultClientAssertionExpiryInSeconds = 10;

        public static string Generate(string clientId,
                                    string audience,
                                    Dictionary<string, string> extraClaims,
                                    TimeSpan jwtLifetime,
                                    SigningMethod signingMethod,
                                    X509SecurityKey securityKey,
                                    string securityAlgorithm)
        {
            if (clientId.IsNullOrEmpty())
                throw new ArgumentException("clientId can not be empty or null");

            if (audience.IsNullOrEmpty())
                throw new ArgumentException("The audience address can not be empty or null");

            if (securityKey == null)
                throw new ArgumentException("The security key can not be null");

            if (securityAlgorithm.IsNullOrEmpty())
                throw new ArgumentException("The security algorithm can not be empty or null");

            var expiryDate = DateTime.Now.Add(jwtLifetime);
            return GenerateJwt(clientId, audience, expiryDate, signingMethod, securityKey, securityAlgorithm, extraClaims);


        }

        /// <summary>
        /// Generates a new JWT
        /// </summary>
        /// <param name="clientId">The OAuth/OIDC client ID</param>
        /// <param name="tokenEndpoint">The provider token endpoint</param>
        /// <param name="signingMethod">Indicate which method to use when signing the Jwt Token</param>
        /// <param name="securityKey">The token security key</param>
        /// <param name="securityAlgorithm">The security algorithm</param>
        /// <param name="extraClaims">Additional claims to add to the jwt</param>
        public static string Generate(string clientId,
                            string tokenEndpoint,
                            SigningMethod signingMethod,
                            SecurityKey securityKey,
                            string securityAlgorithm)
        {
            if (clientId.IsNullOrEmpty())
                throw new ArgumentException("clientId can not be empty or null");

            if (tokenEndpoint.IsNullOrEmpty())
                throw new ArgumentException("The token endpoint address can not be empty or null");

            if (securityKey == null)
                throw new ArgumentException("The security key can not be null");

            if (securityAlgorithm.IsNullOrEmpty())
                throw new ArgumentException("The security algorithm can not be empty or null");

            return GenerateJwt(clientId, tokenEndpoint, null, signingMethod, securityKey, securityAlgorithm);
        }
        
        /// <summary>
        /// Generates a new token adding the supplied request object as payload
        /// </summary>
        /// <param name="clientId">The oidc client identifier</param>
        /// <param name="tokenEndpoint">The oidc token endpoint</param>
        /// <param name="securityKey">The security key to sign the token</param>
        /// <param name="securityAlgorithm">The security algorithm</param>
        /// <param name="clock">The current instance of system clock</param>
        /// <param name="requestObject">The request object</param>
        public static string GenerateWithRequestObject(string clientId,
            string tokenEndpoint,
            SecurityKey securityKey,
            string securityAlgorithm,
            IRequestObject requestObject)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentException("clientId can not be empty or null");

            if (string.IsNullOrEmpty(tokenEndpoint))
                throw new ArgumentException("The token endpoint address can not be empty or null");

            if (securityKey == null)
                throw new ArgumentException("The security key can not be null");

            if (string.IsNullOrEmpty(securityAlgorithm))
                throw new ArgumentException("The security algorithm can not be empty or null");

            return GenerateJwtWithPayload(clientId, tokenEndpoint, securityKey, securityAlgorithm, requestObject);
        }


        /// <summary>
        /// Generates a new JWT
        /// </summary>
        /// <param name="clientId">The OAuth/OIDC client ID</param>
        /// <param name="audience">The Authorization Server (STS)</param>
        /// <param name="expiryDate">If value is null, the default expiry date is used (10 hrs)</param>
        /// <param name="signingMethod">One of <see cref="SigningMethod"/> to sign the jwt</param>
        /// <param name="securityKey">The token security key</param>
        /// <param name="securityAlgorithm">The security algorithm</param>
        /// <param name="extraClaims">Additional claims to add to the jwt</param>
        /// <returns></returns>
        private static string GenerateJwt(string clientId, string audience, DateTime? expiryDate, SigningMethod signingMethod, SecurityKey securityKey, string securityAlgorithm, Dictionary<string, string> extraClaims = null)
        {
            var signingCredentials = new SigningCredentials(securityKey, securityAlgorithm);

            var jwt = CreateJwtSecurityToken(clientId, audience + "", expiryDate, signingCredentials, extraClaims);

            UpdateJwtHeader(securityKey, jwt);


            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(jwt);
        }
        
        private static string GenerateJwtWithPayload(string clientId, string audience, SecurityKey securityKey,
            string securityAlgorithm, IRequestObject requestObject)
        {
            var now = DateTime.UtcNow;
            var signingCredentials = new SigningCredentials(securityKey, securityAlgorithm);

            var requestObjectItems = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(
                JsonConvert.SerializeObject(requestObject.RequestObjectItems));

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = clientId,
                Audience = audience,
                Subject = null,
                NotBefore = now,
                Expires = now.AddSeconds(DefaultClientAssertionExpiryInSeconds),
                SigningCredentials = signingCredentials,
                Claims = new Dictionary<string, object>
                {
                    { OidcConstants.TokenRequest.ClientId, clientId },
                    { JwtClaimTypes.JwtId, Guid.NewGuid().ToString("N") },
                    { requestObject.Key, requestObjectItems }
                }
            };

            UpdateJwtHeader(securityKey, securityTokenDescriptor);

            return new JsonWebTokenHandler().CreateToken(securityTokenDescriptor);
        }

        private static void UpdateJwtHeader(SecurityKey key, SecurityTokenDescriptor descriptor)
        {
            descriptor.AdditionalInnerHeaderClaims ??= new Dictionary<string, object>();

            if (key is X509SecurityKey x509Key)
            {
                var publicKey = x509Key.PublicKey as RSA;
                var parameters = publicKey.ExportParameters(false);
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.Kty] = publicKey.SignatureAlgorithm;
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.Use] = "sig";
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.E] = Base64UrlEncoder.Encode(parameters.Exponent);
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.N] = Base64UrlEncoder.Encode(parameters.Modulus);
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.X5c] = GenerateX5C(x509Key.Certificate);
            }

            if (key is RsaSecurityKey rsaKey)
            {
                var parameters = rsaKey.Rsa?.ExportParameters(false) ?? rsaKey.Parameters;
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.Kty] = "RSA";
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.Use] = "sig";
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.E] = Base64UrlEncoder.Encode(parameters.Exponent);
                descriptor.AdditionalInnerHeaderClaims[JsonWebKeyParameterNames.N] = Base64UrlEncoder.Encode(parameters.Modulus);
            }

            descriptor.AdditionalInnerHeaderClaims[JwtClaimTypes.TokenType] = "client-authentication+jwt";
        }

        public static void UpdateJwtHeader(SecurityKey key, JwtSecurityToken token)
        {
            if (key is X509SecurityKey x509Key)
            {
                var thumbprint = Base64UrlEncoder.Encode(x509Key.Certificate.GetCertHash());
                var x5C = GenerateX5C(x509Key.Certificate);
                var pubKey = x509Key.PublicKey as RSA;
                var parameters = pubKey.ExportParameters(false);
                var exponent = Base64UrlEncoder.Encode(parameters.Exponent);
                var modulus = Base64UrlEncoder.Encode(parameters.Modulus);

                token.Header.Add("x5c", x5C);
                token.Header.Add("kty", pubKey.SignatureAlgorithm);
                token.Header.Add("use", "sig");
                token.Header.Add("x5t", thumbprint);
                token.Header.Add("e", exponent);
                token.Header.Add("n", modulus);
            }

            if (key is RsaSecurityKey rsaKey)
            {
                var parameters = rsaKey.Rsa?.ExportParameters(false) ?? rsaKey.Parameters;
                var exponent = Base64UrlEncoder.Encode(parameters.Exponent);
                var modulus = Base64UrlEncoder.Encode(parameters.Modulus);

                token.Header.Add("kty", "RSA");
                token.Header.Add("use", "sig");
                token.Header.Add("e", exponent);
                token.Header.Add("n", modulus);
            }

            token.Header[JwtClaimTypes.TokenType] = "client-authentication+jwt";
        }

        private static List<string> GenerateX5C(X509Certificate2 certificate)
        {

            var x5C = new List<string>();

            var chain = GetCertificateChain(certificate);
            if (chain != null)
            {
                foreach (var cert in chain.ChainElements)
                {
                    var x509Base64 = Convert.ToBase64String(cert.Certificate.RawData);
                    x5C.Add(x509Base64);
                }
            }
            return x5C;
        }

        private static X509Chain GetCertificateChain(X509Certificate2 cert)
        {
            var certificateChain = X509Chain.Create();
            certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            certificateChain.Build(cert);
            return certificateChain;
        }

        private static JwtSecurityToken CreateJwtSecurityToken(string clientId, string audience, DateTime? expiryDate, SigningCredentials signingCredentials, Dictionary<string, string> extraClaims)
        {
            var now = DateTime.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, clientId),
                new Claim(JwtClaimTypes.IssuedAt, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString("N"))
            };

            if (extraClaims != null && extraClaims.Count > 0)
            {
                foreach (var claim in extraClaims)
                {
                    claims.Add(new Claim(claim.Key, claim.Value));
                }
            }

            if (!expiryDate.HasValue)
                expiryDate = now.AddSeconds(DefaultClientAssertionExpiryInSeconds);

            var token = new JwtSecurityToken(clientId, audience, claims, now, expiryDate, signingCredentials);

            return token;
        }
    }
}
