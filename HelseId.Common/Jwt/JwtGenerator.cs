using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using HelseId.Common.Extensions;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace HelseId.Common.Jwt
{
    public class JwtGenerator
    {
        public enum SigningMethod
        {
            None, X509SecurityKey, RsaSecurityKey, X509EnterpriseSecurityKey
        }

        private const double DefaultExpiryInHours = 10;

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

            if (signingMethod == SigningMethod.X509EnterpriseSecurityKey)
                UpdateJwtHeader(securityKey, jwt);


            var tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(jwt);
        }

        public static void UpdateJwtHeader(SecurityKey key, JwtSecurityToken token)
        {
            if (key is X509SecurityKey x509Key)
            {
                var thumbprint = Base64Url.Encode(x509Key.Certificate.GetCertHash());
                var x5C = GenerateX5C(x509Key.Certificate);
                var pubKey = x509Key.PublicKey as RSA;
                var parameters = pubKey.ExportParameters(false);
                var exponent = Base64Url.Encode(parameters.Exponent);
                var modulus = Base64Url.Encode(parameters.Modulus);

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
                var exponent = Base64Url.Encode(parameters.Exponent);
                var modulus = Base64Url.Encode(parameters.Modulus);

                token.Header.Add("kty", "RSA");
                token.Header.Add("use", "sig");
                token.Header.Add("e", exponent);
                token.Header.Add("n", modulus);
            }
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

            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Subject, clientId),
                new Claim(JwtClaimTypes.IssuedAt, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
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
                expiryDate = DateTime.UtcNow.AddHours(DefaultExpiryInHours);

            var token = new JwtSecurityToken(clientId, audience, claims, DateTime.Now, expiryDate, signingCredentials);

            return token;
        }
    }
}
