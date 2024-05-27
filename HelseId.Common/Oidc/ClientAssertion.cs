using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using HelseId.Common.Certificates;
using HelseId.Common.Crypto;
using HelseId.Common.Jwt;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace HelseId.Common.Oidc
{
    public class ClientAssertion
    {
        public static ClientAssertion CreateWithRsaKeys(string clientId, string tokenEndpointUrl, bool isMultiTenant)
        {
            RsaSecurityKey securityKey;
            if (isMultiTenant == false)
            {
                var assembly = Assembly.GetEntryAssembly();
                var key = assembly.GetManifestResourceStream("WebEpj.HelseIdClientRsaPrivateKey.pem");

                var rsa = RSAKeyGenerator.GetRsaParameters(key);
                securityKey = new RsaSecurityKey(rsa);
            }
            else
            {
                securityKey = LoadWebEpjVendorPrivateKey();
            }

            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl, JwtGenerator.SigningMethod.RsaSecurityKey, securityKey, SecurityAlgorithms.RsaSha512);

            return new ClientAssertion{ client_assertion = assertion };
        }

        public static ClientAssertion CreateWithEnterpriseCertificate(string clientId, string tokenEndpointUrl, string thumbprint)
        {
            var certificate = CertificateStore.GetCertificateByThumbprint(thumbprint);
            var securityKey = new X509SecurityKey(certificate);
            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl, JwtGenerator.SigningMethod.X509EnterpriseSecurityKey, securityKey, SecurityAlgorithms.RsaSha512);

            return new ClientAssertion { client_assertion = assertion };
        }

        [JsonProperty("client_assertion")]
        public string client_assertion { get; set; }

        [JsonProperty("client_assertion_type")]
        public string client_assertion_type { get; set; } = IdentityModel.OidcConstants.ClientAssertionTypes.JwtBearer;
        
        public static RsaSecurityKey LoadWebEpjVendorPrivateKey()
        {
            var assembly = Assembly.GetEntryAssembly();
            var resourceName = "WebEpj.HelseIdClientEpjVenderPrivateKey.json";

            string jsonFile;
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            using (var reader = new StreamReader(stream))
            {
                jsonFile = reader.ReadToEnd();
            }
           
            var jsonWebKey = JsonWebKey.Create(jsonFile);

            var rsaParameters = new RSAParameters {
                // PUBLIC KEY PARAMETERS
                // n parameter - public modulus
                Modulus = Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                // e parameter - public exponent
                Exponent = Base64UrlEncoder.DecodeBytes(jsonWebKey.E),

                // PRIVATE KEY PARAMETERS (optional)
                // d parameter - the private exponent value for the RSA key 
                D = Base64UrlEncoder.DecodeBytes(jsonWebKey.D),
                // dp parameter - CRT exponent of the first factor
                DP = Base64UrlEncoder.DecodeBytes(jsonWebKey.DP),
                // dq parameter - CRT exponent of the second factor
                DQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.DQ),
                // p parameter - first prime factor
                P = Base64UrlEncoder.DecodeBytes(jsonWebKey.P),
                // q parameter - second prime factor
                Q = Base64UrlEncoder.DecodeBytes(jsonWebKey.Q),
                // qi parameter - CRT coefficient of the second factor
                InverseQ = Base64UrlEncoder.DecodeBytes(jsonWebKey.QI)
            };
            return new RsaSecurityKey(rsaParameters);
        }
    }
}
