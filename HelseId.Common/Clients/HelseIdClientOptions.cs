using HelseId.Common.Crypto;
using IdentityModel.OidcClient;
using System;
using static HelseId.Common.Jwt.JwtGenerator;

namespace HelseId.Common.Clients
{
    public class HelseIdClientOptions : OidcClientOptions
    {
        /// <summary>
        /// The thumbprint of the certificate to use for client assertion.
        /// </summary>
        /// <value>
        /// The certificate thumbprint.
        /// </value>
        public string CertificateThumbprint { get; set; }

        /// <summary>
        /// The SigningMethod to use for client assertion
        /// </summary>
        /// <value>
        /// The signing method.
        /// </value>
        public SigningMethod SigningMethod { get; set; }

        /// <summary>
        /// Specify which identity provider to use
        /// </summary>
        /// <value>
        /// The identity provider.
        /// </value>
        public string PreselectIdp { get; set; }

        public bool Check(bool throwException = true) {
            try
            {
                if (string.IsNullOrEmpty(Authority))
                {
                    throw new ArgumentNullException("Authority");
                }
                if (string.IsNullOrEmpty(ClientId))
                {
                    throw new ArgumentNullException("ClientId");
                }
                if(SigningMethod == SigningMethod.None && string.IsNullOrEmpty(ClientSecret))
                {
                    throw new ArgumentNullException("ClientSecret");
                }
                if (SigningMethod == SigningMethod.X509EnterpriseSecurityKey && string.IsNullOrEmpty(CertificateThumbprint))
                {
                    throw new ArgumentNullException("CertificateThumprint");
                }

                if (string.IsNullOrEmpty(RedirectUri))
                {
                    throw new ArgumentNullException("RedirectUri");
                }
                // Not true if all we want to do is call for a refresh token..
                //if (string.IsNullOrEmpty(Scope))
                //{
                //    throw new ArgumentNullException("Scope");
                //}
                //if (!Scope.Contains("openid"))
                //{
                //    throw new ArgumentException("Scope must include openid", nameof(Scope));
                //}
            }
            catch
            {
                if (throwException)
                    throw;
                return false;
            }
            return true;
        }
    }
}
