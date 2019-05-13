using System;
using System.Security.Cryptography.X509Certificates;
using HelseId.Common.Extensions;

namespace HelseId.Common.Certificates
{
    public class CertificateStore
    {
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName store = StoreName.My, StoreLocation location = StoreLocation.CurrentUser)
        {
            if (thumbprint.IsNullOrEmpty())
                throw new ArgumentOutOfRangeException(nameof(thumbprint));

            using (var x509Store = new X509Store(store, location))
            {
                x509Store.Open(OpenFlags.ReadOnly);

                var certificatesInStore = x509Store.Certificates;
                var certificates = certificatesInStore.Find(X509FindType.FindByThumbprint, thumbprint, false);

                if (certificates.Count < 1)
                    throw new UnknownCertificateThumbprintException($"Did not find any Certificates with the thumbprint: {thumbprint}");

                if (certificates.Count > 1)
                    throw new Exception($"Found {certificates.Count} certificates with thumbprint: {thumbprint}");

                var certificate = certificates[0];

                return certificate;
            }
        }
    }
}
