using System;

namespace HelseId.Common.Certificates
{
    public class UnknownCertificateThumbprintException : Exception
    {
        public UnknownCertificateThumbprintException(string message) : base(message)
        {
        }
    }
}
