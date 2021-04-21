using System;
using System.Security.Cryptography;

namespace WebEpj
{
    /// <summary>
    /// Helper class to generate nonce
    /// </summary>
    public static class NonceHelper
    {
        public static (string nonceBase64, string nonceHashBase64) CreateNonce()
        {
            // Generates a random number (nonce) 
            // We return two versions of this number: 
            // - The hashed version is used in the first call where we create the session. 
            //   The server stores this value for later verification.
            // - The full version is passed by the browser when logging on.
            //   The server calculates the hash of this and uses that as a proof that the front-end and
            //   back end calls are from the same application.
            var nonce = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(nonce);
            var nonceBase64 = Convert.ToBase64String(nonce);
            var hashAlg = SHA512.Create();
            var nonceHashBase64 = Convert.ToBase64String(hashAlg.ComputeHash(nonce));
            return (nonceBase64, nonceHashBase64);
        }
    }
}