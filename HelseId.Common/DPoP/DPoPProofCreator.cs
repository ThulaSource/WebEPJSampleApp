using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Duende.IdentityModel;
using Microsoft.IdentityModel.Tokens;

namespace HelseId.Common.DPoP;

public interface IDPoPProofCreator
{
    string CreateProof(string url, string httpMethod, string nonce = null, string accessToken = null);
}

public sealed class DPoPProofCreator : IDPoPProofCreator
{
    private readonly JsonWebKey securityKey;
    private readonly SigningCredentials signingCredentials;

    public DPoPProofCreator(string privateJwk)
    {
        if (string.IsNullOrWhiteSpace(privateJwk))
        {
            throw new ArgumentException("A private DPoP JWK is required.", nameof(privateJwk));
        }

        securityKey = new JsonWebKey(privateJwk);
        var algorithm = securityKey.Kty switch
        {
            JsonWebAlgorithmsKeyTypes.RSA => SecurityAlgorithms.RsaSsaPssSha256,
            JsonWebAlgorithmsKeyTypes.EllipticCurve => SecurityAlgorithms.EcdsaSha256,
            _ => throw new InvalidOperationException("The DPoP key must be RSA or elliptic curve.")
        };
        signingCredentials = new SigningCredentials(securityKey, algorithm);
    }

    public string CreateProof(string url, string httpMethod, string nonce = null, string accessToken = null)
    {
        var publicJwk = securityKey.Kty switch
        {
            JsonWebAlgorithmsKeyTypes.RSA => new Dictionary<string, string>
            {
                [JsonWebKeyParameterNames.Kty] = securityKey.Kty,
                [JsonWebKeyParameterNames.N] = securityKey.N,
                [JsonWebKeyParameterNames.E] = securityKey.E
            },
            JsonWebAlgorithmsKeyTypes.EllipticCurve => new Dictionary<string, string>
            {
                [JsonWebKeyParameterNames.Kty] = securityKey.Kty,
                [JsonWebKeyParameterNames.X] = securityKey.X,
                [JsonWebKeyParameterNames.Y] = securityKey.Y,
                [JsonWebKeyParameterNames.Crv] = securityKey.Crv
            },
            _ => throw new InvalidOperationException("The DPoP key must be RSA or elliptic curve.")
        };

        var header = new JwtHeader(signingCredentials)
        {
            [JwtClaimTypes.TokenType] = "dpop+jwt",
            [JwtClaimTypes.JsonWebKey] = publicJwk
        };
        var payload = new JwtPayload
        {
            [JwtClaimTypes.JwtId] = Guid.NewGuid().ToString("N"),
            [JwtClaimTypes.DPoPHttpMethod] = httpMethod,
            [JwtClaimTypes.DPoPHttpUrl] = url,
            [JwtClaimTypes.IssuedAt] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };

        if (!string.IsNullOrWhiteSpace(nonce))
        {
            payload[JwtClaimTypes.Nonce] = nonce;
        }

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
            payload[JwtClaimTypes.DPoPAccessTokenHash] = Base64UrlEncoder.Encode(hash);
        }

        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }
}
