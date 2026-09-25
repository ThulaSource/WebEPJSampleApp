using System;
using HelseId.Common.DPoP;
using Microsoft.Extensions.Options;

namespace WebEpj.DPoP;

public sealed class DPoPProofProvider : IDPoPProofCreator
{
    private readonly DPoPProofCreator proofCreator;

    public DPoPProofProvider(IOptions<AuthenticationOptions> options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Value.DPoPKey);

        proofCreator = new DPoPProofCreator(options.Value.DPoPKey);
    }

    public string CreateProof(string url, string httpMethod, string nonce = null, string accessToken = null)
    {
        return proofCreator.CreateProof(url, httpMethod, nonce, accessToken);
    }
}
