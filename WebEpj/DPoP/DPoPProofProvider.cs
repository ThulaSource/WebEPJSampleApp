using System;
using HelseId.Common.DPoP;
using HelseId.Common.Oidc;

namespace WebEpj.DPoP;

public sealed class DPoPProofProvider : IDPoPProofCreator
{
    private readonly DPoPProofCreator proofCreator;

    public DPoPProofProvider()
    {
        proofCreator = new DPoPProofCreator(ClientAssertion.LoadWebEpjVendorPrivateKeyJson());
    }

    public string CreateProof(string url, string httpMethod, string nonce = null, string accessToken = null)
    {
        return proofCreator.CreateProof(url, httpMethod, nonce, accessToken);
    }
}
