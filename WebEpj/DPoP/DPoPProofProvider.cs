using System;
using HelseId.Common.DPoP;
using Microsoft.Extensions.Options;

namespace WebEpj.DPoP;

public interface IDPoPProofProvider
{
    IDPoPProofCreator GetProofCreator();
}

public sealed class DPoPProofProvider : IDPoPProofProvider
{
    private readonly IDPoPProofCreator proofCreator;

    public DPoPProofProvider(IOptions<AuthenticationOptions> options)
    {
        if (string.IsNullOrWhiteSpace(options.Value.DPoPKey))
        {
            throw new InvalidOperationException("A DPoP key must be configured.");
        }

        proofCreator = new DPoPProofCreator(options.Value.DPoPKey);
    }

    public IDPoPProofCreator GetProofCreator()
    {
        return proofCreator;
    }
}
