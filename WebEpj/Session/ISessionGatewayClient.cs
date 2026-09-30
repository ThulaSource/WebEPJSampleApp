using System.Threading;
using System.Threading.Tasks;
using WebEpj.Models;

namespace WebEpj.Session;

public interface ISessionGatewayClient
{
    Task<SessionResult> CreateSessionAsync(string nonceHash, CancellationToken cancellationToken = default);
    Task<string> CreatePatientTicketAsync(string patientIdentifier, CancellationToken cancellationToken = default);
    Task RefreshSessionAsync(CancellationToken cancellationToken = default);
    Task EndSessionAsync(CancellationToken cancellationToken = default);
}
