using System.Threading.Tasks;
using WebEpj.Models;

namespace WebEpj.Session;

public interface ISessionGatewayClient
{
    Task<SessionResult> CreateSessionAsync(string nonceHash);
    Task<string> CreatePatientTicketAsync(string patientIdentifier);
    Task RefreshSessionAsync();
    Task EndSessionAsync();
}
