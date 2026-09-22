using Duende.IdentityModel.Client;
using System.Net.Http;
using System.Threading.Tasks;

namespace HelseId.Common.Oidc
{
    public class OidcDiscoveryHelper
    {
        public static async Task<DiscoveryDocumentResponse> GetDiscoveryDocument(string authority)
        {
            using var httpClient = new HttpClient();
            return await httpClient.GetDiscoveryDocumentAsync(authority);
        }
    }
}
