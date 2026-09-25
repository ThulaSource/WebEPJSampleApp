using System.Net.Http;
using System.Threading.Tasks;
using Duende.IdentityModel.Client;

namespace HelseId.Common.Oidc
{
    public class OidcDiscoveryHelper
    {
        public static async Task<DiscoveryDocumentResponse> GetDiscoveryDocument(string authority, HttpClient httpClient)
        {
            return await httpClient.GetDiscoveryDocumentAsync(authority);
        }
    }
}
