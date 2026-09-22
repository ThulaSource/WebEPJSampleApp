using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using HelseId.Common.DPoP;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using WebEpj.DPoP;
using WebEpj.Models;

namespace WebEpj.Session;

public sealed class SessionGatewayClient : ISessionGatewayClient
{
    private readonly ApplicationOptions applicationOptions;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly IDPoPProofProvider dPoPProofProvider;

    public SessionGatewayClient(
        IOptions<ApplicationOptions> applicationOptions,
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        IDPoPProofProvider dPoPProofProvider)
    {
        this.applicationOptions = applicationOptions.Value;
        this.httpClientFactory = httpClientFactory;
        this.httpContextAccessor = httpContextAccessor;
        this.dPoPProofProvider = dPoPProofProvider;
    }

    public async Task<SessionResult> CreateSessionAsync(string nonceHash)
    {
        var content = JsonContent(new { nonce = nonceHash });
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.CreateSession, content);
        response.EnsureSuccessStatusCode();
        return JsonConvert.DeserializeObject<SessionResult>(await response.Content.ReadAsStringAsync());
    }

    public async Task<string> CreatePatientTicketAsync(string patientIdentifier)
    {
        var content = JsonContent(new { patientPid = patientIdentifier });
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.CreatePatientTicket, content);
        response.EnsureSuccessStatusCode();
        return JsonConvert.DeserializeObject<string>(await response.Content.ReadAsStringAsync());
    }

    public async Task RefreshSessionAsync()
    {
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.RefreshSession);
        response.EnsureSuccessStatusCode();
    }

    public async Task EndSessionAsync()
    {
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.EndSession);
        response.EnsureSuccessStatusCode();
    }

    private async Task<HttpResponseMessage> SendDpopAsync(HttpMethod method, string path, HttpContent content = null)
    {
        var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");
        var baseUri = applicationOptions.SfmSessionGatewayEndpoint.TrimEnd('/') + "/";
        var requestUri = new Uri(new Uri(baseUri), path.TrimStart('/'));
        using var request = new HttpRequestMessage(method, requestUri) { Content = content };

        var proof = dPoPProofProvider.GetProofCreator()
            .CreateProof(requestUri.ToString(), method.Method, accessToken: accessToken);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            OidcConstants.AuthenticationSchemes.AuthorizationHeaderDPoP, accessToken);
        request.Headers.Add(OidcConstants.HttpHeaders.DPoP, proof);

        return await httpClientFactory.CreateClient().SendAsync(request);
    }

    private static StringContent JsonContent(object value)
    {
        return new StringContent(JsonConvert.SerializeObject(value), Encoding.UTF8, "application/json");
    }
}
