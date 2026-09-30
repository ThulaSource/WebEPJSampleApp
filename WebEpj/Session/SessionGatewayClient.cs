using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel;
using HelseId.Common.DPoP;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using WebEpj.Models;

namespace WebEpj.Session;

public sealed class SessionGatewayClient : ISessionGatewayClient
{
    private readonly ApplicationOptions applicationOptions;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly IDPoPProofCreator dPoPProofCreator;

    public SessionGatewayClient(
        IOptions<ApplicationOptions> applicationOptions,
        IHttpClientFactory httpClientFactory,
        IHttpContextAccessor httpContextAccessor,
        IDPoPProofCreator dPoPProofCreator)
    {
        this.applicationOptions = applicationOptions.Value;
        this.httpClientFactory = httpClientFactory;
        this.httpContextAccessor = httpContextAccessor;
        this.dPoPProofCreator = dPoPProofCreator;
    }

    public async Task<SessionResult> CreateSessionAsync(string nonceHash, CancellationToken cancellationToken = default)
    {
        var content = JsonContent(new { nonce = nonceHash });
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.CreateSession, content, cancellationToken);
        await EnsureSuccessAsync(response, SessionGatewayEndpoints.CreateSession, cancellationToken);
        return JsonConvert.DeserializeObject<SessionResult>(await response.Content.ReadAsStringAsync(cancellationToken));
    }

    public async Task<string> CreatePatientTicketAsync(string patientIdentifier, CancellationToken cancellationToken = default)
    {
        var content = JsonContent(new { patientPid = patientIdentifier });
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.CreatePatientTicket, content, cancellationToken);
        await EnsureSuccessAsync(response, SessionGatewayEndpoints.CreatePatientTicket, cancellationToken);
        return JsonConvert.DeserializeObject<string>(await response.Content.ReadAsStringAsync(cancellationToken));
    }

    public async Task RefreshSessionAsync(CancellationToken cancellationToken = default)
    {
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.RefreshSession, cancellationToken: cancellationToken);
        await EnsureSuccessAsync(response, SessionGatewayEndpoints.RefreshSession, cancellationToken);
    }

    public async Task EndSessionAsync(CancellationToken cancellationToken = default)
    {
        using var response = await SendDpopAsync(HttpMethod.Post, SessionGatewayEndpoints.EndSession, cancellationToken: cancellationToken);
        await EnsureSuccessAsync(response, SessionGatewayEndpoints.EndSession, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendDpopAsync(HttpMethod method, string path, HttpContent content = null, CancellationToken cancellationToken = default)
    {
        var httpContext = httpContextAccessor.HttpContext ?? throw new InvalidOperationException("No active HTTP context is available.");
        var accessToken = await httpContext.GetTokenAsync("access_token");
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new InvalidOperationException("No access token is available for the Session Gateway request.");
        }
        var baseUri = applicationOptions.SfmSessionGatewayEndpoint.TrimEnd('/') + "/";
        var requestUri = new Uri(new Uri(baseUri), path.TrimStart('/'));
        using var request = new HttpRequestMessage(method, requestUri) { Content = content };

        var proof = dPoPProofCreator.CreateProof(requestUri.ToString(), method.Method, accessToken: accessToken);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            OidcConstants.AuthenticationSchemes.AuthorizationHeaderDPoP, accessToken);
        request.Headers.Add(OidcConstants.HttpHeaders.DPoP, proof);

        return await httpClientFactory.CreateClient().SendAsync(request, cancellationToken);
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, string endpoint, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new HttpRequestException($"Session Gateway request to '{endpoint}' failed with {(int)response.StatusCode} ({response.ReasonPhrase}). Response: {body}");
    }

    private static StringContent JsonContent(object value)
    {
        return new StringContent(JsonConvert.SerializeObject(value), Encoding.UTF8, "application/json");
    }
}
