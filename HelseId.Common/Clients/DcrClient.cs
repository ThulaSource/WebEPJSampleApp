using HelseId.Models.DCR.Api;
using HelseId.Models.DCR.Client;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace HelseId.Common.Clients
{
    public class DcrClient
    {
        private HttpClient _client;

        public DcrClient(string uri, string accessToken = "")
        {
            _client = new HttpClient
            {
                BaseAddress = new Uri(uri)
            };
            if(!string.IsNullOrEmpty(accessToken))
                _client.SetBearerToken(accessToken);
        }

        public void SetBearerToken(string accessToken)
        {
            _client.SetBearerToken(accessToken);
        }

        public async Task<ClientResponse> GetClient(string id)
        {
            var response = await _client.GetAsync("api/connect/client/register?id="+ id);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var client = JsonConvert.DeserializeObject<ClientResponse>(responseAsJson);

            return client;
        }

        public async Task<ClientResponse> StoreClient(ClientRequest request)
        {
            var requestAsJson = JsonConvert.SerializeObject(request);
            var content = new StringContent(requestAsJson, Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("api/connect/client/register", content);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var client = JsonConvert.DeserializeObject<ClientResponse>(responseAsJson);

            return client;
        }

        public async Task<ClientResponse> UpdateClient(ClientRequest request)
        {
            var requestAsJson = JsonConvert.SerializeObject(request);
            var content = new StringContent(requestAsJson, Encoding.UTF8, "application/json");
            var response = await _client.PutAsync("api/connect/client/register", content);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var client = JsonConvert.DeserializeObject<ClientResponse>(responseAsJson);

            return client;
        }


        public async Task<ApiResourceResponse> GetApi(string id)
        {
            var response = await _client.GetAsync("api/connect/apiResource/register?id="+ id);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var api = JsonConvert.DeserializeObject<ApiResourceResponse>(responseAsJson);

            return api;
        }

        public async Task<ApiResourceResponse> StoreApi(ApiResourceRequest request)
        {
            var requestAsJson = JsonConvert.SerializeObject(request);
            var content = new StringContent(requestAsJson, Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("api/connect/apiResource/register", content);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var api = JsonConvert.DeserializeObject<ApiResourceResponse>(responseAsJson);

            return api;
        }

        public async Task<ApiResourceResponse> UpdateApi(ApiResourceRequest request)
        {
            var requestAsJson = JsonConvert.SerializeObject(request);
            var content = new StringContent(requestAsJson, Encoding.UTF8, "application/json");
            var response = await _client.PutAsync("api/connect/apiResource/register", content);

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var api = JsonConvert.DeserializeObject<ApiResourceResponse>(responseAsJson);

            return api;
        }
    }
}
