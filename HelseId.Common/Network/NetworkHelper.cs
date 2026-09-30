using System;
using System.Net;
using System.Net.Http;
using System.Threading;

namespace HelseId.Common.Network
{
    public class NetworkHelper
    {
        private static readonly HttpClient HttpClient = new(new HttpClientHandler
        {
            AllowAutoRedirect = true
        });

        public static bool StsIsAvailable(string url)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(120));
                using var response = HttpClient.Send(request, timeout.Token);
                return response.StatusCode == HttpStatusCode.OK;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
