using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using WebEpj.Models;

namespace WebEpj.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IConfiguration configuration;
        
        public HomeController(IConfiguration configuration, IMemoryCache cache)
        {
            this.configuration = configuration;
        }

        public async Task<IActionResult> Index()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            return View(new HomeModel { SfmClientUrl = await GetSfmClientUrl(accessToken) });
        }

        private string ReadTestFile()
        {
            string res = string.Empty;

            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = "WebEpj.TestStartPasient.xml";

            using (var stream = assembly.GetManifestResourceStream(resourceName))
            using (var reader = new StreamReader(stream))
            {
                res = reader.ReadToEnd();
            }

            return res;
        }

        private async Task<string> GetSfmClientUrl(string accessToken)
        {
            var sfmClientUrl = "";
            var sfmApiEndpoint = "";

            var httpHandler = new HttpClientHandler()
            {
                // Prevent 302 redirection
                AllowAutoRedirect = false
            };

            // Connect to SFM.Router to get client and api endpoints for this user/installation
            using (var httpClient = new HttpClient(httpHandler))
            {
                httpClient.SetBearerToken(accessToken);
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await httpClient.GetAsync(configuration.AppSettings("SfmRouterEndpoint"));

                if (!response.StatusCode.Equals(HttpStatusCode.Found))
                {
                    throw new ApplicationException($"Error communicating with SFM Router: {response.ReasonPhrase}");
                }

                var clientAndApiEnpoint = new Uri(response.Headers.Location.ToString());
                sfmApiEndpoint = HttpUtility.ParseQueryString(clientAndApiEnpoint.Query).Get("api_endpoint");
                sfmClientUrl = clientAndApiEnpoint.GetLeftPart(UriPartial.Authority);
            }

            if (!sfmClientUrl.EndsWith("/"))
            {
                sfmClientUrl += "/";
            }

            if (!sfmApiEndpoint.EndsWith("/"))
            {
                sfmApiEndpoint += "/";
            }

            // Connect to SFM Epj API to store/update patient and get ticket
            var sfmApiEndpointMethod = $"{sfmApiEndpoint}api/Epj/StartPasient";

            httpHandler = new HttpClientHandler() { AllowAutoRedirect = false };
            using (var httpClient = new HttpClient(httpHandler))
            {
                using (var stringContent = new StringContent(ReadTestFile(), Encoding.UTF8, "application/xml"))
                {
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                    httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));
                    var response = await httpClient.PostAsync(sfmApiEndpointMethod, stringContent);

                    if (response.StatusCode == HttpStatusCode.Found)
                    {
                        // Construct client entry point with the result from start pasient call
                        response.Headers.TryGetValues("ClientUrl", out var url);
                        sfmClientUrl += url.First() + $"&api_endpoint={sfmApiEndpoint}";
                    }
                }
            }

            return $"{sfmClientUrl}#access_token={accessToken}";
        }
    }
}
