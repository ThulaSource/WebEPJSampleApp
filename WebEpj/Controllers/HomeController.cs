using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using WebEpj.Models;

namespace WebEpj.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ApplicationOptions applicationOptions;
        private readonly AuthenticationOptions authenticationOptions;
        private readonly HttpClient httpClient;
        private readonly IHttpContextAccessor httpContextAccessor;
        
        public HomeController(IOptions<ApplicationOptions> appOptions,
            IOptions<AuthenticationOptions> authOptions,
            IHttpClientFactory httpClientFactory,
            IHttpContextAccessor httpContextAccessor)
        {
            applicationOptions = appOptions.Value;
            authenticationOptions = authOptions.Value;
            httpClient = httpClientFactory.CreateClient();
            this.httpContextAccessor = httpContextAccessor;
        }

        public async Task<IActionResult> Index()
        {
            var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");
            httpClient.SetBearerToken(accessToken);
            httpClient.BaseAddress = new Uri(applicationOptions.SfmSessionGatewayEndpoint);
            
            // Create new SFM Session
            var nonceValues = NonceHelper.CreateNonce();
            var content = new StringContent(JsonConvert.SerializeObject(new { nonce = nonceValues.nonceHashBase64 }), Encoding.UTF8, "application/json");
            
            var response = await httpClient.PostAsync("/api/Session/create", content);
            response.EnsureSuccessStatusCode();

            var responseAsJson = await response.Content.ReadAsStringAsync();
            var sessionInfo = JsonConvert.DeserializeObject<SessionResult>(responseAsJson);

            var model = new HomeModel
            {
                SessionNonce = HttpUtility.UrlEncode(nonceValues.nonceBase64),
                SessionCode = HttpUtility.UrlEncode(sessionInfo.Code),
                ApiUrl = sessionInfo.ApiAddress,
                Portals = GetPortals(sessionInfo.Portals)
            };

            return View(nameof(Index), model);
        }

        private List<PortalModel> GetPortals(List<SessionPortal> sessionInfoPortals)
        {
            return sessionInfoPortals.Select(x => new PortalModel
            {
                Address = x.Address,
                Name = x.PortalType.ToString()
            }).ToList();
        }

        [HttpGet]
        [Route("Home/loadTicketAsync")]
        public async Task<IActionResult> LoadTicketAsync([FromQuery] string patientIdentifier)
        {
            var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");
            httpClient.SetBearerToken(accessToken);
            httpClient.BaseAddress = new Uri(applicationOptions.SfmSessionGatewayEndpoint);

            var content = new StringContent(JsonConvert.SerializeObject(new { patientPid =  patientIdentifier }), Encoding.UTF8, "application/json");
                
            var response = await httpClient.PostAsync("/api/PatientTicket", content);
            response.EnsureSuccessStatusCode();

            var responseAsJson = await response.Content.ReadAsStringAsync();
            return Ok(JsonConvert.DeserializeObject<string>(responseAsJson));
        }
        
        [HttpGet]
        [Route("Home/refreshTokenAsync")]
        public async Task<IActionResult> RefreshTokenAsync()
        {
            // Call session gateway to refresh session
            if (httpContextAccessor.HttpContext.Items.ContainsKey("RenewSession") &&
                bool.Parse(httpContextAccessor.HttpContext.Items["RenewSession"].ToString()))
            {
                var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");
                httpClient.SetBearerToken(accessToken);
                httpClient.BaseAddress = new Uri(applicationOptions.SfmSessionGatewayEndpoint);
                
                var response = await httpClient.PostAsync("/api/Session/refresh", null);
                response.EnsureSuccessStatusCode();
            }
            
            return Ok();
        } 
        
        [HttpPost]
        [Route("Home/endSessionAsync")]
        public async Task<IActionResult> EndSessionAsync()
        {
            var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");
            httpClient.SetBearerToken(accessToken);
            httpClient.BaseAddress = new Uri(applicationOptions.SfmSessionGatewayEndpoint);
                
            var response = await httpClient.PostAsync("/api/Session/end", null);
            response.EnsureSuccessStatusCode();
            
            await HttpContext.SignOutAsync("OpenIdConnect");
            await HttpContext.SignOutAsync("Cookies");
            
            var idToken = await httpContextAccessor.HttpContext.GetTokenAsync("id_token");
            return Redirect($"{authenticationOptions.Endpoint}/connect/endsession?id_token_hint={idToken}");
        }
    }
}
