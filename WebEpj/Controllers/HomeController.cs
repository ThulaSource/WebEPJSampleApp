using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using WebEpj.Extensions;
using WebEpj.Models;

namespace WebEpj.Controllers
{
    
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

        [AllowAnonymous]
        [HttpGet]
        public IActionResult Index()
        {
            return View(nameof(Index));
        }
        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult SingleTenant()
        {
            HttpContext.Session.Set("MultiTenantOrganization", false);
            
            return RedirectToAction(nameof(Authenticate));
        }
        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult MultiTenant(string parentOrganization, string childOrganization)
        {
            HttpContext.Session.Set("MultiTenantOrganization", true);
            HttpContext.Session.Set("HelseIdParentOrganization", parentOrganization);
            HttpContext.Session.Set("HelseIdChildOrganization", childOrganization);
            
            return RedirectToAction(nameof(Authenticate));
        }
        
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Authenticate()
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

            var model = new AuthenticateModel
            {
                SessionNonce = HttpUtility.UrlEncode(nonceValues.nonceBase64),
                SessionCode = HttpUtility.UrlEncode(sessionInfo.Code),
                ApiUrl = sessionInfo.ApiAddress,
                Portals = GetPortals(sessionInfo.Metadata)
            };
            
            var hpr = ReadTokenClaim("helseid://claims/hpr/hpr_number", accessToken);
            var org = ReadTokenClaim("helseid://claims/client/claims/orgnr_parent", accessToken);
            
            model.SetClientHeaders($"sfm-test-epj",
                org,
                HashValue(hpr));

            return View(nameof(Authenticate), model);
        }

        private string HashValue(string value)
        {
            if (value == null)
            {
                return null;
            }
        
            // Calculate the hash
            using var sha256 = SHA256.Create();
            var inputBytes = Encoding.ASCII.GetBytes(value);
            var hash = sha256.ComputeHash(inputBytes);

            // Convert byte array to hex string
            var sb = new StringBuilder();
            foreach (var t in hash)
            {
                sb.Append(t.ToString("X2"));
            }
            return sb.ToString();
        }

        private string ReadTokenClaim(string claimKey, string accessToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(accessToken);
            return jwtToken.Claims.FirstOrDefault(c => c.Type == claimKey)?.Value;
        }

        private List<PortalModel> GetPortals(Dictionary<string, string> metadata)
        {
            return metadata.Select(item => new PortalModel {Name = item.Key.ToUpper(), Address = item.Value}).ToList();
        }

        [HttpGet]
        [Authorize]
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
        [Authorize]
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
        [Authorize(AuthenticationSchemes = "Cookies")]
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
