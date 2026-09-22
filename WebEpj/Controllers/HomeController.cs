using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using WebEpj.Extensions;
using WebEpj.Models;
using WebEpj.Session;

namespace WebEpj.Controllers
{
    
    public class HomeController : Controller
    {
        private readonly AuthenticationOptions authenticationOptions;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly ISessionGatewayClient sessionGatewayClient;
        
        public HomeController(
            IOptions<AuthenticationOptions> authOptions,
            IHttpContextAccessor httpContextAccessor,
            ISessionGatewayClient sessionGatewayClient)
        {
            authenticationOptions = authOptions.Value;
            this.httpContextAccessor = httpContextAccessor;
            this.sessionGatewayClient = sessionGatewayClient;
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
            // Create new SFM Session
            var nonceValues = NonceHelper.CreateNonce();
            var sessionInfo = await sessionGatewayClient.CreateSessionAsync(nonceValues.nonceHashBase64);
            var accessToken = await httpContextAccessor.HttpContext.GetTokenAsync("access_token");

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
            return Ok(await sessionGatewayClient.CreatePatientTicketAsync(patientIdentifier));
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
                await sessionGatewayClient.RefreshSessionAsync();
            }
            
            return Ok();
        } 
        
        [HttpPost]
        [Authorize(AuthenticationSchemes = "Cookies")]
        [Route("Home/endSessionAsync")]
        public async Task<IActionResult> EndSessionAsync()
        {
            await sessionGatewayClient.EndSessionAsync();
            
            await HttpContext.SignOutAsync("OpenIdConnect");
            await HttpContext.SignOutAsync("Cookies");
            
            var idToken = await httpContextAccessor.HttpContext.GetTokenAsync("id_token");
            return Redirect($"{authenticationOptions.Endpoint}/connect/endsession?id_token_hint={idToken}");
        }

    }
}
