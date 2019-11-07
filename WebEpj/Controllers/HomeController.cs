using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
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


        private async Task<string> GetSfmClientUrl(string accessToken)
        {
            // CONTACT FHIR API TO FETCH A NEW PATIENT TICKET FOR THE PATIENT
            // USING PATIENT WITH FNR: 09099512064 AS AN EXAMPLE
            var sfmClientUrl = "";
            var patientTicket = "";

            using (var httpClient = new HttpClient())
            {
                httpClient.SetBearerToken(accessToken);
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var patientFnr = "09099512064";
                var ticketEndpoint = $"{configuration.AppSettings("SfmFhirApiEndpoint")}fhir/PatientTickets/{patientFnr}";
                
                var response = await httpClient.GetAsync(ticketEndpoint);

                if (response.StatusCode.Equals(HttpStatusCode.NotFound))
                {
                    // PATIENT DOES NOT EXIST. POST TO /FHIR/PATIENTS TO CREATE A NEW PATIENT OR PUT TO /FHIR/PATIENTS/{PATIENTTICKET} TO UPDATE AN EXISTING ONE
                    throw new ApplicationException("Patient not found when fetching ticket from SFM Fhir API");
                }

                if (!response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    throw new ApplicationException($"Error communicating with SFM Fhir API: {response.ReasonPhrase}");
                }

                patientTicket = await response.Content.ReadAsAsync<string>();
            }

            // Construct router url along with parameters
            var queryParams = new Dictionary<string, string>();

            queryParams.Add("patientTicket", patientTicket);
            queryParams.Add("show-cave", "true");

            // Uncomment to send on behalf of parameter
            //queryParams.Add("onBehalfOf", "USER HPRID");

            var routerEndpoint = QueryHelpers.AddQueryString(configuration.AppSettings("SfmRouterEndpoint"), queryParams);

            // CONNECT TO SFM.ROUTER TO GET CLIENT ENDPOINT
            using (var httpClient = new HttpClient())
            {
                httpClient.SetBearerToken(accessToken);
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                var response = await httpClient.GetAsync(routerEndpoint);

                if (!response.StatusCode.Equals(HttpStatusCode.OK))
                {
                    throw new ApplicationException($"Error communicating with SFM Router: {response.ReasonPhrase}");
                }

                sfmClientUrl = await response.Content.ReadAsStringAsync();
            }

            return sfmClientUrl;
        }
    }
}
