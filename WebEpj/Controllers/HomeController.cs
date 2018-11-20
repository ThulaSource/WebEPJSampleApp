using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using WebEpj.Models;

namespace WebEpj.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IConfiguration configuration;
        private readonly IMemoryCache cache;

        public string EnvironmentUrl { get; set; }

        public HomeController(IConfiguration configuration, IMemoryCache cache)
        {
            this.configuration = configuration;
            this.cache = cache;
        }

        public IActionResult Index()
        {
            var model = new HomeModel
            {
                Environments = GetAvailableEnvironments()
            };

            // Available patients
            var client = new HttpClient
            {
                BaseAddress = new Uri(configuration.AppSettings("ApiEndpoint"))
            };

            var accessToken = HttpContext.GetTokenAsync("access_token").GetAwaiter().GetResult();
            client.SetBearerToken(accessToken);

            var response = client.GetAsync("api/patients/");

            var result = response.GetAwaiter().GetResult();
            var responseAsJson = result.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            var patientList = JsonConvert.DeserializeObject<List<SimplePatient>>(responseAsJson);

            var availablePatients = new List<SelectListItem>();
            foreach (var item in patientList)
            {
                availablePatients.Add(new SelectListItem { Text = item.FullNameAndFNR, Value = item.Ticket });
            }

            model.Patients = availablePatients;

            return View(model);
        }

        [HttpPost]
        public IActionResult Redirect(HomeModel model)
        {
            var accessToken = HttpContext.GetTokenAsync("access_token").GetAwaiter().GetResult();
            var idToken = HttpContext.GetTokenAsync("id_token").GetAwaiter().GetResult();
            
            var url = $"{model.SelectedEnvironment}/pages/set-context?patientTicket={model.SelectedTicket}#access_token={accessToken}&id_token={idToken}";
            return Redirect(url);
        }

        private List<SelectListItem> GetAvailableEnvironments()
        {
            cache.TryGetValue("AvailableEnvs", out List<string> availableEnvironments);

            if (availableEnvironments == null)
            {
                availableEnvironments = new List<string>(configuration.AppSettingsArray("AvailableHosts"));
                availableEnvironments.Sort();

                var cacheEntryOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(30));
                cache.Set("AvailableEnvs", availableEnvironments, cacheEntryOptions);
            }

            var envs = new List<SelectListItem>();
            foreach (var item in availableEnvironments)
            {
                envs.Add(new SelectListItem { Text = item, Value = item });
            }

            return envs;
        }
    }
}
