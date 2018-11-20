using Microsoft.AspNetCore.Mvc.Rendering;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace WebEpj.Models
{
    public class HomeModel
    {
        public List<SelectListItem> Environments { get; set; }

        public string SelectedEnvironment { get; set; }

        public List<SelectListItem> Patients { get; set; }

        public string SelectedTicket { get; set; }
    }

    public class SimplePatient
    {
        [JsonProperty("ticket")]
        public string Ticket { get; set; }

        [JsonProperty("fullName")]
        public string FullName { get; set; }

        [JsonProperty("fnr")]
        public string FNR { get; set; }

        public string FullNameAndFNR
        {
            get
            {
                return $"{FullName} ({FNR})";
            }
        }
    }
}
