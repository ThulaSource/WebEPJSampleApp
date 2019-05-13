using Newtonsoft.Json;

namespace HelseId.Models.DCR.Api
{
    public class ApiResourceRequest : ApiResource
    {
        [JsonProperty("secrets")]
        public Secret[] Secrets { get; set; }
    }
}