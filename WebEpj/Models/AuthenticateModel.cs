using System.Collections.Generic;

namespace WebEpj.Models
{
    public class AuthenticateModel
    {
        public string SessionNonce { get; set; }
        
        public string SessionCode { get; set; }
        
        public string ApiUrl { get; set; }
        
        public List<PortalModel> Portals { get; set; }
        
        /// <summary>
        /// Dictionary of additional data to pass to the client on initialization
        /// </summary>
        public Dictionary<string,string> Metadata { get; set; } = new ();
    
        public void SetClientHeaders(string clientApplication, string organization, string practitioner)
        {
            // sfm-user-agent 
            // The identification of the vendor application
            if (!string.IsNullOrWhiteSpace(clientApplication))
            {
                Metadata.Add("sfm-user-agent", clientApplication);    
            }

            // X-point-of-care
            // The organization
            if (!string.IsNullOrWhiteSpace(organization))
            {
                Metadata.Add("x-point-of-care", organization);    
            }
        
            // X-practitioner-pseudo
            // schematically identifiable value for the practitioner (Hashed HPR etc...)
            if (!string.IsNullOrWhiteSpace(practitioner))
            {
                Metadata.Add("x-practitioner-pseudo", practitioner);    
            }
        }
    }

    public class PortalModel
    {
        public string Name { get; set; }
        
        public string Address { get; set; }
    }
}
