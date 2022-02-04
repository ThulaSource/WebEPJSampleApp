using System.Collections.Generic;

namespace WebEpj.Models
{
    public class HomeModel
    {
        public string SessionNonce { get; set; }
        
        public string SessionCode { get; set; }
        
        public string ApiUrl { get; set; }
        
        public List<PortalModel> Portals { get; set; }
    }

    public class PortalModel
    {
        public string Name { get; set; }
        
        public string Address { get; set; }
    }
}
