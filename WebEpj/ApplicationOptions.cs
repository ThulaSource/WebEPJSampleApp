namespace WebEpj
{
    public class ApplicationOptions
    {
        public string SfmSessionGatewayEndpoint { get; set; }
    }
    
    public class AuthenticationOptions
    {
        public string Endpoint { get; set; }
            
        public string ClientId { get; set; }
            
        public string SignedOutRedirectUri { get; set; }
            
        public string[] Scopes { get; set; }
            
        public int? TokenRenewCheckInMinutes { get; set; }
    }
}