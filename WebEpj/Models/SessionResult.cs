using System.Collections.Generic;
using System.Runtime.Serialization;

namespace WebEpj.Models
{
    public class SessionResult
    {
        /// <summary>
        /// The session identifier.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// The session one time code. 
        /// </summary>
        public string Code { get; set; }

        /// <summary>
        /// The session SFM Client address.
        /// </summary>
        public string ApiAddress { get; set; }
        
        /// <summary>
        /// List of Portals to connect
        /// </summary>
        public List<SessionPortal> Portals { get; set; }
    }
    
    /// <summary>
    /// Portal details
    /// </summary>
    public class SessionPortal
    {
        /// <summary>
        /// Type of Portal
        /// </summary>
        public PortalType PortalType { get; set; }

        /// <summary>
        /// Address of Portal
        /// </summary>
        public string Address { get; set; }
    }

    public enum PortalType
    {
        [EnumMember(Value = @"PatientPortal")]
        PatientPortal = 0,
    
        [EnumMember(Value = @"EnterprisePortal")]
        EnterprisePortal = 1,
    
        [EnumMember(Value = @"HealthcarePortal")]
        HealthcarePortal = 2,
    
    }
}