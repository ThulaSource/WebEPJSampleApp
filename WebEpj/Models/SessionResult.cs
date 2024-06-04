using System.Collections.Generic;

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
        /// Dictionary of Metadata to connect
        /// </summary>
        public Dictionary<string, string> Metadata { get; set; }
    }
}