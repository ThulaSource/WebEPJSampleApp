using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace HelseId.Common.Extensions
{
    public static class TokenExtensions
    {
        public static string DecodeToken(this string token)
        {
            if (string.IsNullOrEmpty(token)) return token;

            var parts = token.Split('.');

            string partToConvert = parts[1];
            partToConvert = partToConvert.Replace('-', '+');
            partToConvert = partToConvert.Replace('_', '/');
            switch (partToConvert.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    partToConvert += "==";
                    break;
                case 3:
                    partToConvert += "=";
                    break;
            }

            var partAsBytes = Convert.FromBase64String(partToConvert);
            var partAsUtf8String = Encoding.UTF8.GetString(partAsBytes, 0, partAsBytes.Count());

            return JObject.Parse(partAsUtf8String).ToString();
        }
    }
}
