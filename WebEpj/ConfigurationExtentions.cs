using System;
using System.Linq;
using Microsoft.Extensions.Configuration;

namespace WebEpj
{
    public static class ConfigurationExtentions
    {
        public static dynamic AppSettings(this IConfiguration configuration, string name)
        {
            var section = configuration.GetSection(Constants.AppSettingsKey);
            if (section == null)
            {
                throw new ArgumentException("appSettings section is missing from the appsettings.json file");
            }
            return section[name];
        }

        public static dynamic AppSettingsArray(this IConfiguration configuration, string name)
        {
            var section = configuration.GetSection(Constants.AppSettingsKey);
            if (section == null)
            {
                throw new ArgumentException("appSettings section is missing from the appsettings.json file");
            }

            var array = section.GetSection(name);
            return array?.GetChildren()?.Select(x => x.Value)?.ToArray();
        }
    }
}