using System.Collections.Generic;
using System.Dynamic;
using System.Linq;

namespace HelseId.Common.RequestObjects;

public class HelseIdAuthorizationRequestObjectItem : IRequestObjectItem
{
    public object BuildValue(params KeyValuePair<string, object>[] inputValues)
    {
        dynamic authorizationDetails = new ExpandoObject();
        authorizationDetails.type = "helseid_authorization";
        authorizationDetails.practitioner_role = new ExpandoObject();
        authorizationDetails.practitioner_role.organization = new ExpandoObject();
        authorizationDetails.practitioner_role.organization.identifier =
            new ExpandoObject();
        authorizationDetails.practitioner_role.organization.identifier.system =
            inputValues.FirstOrDefault(x => x.Key == Keys.System).Value;
        authorizationDetails.practitioner_role.organization.identifier.type = "ENH";
        authorizationDetails.practitioner_role.organization.identifier.value =
            inputValues.FirstOrDefault(x => x.Key == Keys.Value).Value;
            
        return authorizationDetails;
    }

    internal static class Keys
    {
        public const string System = "System";
        public const string Value = "Value";
    }
}