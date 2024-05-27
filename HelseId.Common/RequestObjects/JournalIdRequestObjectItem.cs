using System.Collections.Generic;
using System.Dynamic;
using System.Linq;

namespace HelseId.Common.RequestObjects;

public class JournalIdRequestObjectItem : IRequestObjectItem
{
    public object BuildValue(params KeyValuePair<string, object>[] inputValues)
    {
        dynamic authorizationDetails = new ExpandoObject();
        authorizationDetails.type = "nhn:sfm:journal-id";
        authorizationDetails.value = new ExpandoObject();
        authorizationDetails.value.journal_id = inputValues.FirstOrDefault(x => x.Key == Keys.JournalId).Value;

        return authorizationDetails;
    }
    
    internal static class Keys
    {
        public const string JournalId = "System"; }
}