using System.Collections.Generic;

namespace HelseId.Common.RequestObjects;

public class AuthorizationDetailsRequestObjectBuilder : IAuthorizationDetailsRequestObjectBuilder
{
    private readonly IRequestObject requestObject;

    public AuthorizationDetailsRequestObjectBuilder()
    {
        requestObject = new AuthorizationDetailsRequestObject();
    }

    public IRequestObject Build()
    {
        return requestObject;
    }

    public IAuthorizationDetailsRequestObjectBuilder AddHelseIdAuthorizationRequestObjectItem(string system, string value)
    {
        var helseIdAuthorizationRequestObject =
            new HelseIdAuthorizationRequestObjectItem().BuildValue(
                new KeyValuePair<string, object>(HelseIdAuthorizationRequestObjectItem.Keys.System,
                    system),
                new KeyValuePair<string, object>(HelseIdAuthorizationRequestObjectItem.Keys.Value,
                    value));
        requestObject.RequestObjectItems.Add(helseIdAuthorizationRequestObject);
        return this;
    }

    public IAuthorizationDetailsRequestObjectBuilder AddJournalIdRequestObjectItem(string journalId)
    {
        var helseIdAuthorizationRequestObject =
            new JournalIdRequestObjectItem().BuildValue(new KeyValuePair<string, object>(JournalIdRequestObjectItem.Keys.JournalId, journalId));
            
        requestObject.RequestObjectItems.Add(helseIdAuthorizationRequestObject);
        return this;
    }
}