using System.Collections.Generic;

namespace HelseId.Common.RequestObjects;

public class AuthorizationDetailsRequestObject : IRequestObject
{
    public string Key => "authorization_details";
    public IList<object> RequestObjectItems { get; }

    public AuthorizationDetailsRequestObject()
    {
        RequestObjectItems = new List<object>();
    }
}