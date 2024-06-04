using System.Collections.Generic;

namespace HelseId.Common.RequestObjects;

public interface IRequestObject
{
    /// <summary>
    /// The name of the request object item
    /// </summary>
    string Key { get; }

    /// <summary>
    /// The objects to be inserted as payload
    /// </summary>
    IList<object> RequestObjectItems { get; }
}