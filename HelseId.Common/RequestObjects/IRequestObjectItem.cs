using System.Collections.Generic;

namespace HelseId.Common.RequestObjects;

public interface IRequestObjectItem
{
    /// <summary>
    /// Custom logic to build <see cref="Value"/>
    /// </summary>
    /// <param name="inputValues">Input values to build the request</param>
    /// <returns>For simplicity returns itself</returns>
    object BuildValue(params KeyValuePair<string, object>[] inputValues);
}