namespace HelseId.Common.RequestObjects;

public interface IRequestObjectBuilder
{
    /// <summary>
    /// Builder method to join all the <see cref="IRequestObjectItem"/>
    /// </summary>
    IRequestObject Build();
}