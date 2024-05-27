namespace HelseId.Common.RequestObjects;

public interface IAuthorizationDetailsRequestObjectBuilder : IRequestObjectBuilder
{
    /// <summary>
    /// Builds a HelseId Authorization request object
    /// </summary>
    /// <param name="system">The system</param>
    /// <param name="value">The value</param>
    IAuthorizationDetailsRequestObjectBuilder AddHelseIdAuthorizationRequestObjectItem(string system, string value);

    /// <summary>
    /// Builds a journal Id request object
    /// </summary>
    /// <param name="journalId">The journalId</param>
    IAuthorizationDetailsRequestObjectBuilder AddJournalIdRequestObjectItem(string journalId);
}