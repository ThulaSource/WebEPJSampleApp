using System;
using System.Threading;
using System.Threading.Tasks;
using Duende.IdentityModel.OidcClient.Browser;

namespace HelseId.Common.Browser
{
    public abstract class Browser : IBrowser
    {
        private string _redirectUri;

        public Browser(string redirectUri)
        {
            _redirectUri = redirectUri;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default)
        {
            using (var listener = new BrowserRequestHandler(_redirectUri))
            {
                OpenBrowser(options.StartUrl);

                try
                {
                    var result = await listener.WaitForCallbackAsync().WaitAsync(cancellationToken);
                    if (String.IsNullOrWhiteSpace(result))
                    {
                        return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = "Empty response." };
                    }

                    return new BrowserResult { Response = result, ResultType = BrowserResultType.Success };
                }
                catch (TaskCanceledException ex)
                {
                    return new BrowserResult { ResultType = BrowserResultType.Timeout, Error = ex.Message };
                }
                catch (Exception ex)
                {
                    return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
                }
            }
        }

        public abstract void OpenBrowser(string url);
    }
}
