using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace HelseId.Common.Browser
{
    public class BrowserRequestHandler: IDisposable
    {
        const int DefaultTimeout = 60 * 5;

        private HttpListener Listener { get; }

        TaskCompletionSource<string> _source = new TaskCompletionSource<string>();

        public BrowserRequestHandler(string redirectUri)
        {
            if (!redirectUri.EndsWith("/"))
                redirectUri += "/";

           Listener = new HttpListener();
            try
            {
                Listener.Prefixes.Add(redirectUri);

                Task.Run(async () =>
                {
                    await Start();
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
                Environment.Exit(-1);
            }
        }

        internal async Task Start()
        {
            if (Listener.IsListening)
                Listener.Stop();

            Listener.Start();


            var httpctx = await Listener.GetContextAsync();
            await ProcessContext(httpctx);

            
            
            Listener.Stop();
        }

        private async Task ProcessContext(HttpListenerContext ctx)
        {
            if (ctx.Request.HttpMethod == "GET")
            {
                SetResult(ctx.Request.RawUrl, ctx);
            }
            else if (ctx.Request.HttpMethod == "POST")
            {
                if (!ctx.Request.ContentType.Equals("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Response.StatusCode = 415;
                }
                else
                {
                    using (var body = ctx.Request.InputStream)
                    {
                        using (var reader = new StreamReader(body, ctx.Request.ContentEncoding))
                        {
                            var content = await reader.ReadToEndAsync();
                            SetResult(content, ctx);
                        }
                    }
                }
            }
            await OutputResponse(ctx.Response);
        }

        private void SetResult(string value, HttpListenerContext ctx)
        {
            try
            {
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "text/html";

                var buffer = Encoding.UTF8.GetBytes("<h1>You can now return to the application.</h1>");
                // Get a response stream and write the response to it.
                ctx.Response.ContentLength64 = buffer.Length;
                ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.OutputStream.Flush();

                _source.TrySetResult(value);
            }
            catch
            {
                ctx.Response.StatusCode = 400;
                ctx.Response.ContentType = "text/html";
                var buffer = Encoding.UTF8.GetBytes("<h1>Invalid request.</h1>");
                ctx.Response.ContentLength64 = buffer.Length;
                ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.OutputStream.Flush();
            }
        }

        private static async Task OutputResponse(HttpListenerResponse response)
        {
            const string responseString = "<html><head><meta charset=\"UTF-8\"></head><body><h1>Innlogging vellykket :)</h1><h2>Lukk nettleseren for å logge ut.</h2></body></html>";

            var buffer = Encoding.UTF8.GetBytes(responseString);

            response.ContentLength64 = buffer.Length;

            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);

            response.OutputStream.Close();
        }

        public void Dispose()
        {
            Listener.Stop();
            Listener.Close();
        }

        public Task<string> WaitForCallbackAsync(int timeoutInSeconds = DefaultTimeout)
        {
            Task.Run(async () =>
            {
                await Task.Delay(timeoutInSeconds * 1000);
                _source.TrySetCanceled();
            });

            return _source.Task;
        }
    }
}
