using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using HelseId.Common.Clients;
using HelseId.Common.Jwt;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WebEpj
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHealthChecks();
            services.AddHttpContextAccessor()
                .Configure<ApplicationOptions>(Configuration)
                .Configure<AuthenticationOptions>(Configuration.GetSection("Authentication"))
                .Configure<CookiePolicyOptions>(options =>
                {
                    options.CheckConsentNeeded = context => true;
                    options.MinimumSameSitePolicy = SameSiteMode.None;
                })
                .AddMemoryCache()
                .AddHttpClient()
                .AddHttpContextAccessor()
                .AddMvc(options => { options.EnableEndpointRouting = false; })
                .Services
                .AddAuthentication((options) =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                //
                // CONFIGURE ASP.NET AUTHENTICATION COOKIE 
                //
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme,
                    o =>
                    {
                        o.Cookie = new CookieBuilder
                        {
                            HttpOnly = true,
                            Name = "EpjCookie",
                            SameSite = SameSiteMode.Unspecified,
                            SecurePolicy = CookieSecurePolicy.SameAsRequest
                        };
                        o.Events = new CookieAuthenticationEvents()
                        {
                            // This prevents the jwt token to get expired by:
                            // 1 - Check if the cookie is close to expire (threshold is read from setting, defaults to 5 minutes)
                            // 2 - If true get new access token by using the existing refresh token
                            // 3 - Create new cookie with expiration date the same as token expiration date
                            OnValidatePrincipal = async ctx =>
                            {
                                if (ctx?.Principal?.Identity != null && ctx.Principal.Identity.IsAuthenticated)
                                {
                                    var expTokenValue = ctx.Properties.GetTokenValue("expires_at");
                                    if (!DateTime.TryParse(expTokenValue, CultureInfo.InvariantCulture,
                                        DateTimeStyles.None, out var expValue))
                                    {
                                        return;
                                    }

                                    var applicationOptions = ctx.HttpContext.RequestServices
                                        .GetService<IOptions<AuthenticationOptions>>();
                                    var expires = expValue.ToUniversalTime();
                                    var timeRemaining = expires.Subtract(DateTime.UtcNow);

                                    var refreshThreshold =
                                        TimeSpan.FromMinutes(applicationOptions.Value.TokenRenewCheckInMinutes ?? 5);

                                    var forceRenewal = false;
                                    if (ctx.Request.Headers.ContainsKey("renewSession") &&
                                        bool.TryParse(ctx.Request.Headers["renewSession"], out var tmpHeaderValue))
                                    {
                                        forceRenewal = tmpHeaderValue;
                                    }

                                    if (timeRemaining < refreshThreshold || forceRenewal)
                                    {
                                        var accessToken = ctx.Properties.GetTokenValue("access_token");
                                        var tokenHandler = new JwtSecurityTokenHandler();
                                        var jwtToken = tokenHandler.ReadToken(accessToken) as JwtSecurityToken;
                                        var sfmId = jwtToken?.Claims?.FirstOrDefault(x =>
                                            x.Type == "e-helse:sfm.api/client/claims/sfm-id")?.Value;
                                        var authority = jwtToken?.Claims?.FirstOrDefault(x => x.Type == "iss")?.Value;

                                        // Account for losing session between application restarts
                                        if (string.IsNullOrWhiteSpace(sfmId) || string.IsNullOrWhiteSpace(authority))
                                        {
                                            return;
                                        }

                                        var refreshToken = ctx.Properties.GetTokenValue("refresh_token");

                                        if (string.IsNullOrWhiteSpace(refreshToken))
                                        {
                                            return;
                                        }

                                        var opt = new HelseIdClientOptions
                                        {
                                            ClientId = sfmId,
                                            Authority = authority,
                                            ClientSecret = "", // needs to be empty
                                            SigningMethod =
                                                (JwtGenerator.SigningMethod) Enum.Parse(
                                                    typeof(JwtGenerator.SigningMethod), "2"),
                                            Flow = IdentityModel.OidcClient.OidcClientOptions.AuthenticationFlow.Hybrid,
                                            RedirectUri = $"{ctx.Request.Scheme}://{ctx.Request.Host}/signin-oidc"
                                        };

                                        var client = new HelseIdClient(opt);
                                        var response = await client.AcquireTokenByRefreshToken(refreshToken);

                                        if (!response.IsError)
                                        {
                                            var expiresInSeconds = response.ExpiresIn;
                                            var updatedExpiresAt = DateTime.UtcNow.ToUniversalTime()
                                                .AddSeconds(expiresInSeconds);

                                            ctx.Properties.UpdateTokenValue("expires_at",
                                                updatedExpiresAt.ToString(CultureInfo.InvariantCulture));
                                            ctx.Properties.UpdateTokenValue("access_token", response.AccessToken);
                                            ctx.Properties.UpdateTokenValue("refresh_token", response.RefreshToken);

                                            // Indicate to the cookie middleware that the cookie should be created again (since we have updated it)
                                            ctx.ShouldRenew = true;
                                            // Update a context flag that will trigger a call to session gateway to refresh the session token
                                            ctx.HttpContext.Items.Add("RenewSession", true);
                                        }
                                        else
                                        {
                                            ctx.RejectPrincipal();
                                            await ctx.HttpContext.SignOutAsync();
                                        }
                                    }
                                }
                            }
                        };
                    })
                //
                // CONFIGURE OPENID CONNECT 
                //
                .AddOpenIdConnect
                (
                    options =>
                    {
                        var authenticationOptions = new AuthenticationOptions();
                        Configuration.GetSection("Authentication").Bind(authenticationOptions);

                        options.UseTokenLifetime = false;
                        options.ClientId = authenticationOptions.ClientId;
                        options.SignInScheme = "Cookies";
                        options.Authority = authenticationOptions.Endpoint;
                        options.ResponseType = OidcConstants.ResponseTypes.Code;
                        options.RequireHttpsMetadata = false;

                        var scopes = "";
                        foreach (var item in authenticationOptions.Scopes)
                        {
                            options.Scope.Add(item);
                            scopes += $"{item} ";
                        }

                        options.SignedOutRedirectUri = authenticationOptions.SignedOutRedirectUri;
                        options.GetClaimsFromUserInfoEndpoint = true;
                        options.SaveTokens = true;
                        options.TokenValidationParameters = new TokenValidationParameters {ValidateAudience = false};

                        options.Events = new OpenIdConnectEvents
                        {
                            OnAuthorizationCodeReceived = async ctx =>
                            {
                                var opt = new HelseIdClientOptions
                                {
                                    ClientId = authenticationOptions.ClientId,
                                    Authority = authenticationOptions.Endpoint,
                                    RedirectUri = $"{ctx.Request.Scheme}://{ctx.Request.Host}/signin-oidc",
                                    PostLogoutRedirectUri = authenticationOptions.SignedOutRedirectUri,
                                    SigningMethod =
                                        (JwtGenerator.SigningMethod) Enum.Parse(typeof(JwtGenerator.SigningMethod),
                                            "2"),
                                    Scope = scopes.TrimEnd(),
                                    Flow = IdentityModel.OidcClient.OidcClientOptions.AuthenticationFlow.Hybrid,
                                };

                                var client = new HelseIdClient(opt);

                                var result =
                                    await client.AcquireTokenByAuthorizationCodeAsync(ctx.ProtocolMessage.Code);

                                if (result.IsError)
                                {
                                    throw new ApplicationException(result.Error);
                                }

                                var response = new OpenIdConnectMessage
                                {
                                    AccessToken = result.AccessToken,
                                    IdToken = result.IdentityToken,
                                    RefreshToken = result.RefreshToken,
                                    ExpiresIn = result.ExpiresIn.ToString()
                                };
                                ctx.HandleCodeRedemption(response);
                            },
                            OnRedirectToIdentityProvider = ctx =>
                            {
                                ctx?.ProtocolMessage.Parameters.Remove("code_challenge");
                                ctx?.ProtocolMessage.Parameters.Remove("code_challenge_method");
                                ctx?.ProtocolMessage.Parameters.Remove("nonce");

                                return Task.CompletedTask;
                            },
                        };
                    }).Services
                .AddSession(options => { options.IdleTimeout = TimeSpan.FromHours(2); });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Fix redirect uri behind reverse proxy
            // https://github.com/aspnet/Security/issues/1702
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedProto
            });

            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();

            app.UseSession();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action}/{id?}", new {controller = "Home", action = "Index"});
            });
        }
    }
}