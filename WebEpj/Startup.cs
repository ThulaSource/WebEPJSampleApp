using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using HelseId.Common.Clients;
using HelseId.Common.Jwt;
using HelseId.Common.Oidc;
using HelseId.Common.RequestObjects;
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
using WebEpj.Extensions;

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
                                        var response = await client.AcquireTokenByRefreshToken(refreshToken, false);

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

                        options.ClientId = authenticationOptions.EpjVendorId;
                        options.SignInScheme = "Cookies";
                        options.Authority = authenticationOptions.Endpoint;
                        options.ResponseType = OidcConstants.ResponseTypes.Code;
                        options.ResponseMode = OidcConstants.ResponseModes.FormPost;
                        options.RequireHttpsMetadata = false;
                        options.UsePkce = true;
                        
                        var scopes = "";
                        foreach (var item in authenticationOptions.Scopes)
                        {
                            options.Scope.Add(item);
                            scopes += $"{item} ";
                        }

                        options.SignedOutRedirectUri = authenticationOptions.SignedOutRedirectUri;
                        options.GetClaimsFromUserInfoEndpoint = true;
                        options.SaveTokens = true;
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = false
                        };

                        options.Events = new OpenIdConnectEvents
                        {
                            OnAuthorizationCodeReceived = async ctx =>
                            {
                                var isMultiTenant = ctx.TokenEndpointRequest.ClientId == authenticationOptions.EpjVendorId;

                                var clientId = isMultiTenant
                                    ? authenticationOptions.EpjVendorId
                                    : authenticationOptions.OrganizationSfmId;

                                var codeVerifier = isMultiTenant
                                    ? ctx.TokenEndpointRequest.Parameters[OidcConstants.TokenRequest.CodeVerifier]
                                    : string.Empty;
                                
                                var opt = new HelseIdClientOptions(clientId: clientId,
                                    authority: authenticationOptions.Endpoint,
                                    redirectUri: $"{ctx.Request.Scheme}://{ctx.Request.Host}/signin-oidc",
                                    postLogoutRedirectUri: authenticationOptions.SignedOutRedirectUri,
                                    signingMethod: (JwtGenerator.SigningMethod) Enum.Parse(typeof(JwtGenerator.SigningMethod), "2"), 
                                    scope: scopes.TrimEnd(),
                                    flow: IdentityModel.OidcClient.OidcClientOptions.AuthenticationFlow.Hybrid);

                                var client = new HelseIdClient(opt);

                                var result =
                                    await client.AcquireTokenByAuthorizationCodeAsync(
                                        ctx.ProtocolMessage.Code, 
                                        codeVerifier, 
                                        isMultiTenant);

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
                                var isMultiTenant = ctx?.HttpContext?.Session.Get<bool>("MultiTenantOrganization") ?? false;

                                if (isMultiTenant)
                                {
                                    options.ClientId = authenticationOptions.EpjVendorId;
                                    ctx.ProtocolMessage.Parameters.Remove("client_id");
                                    ctx.ProtocolMessage.Parameters.Add("client_id", authenticationOptions.EpjVendorId);
                                    
                                    var requestObject = new AuthorizationDetailsRequestObjectBuilder();

                                    var parentOrg = ctx?.HttpContext?.Session.Get<string>("HelseIdParentOrganization");
                                    var childOrg = ctx?.HttpContext?.Session.Get<string>("HelseIdChildOrganization");

                                    // If we don't have any type of organization we'll be preemptive and throw a 401
                                    // only exception to this - When the request is coming from the ClientWrapper
                                    // in this scenario we'll allow it to proceed
                                    if (string.IsNullOrEmpty(parentOrg) && string.IsNullOrEmpty(childOrg))
                                    {
                                        // We do not want these validation to be applied to ClientWrapper and just ClientWrapper
                                        // There will be a refactoring on the organization on the server side where this condition should be removed
                                        ctx.Response.StatusCode = 401;
                                        ctx.HandleResponse();
                                        return Task.CompletedTask;
                                    }

                                    // HelseId now accepts organizational claims
                                    // in order for this to work we need to send a POST request to the authorization endpoint following
                                    // the request object pattern. This is but a single token with an authorization_details claim present.
                                    // We are bypassing our own HelseIdClient because the audience needs to be the authority and not the 
                                    // TokenEndpointUrl that we got via discovery.
                                    // More information on this
                                    // GIT Samples => https://github-com.translate.goog/NorskHelsenett/HelseID.Samples/tree/master/HelseId.Samples.RequestObjectsDemo?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en-US&_x_tr_pto=op
                                    // Confluence => https://helseid.atlassian.net/wiki/spaces/HELSEID/pages/5636230/Passing+organization+identifier+from+a+client+application+to+HelseID
                                    // https://helseid.atlassian.net/wiki/spaces/HELSEID/pages/478183429/Passing+extended+context+information+to+HelseID

                                    // We use 2 different systems:
                                    // 1. only child is present - urn:oid:2.16.578.1.12.4.1.2.101
                                    // 2. when we have parent/child or just parent organization - urn:oid:1.0.6523
                                    var system = "urn:oid:1.0.6523";
                                    var value = string.Empty;

                                    // We have three different scenarios when calculating the value:
                                    // 1. Only Parent - NO:ORGNR:[ParentOrganization] with system urn:oid:1.0.6523
                                    // 2. Parent+child - NO:ORGNR:[ParentOrganization]:[ChildOrganization] with system urn:oid:1.0.6523
                                    // 3. Only child - [ChildOrganization] with system urn:oid:2.16.578.1.12.4.1.2.101
                                    if (!string.IsNullOrEmpty(parentOrg))
                                    {
                                        value = $"NO:ORGNR:{parentOrg}";

                                        if (!string.IsNullOrEmpty(childOrg))
                                        {
                                            value = $"{value}:{childOrg}";
                                        }
                                    }
                                    else if (!string.IsNullOrEmpty(childOrg))
                                    {
                                        value = childOrg;
                                        system = "urn:oid:2.16.578.1.12.4.1.2.101";
                                    }

                                    if (!string.IsNullOrEmpty(value))
                                    {
                                        requestObject.AddHelseIdAuthorizationRequestObjectItem(system, value);
                                    }

                                    requestObject.AddJournalIdRequestObjectItem(authenticationOptions.OrganizationSfmId);

                                    var token = JwtGenerator.GenerateWithRequestObject(ctx.Options.ClientId,
                                        ctx.Options.Authority, 
                                        ClientAssertion.LoadWebEpjVendorPrivateKey(),
                                        SecurityAlgorithms.RsaSha512,
                                        requestObject.Build());

                                    ctx.ProtocolMessage.SetParameter("request", token);
                                }
                                else
                                {
                                    options.ClientId = authenticationOptions.OrganizationSfmId;
                                    ctx?.ProtocolMessage.Parameters.Remove("client_id");
                                    ctx?.ProtocolMessage.Parameters.Add("client_id", authenticationOptions.OrganizationSfmId);
                                    
                                    ctx?.ProtocolMessage.Parameters.Remove("code_challenge");
                                    ctx?.ProtocolMessage.Parameters.Remove("code_challenge_method");
                                    ctx?.ProtocolMessage.Parameters.Remove("nonce");
                                }

                                return Task.CompletedTask;
                            }
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