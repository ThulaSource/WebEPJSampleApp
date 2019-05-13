using HelseId.Common.Clients;
using HelseId.Common.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;

namespace WebEpj
{
    public class Startup
    {
        public IConfiguration Configuration { get; }
        
        public Startup(IConfiguration configuration, IHostingEnvironment env)
        {
            Configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddMemoryCache();
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

            services.AddAuthentication((options) =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
            {
                o.Cookie = new CookieBuilder { HttpOnly = true };
            })
            .AddOpenIdConnect((options) =>
            {
                options.SignInScheme = "Cookies";
                options.Authority = Configuration.AppSettings(Constants.AuthEndpointKey);
                options.ClientId = Configuration.AppSettings(Constants.AuthClientIdKey);
                options.ResponseType = "code";

                var scopes = Configuration.AppSettingsArray(Constants.AuthScopesKey);
                var scopeString = string.Empty; 
                foreach (var item in scopes)
                {
                    options.Scope.Add(item);
                    scopeString += $"{item} ";
                }

                options.SignedOutRedirectUri = Configuration.AppSettings(Constants.AuthSignedOutRedirectUriKey);
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.UseTokenLifetime = true;
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters { ValidateLifetime = true };
                options.Events = new OpenIdConnectEvents
                {
                    OnAuthorizationCodeReceived = async ctx =>
                    {
                        var opt = new HelseIdClientOptions
                        {
                            ClientId = Configuration.AppSettings(Constants.AuthClientIdKey),
                            Authority = Configuration.AppSettings(Constants.AuthEndpointKey),
                            RedirectUri = $"{ctx.Request.Scheme}://{ctx.Request.Host}/signin-oidc",
                            SigningMethod = (JwtGenerator.SigningMethod)Enum.Parse(typeof(JwtGenerator.SigningMethod), "2"),
                            Scope = scopeString.TrimEnd(),
                            Flow = IdentityModel.OidcClient.OidcClientOptions.AuthenticationFlow.Hybrid,
                        };

                        var client = new HelseIdClient(opt);

                        var result = await client.AcquireTokenByAuthorizationCodeAsync(ctx.ProtocolMessage.Code);

                        if (result.IsError)
                        {
                            throw new ApplicationException(result.Error);
                        }

                        var response = new OpenIdConnectMessage
                        {
                            AccessToken = result.AccessToken,
                            IdToken = result.IdentityToken,
                            RefreshToken = result.RefreshToken
                        };

                        ctx.HandleCodeRedemption(response);
                    }
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            // Fix redirect uri behind reverse proxy
            // https://github.com/aspnet/Security/issues/1702
            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedProto
            });

            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
