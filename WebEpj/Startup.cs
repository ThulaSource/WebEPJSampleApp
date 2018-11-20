using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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
                options.ResponseType = "id_token token";

                var scopes = Configuration.AppSettingsArray(Constants.AuthScopesKey);
                foreach (var item in scopes)
                {
                    options.Scope.Add(item);
                }

                options.SignedOutRedirectUri = Configuration.AppSettings(Constants.AuthSignedOutRedirectUriKey);
                options.AuthenticationMethod = OpenIdConnectRedirectBehavior.FormPost;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.UseTokenLifetime = true;
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters { ValidateLifetime = true };
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
