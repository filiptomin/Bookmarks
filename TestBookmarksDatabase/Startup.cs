using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TestBookmarksDatabase.Models;
using TestBookmarksDatabase.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace TestBookmarksDatabase
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options => { options.CheckConsentNeeded = context => true; options.MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.None; });
            services.AddMvc(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
                options.EnableEndpointRouting = false;
            })
            .SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
            services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
                .AddAzureAD(options => Configuration.Bind("AzureAd", options));
            services.Configure<OpenIdConnectOptions>(AzureADDefaults.OpenIdScheme, options =>
            {
                options.Authority = options.Authority + "/2.0/";
                options.TokenValidationParameters.ValidateIssuer = false; });
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddIdentity<IdentityUser<Guid>,IdentityRole<Guid>>(options =>
            {
                options.SignIn.RequireConfirmedAccount = true;
                options.Password.RequiredLength = 6;
                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            //.AddDefaultUI()
            .AddDefaultTokenProviders();
            services.AddAuthentication()
            .AddMicrosoftAccount(options =>
             {
                 options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                 options.ClientId = Configuration["Authentication:Microsoft:ClientId"];
                 options.ClientSecret = Configuration["Authentication:Microsoft:ClientSecret"];
                 options.SaveTokens = true;
             })
            .AddGoogle(options => { IConfigurationSection googleAuthNSection = Configuration.GetSection("Authentication:Google");
                options.ClientId = googleAuthNSection["ClientId"];
                options.ClientSecret = googleAuthNSection["ClientSecret"];
            })
            .AddFacebook(facebookOptions =>
            {
                facebookOptions.AppId = Configuration["Authentication:Facebook:AppId"];
                facebookOptions.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
            })
            .AddTwitter(twitterOptions =>
            {
                twitterOptions.ConsumerKey = Configuration["Authentication:Twitter:ConsumerAPIKey"];
                twitterOptions.ConsumerSecret = Configuration["Authentication:Twitter:ConsumerSecret"];
                twitterOptions.RetrieveUserDetails = true;
            });
            ;
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy => policy.RequireRole("Administrátor"));
                options.AddPolicy("User", policy =>policy.RequireRole("User"));
            });
            services.AddScoped<IBookmarksManager, BookmarksManager>();
            services.AddScoped<IEmailSender, EmailSender>();
            services.AddRazorPages(options =>
            {
                options.Conventions.AuthorizeFolder("/Pages/Administration","Admin");
                options.Conventions.AuthorizeFolder("/Pages/Personal","User");
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            //app.UseMvc(routes => { routes.MapRoute(name: "default", template: "{controller=Home}/{action=Index}/{id?}"); });
            app.UseHttpsRedirection();
            app.UseStaticFiles();
            //app.UseCookiePolicy();
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }
}
