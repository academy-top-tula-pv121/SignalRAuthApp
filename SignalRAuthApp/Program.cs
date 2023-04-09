using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using SignalRAuthApp;
using System.Runtime.InteropServices;
using System.Security.Claims;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o => o.LoginPath = "/login");
builder.Services.AddAuthorization();
builder.Services.AddSignalR();


var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


var roleAdmin = new Role() { Name = "admin" };
var roleUser = new Role() { Name = "user" };

var users = new List<User>()
{
    new() { Login = "bob", Password = "123", Role = roleUser },
    new() { Login = "leo", Password = "555", Role = roleAdmin },
};


app.MapGet("/login", async context => await SendHtmlAsync(context, "html/login.html"));

app.MapPost("/login", async (string? redirectUrl, HttpContext context) =>
{
    var form = context.Request.Form;

    if (!form.ContainsKey("login") || !form.ContainsKey("password"))
        return Results.BadRequest("Login or password undefined");

    string login = form["login"];
    string password = form["password"];

    User? user = users.Find(x => x.Login == login && x.Password == password);
    if (user == null)
        return Results.Unauthorized();

    var claims = new List<Claim>()
    {
        new(ClaimsIdentity.DefaultNameClaimType, user.Login),
        new(ClaimsIdentity.DefaultRoleClaimType, user.Role.Name),
    };

    var claimsIdenty = new ClaimsIdentity(claims, "Cookies");
    var claimsPrincipal = new ClaimsPrincipal(claimsIdenty);

    await context.SignInAsync(claimsPrincipal);
    return Results.Redirect(redirectUrl ?? "/");
});

app.MapGet("/", [Authorize] async (HttpContext context) =>
{
    await SendHtmlAsync(context, "html/index.html");
});

app.MapGet("/admin", [Authorize(Roles = "admin")] async (HttpContext context) =>
{
    await SendHtmlAsync(context, "html/admin.html");
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.MapHub<ChatHub>("/chat");

app.Run();




async Task SendHtmlAsync(HttpContext context, string path)
{
    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.SendFileAsync(path);
}
public class User
{
    public string Login { set; get; }
    public string Password { set; get; }
    public Role Role { set; get; }
}
public class Role
{
    public string Name { set; get; }
}