using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

using Microsoft.AspNetCore.SignalR;

namespace SignalRAuthApp
{
    [Authorize]
    public class ChatHub : Hub
    {
        public async Task Send(string username, string message)
        {
            var userCurrent = Context.User;
            var userNaqmeCurrent = userCurrent?.Identity?.Name;
            var userRoleCurrent = userCurrent?.FindFirst(ClaimTypes.Role)?.Value;

            await Clients.All.SendAsync("Receive", username, message);
        }

        [Authorize(Roles = "admin")]
        public async Task Notify(string message)
        {
            await Clients.All.SendAsync("Receive", "Admin", message);
        }
    }
}
