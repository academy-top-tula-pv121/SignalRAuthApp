using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SignalRAuthApp
{
    [Authorize]
    public class ChatHub : Hub
    {
        public async Task Send(string username, string message)
        {
            await Clients.All.SendAsync("Receive", username, message);
        }

        [Authorize(Roles = "admin")]
        public async Task Notify(string message)
        {
            await Clients.All.SendAsync("Receive", "Admin", message);
        }
    }
}
