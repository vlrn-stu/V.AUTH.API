using Microsoft.AspNetCore.Identity;

namespace V.AUTH.API.Models
{
    public class AuthUser : IdentityUser
    {
        public string FirstName { get; set; } = default!;
        public string LastName { get; set; } = default!;
        public string? ProfilePicture {  get; set; }
    }

}
