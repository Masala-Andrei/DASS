namespace AuthX.Vulnerable.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = "USER";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool Locked { get; set; } = false;

    public List<Ticket> Tickets { get; set; } = new();
    public List<PasswordResetToken> ResetTokens { get; set; } = new();
}
