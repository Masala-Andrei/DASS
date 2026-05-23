namespace AuthX.Secure.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;

    // Stochez hasul parolei, nu parola in clar
    public string PasswordHash { get; set; } = string.Empty;

    public string Role { get; set; } = "USER";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Rate limiting si blocarea userului dupa prea multe incercari de login
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockedUntil { get; set; }

    public List<Ticket> Tickets { get; set; } = new();
    public List<PasswordResetToken> ResetTokens { get; set; } = new();
    public List<Session> Sessions { get; set; } = new();
}
