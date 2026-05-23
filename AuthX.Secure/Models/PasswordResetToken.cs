namespace AuthX.Secure.Models;

public class PasswordResetToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public User? User { get; set; }

    // Tokenul stocheaza un hash al valorii random emise
    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(15);
    public bool Used { get; set; } = false;
    public DateTime? UsedAt { get; set; }
}
