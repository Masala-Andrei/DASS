namespace AuthX.Secure.Models;

// Voi stoca sesiunea serverside ca sa o validez / sa o revoc.
// Cand acesta iese din cont, sterg sesiunea. Daca atacatorul a reusit sa fure cookie ul
// nu il poate folosi pentru ca sesiunea e stearsa
public class Session
{
    public string Id { get; set; } = string.Empty; // GUID generat server-side
    public int UserId { get; set; }
    public User? User { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;
    public bool Revoked { get; set; } = false;
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }
}
