using AuthX.Vulnerable.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthX.Vulnerable.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<Ticket> Tickets => Set<Ticket>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Email)
            .IsUnique();

        modelBuilder.Entity<Ticket>()
            .HasOne(t => t.Owner)
            .WithMany(u => u.Tickets)
            .HasForeignKey(t => t.OwnerId);

        modelBuilder.Entity<PasswordResetToken>()
            .HasOne(t => t.User)
            .WithMany(u => u.ResetTokens)
            .HasForeignKey(t => t.UserId);
    }
}

public class RevokedToken
{
    public int Id { get; set; }
    public string Jti { get; set; } = string.Empty;
    public DateTime RevokedAt { get; set; } = DateTime.UtcNow;
}
