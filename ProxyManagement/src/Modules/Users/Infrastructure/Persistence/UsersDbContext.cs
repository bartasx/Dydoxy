using Microsoft.EntityFrameworkCore;
using ProxyManagement.Modules.Users.Domain.Entities;

namespace ProxyManagement.Modules.Users.Infrastructure.Persistence;

public class UsersDbContext : DbContext
{
    public UsersDbContext(DbContextOptions<UsersDbContext> options) : base(options) { }

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Subscription> Subscriptions => Set<Subscription>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema("users");

        // Organization configuration
        modelBuilder.Entity<Organization>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id)
                .HasConversion(id => id.Value, value => new OrganizationId(value));
            entity.Property(e => e.Name).HasMaxLength(255).IsRequired();
            entity.Property(e => e.PlanType).HasConversion<string>();
            entity.Property(e => e.Settings).HasColumnType("jsonb");
        });

        // User configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id)
                .HasConversion(id => id.Value, value => new UserId(value));
            entity.Property(e => e.OrganizationId)
                .HasConversion(id => id.Value, value => new OrganizationId(value));
            entity.Property(e => e.Email)
                .HasConversion(email => email.Value, value => new Email(value))
                .HasMaxLength(255).IsRequired();
            entity.Property(e => e.Role).HasConversion<string>();
            entity.Property(e => e.Limits).HasColumnType("jsonb");
            entity.HasIndex(e => e.Email).IsUnique();
        });

        // Subscription configuration
        modelBuilder.Entity<Subscription>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id)
                .HasConversion(id => id.Value, value => new SubscriptionId(value));
            entity.Property(e => e.OrganizationId)
                .HasConversion(id => id.Value, value => new OrganizationId(value));
            entity.Property(e => e.Plan).HasConversion<string>();
            entity.Property(e => e.Limits).HasColumnType("jsonb");
        });
    }
}