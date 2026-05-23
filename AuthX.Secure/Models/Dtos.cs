using System.ComponentModel.DataAnnotations;

namespace AuthX.Secure.Models;

public class RegisterViewModel
{
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Display(Name = "Parola")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Display(Name = "Rol (USER / ANALYST / MANAGER)")]
    public string? Role { get; set; }
}

public class LoginViewModel
{
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;

    [Display(Name = "Parola")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
}

public class ForgotPasswordViewModel
{
    [Display(Name = "Email")]
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordViewModel
{
    [Display(Name = "Token")]
    public string Token { get; set; } = string.Empty;

    [Display(Name = "Parola noua")]
    [DataType(DataType.Password)]
    public string NewPassword { get; set; } = string.Empty;
}

public class TicketCreateViewModel
{
    [Display(Name = "Titlu")]
    public string Title { get; set; } = string.Empty;

    [Display(Name = "Descriere")]
    public string Description { get; set; } = string.Empty;

    [Display(Name = "Severitate (LOW / MEDIUM / HIGH)")]
    public string Severity { get; set; } = "LOW";
}
