namespace AuthX.Secure.Services;

// Validari de parola
//  - lungime minima 12 
//  - cel putin o litera mica
//  - cel putin o litera mare
//  - cel putin o cifra
//  - cel putin un caracter non-alfanumeric 
public class PasswordPolicy
{
    private readonly int _minLength;

    public PasswordPolicy(IConfiguration config)
    {
        _minLength = config.GetValue<int>("Security:MinPasswordLength", 12);
    }

    public bool IsValid(string password, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrEmpty(password) || password.Length < _minLength)
        {
            error = $"Parola trebuie sa aiba cel putin {_minLength} caractere si sa contina litere mari, mici, cifre si simboluri.";
            return false;
        }

        bool hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
        foreach (var c in password)
        {
            if (char.IsLower(c)) hasLower = true;
            else if (char.IsUpper(c)) hasUpper = true;
            else if (char.IsDigit(c)) hasDigit = true;
            else if (!char.IsLetterOrDigit(c)) hasSymbol = true;
        }

        if (!hasLower || !hasUpper || !hasDigit || !hasSymbol)
        {
            error = $"Parola trebuie sa aiba cel putin {_minLength} caractere si sa contina litere mari, mici, cifre si simboluri.";
            return false;
        }

        return true;
    }
}
