<#+
.SYNOPSIS
    Finds user accounts with 'Password Never Expires' enabled.
.DESCRIPTION
    Audits for user accounts with non-expiring passwords. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-NonExpiringPasswords {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    try {
        $users = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires,SamAccountName
        foreach ($user in $users) {
            $finding = "User $($user.SamAccountName) has 'Password Never Expires' enabled."
            $results += [PSCustomObject]@{
                Status    = "Fail"
                Finding   = $finding
                RiskLevel = "High"
                Details   = $user | Select-Object SamAccountName, PasswordNeverExpires
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Status    = "Error"
            Finding   = "Could not enumerate users with non-expiring passwords."
            RiskLevel = "High"
            Details   = $_.Exception.Message
        }
    }
    return $results
} 