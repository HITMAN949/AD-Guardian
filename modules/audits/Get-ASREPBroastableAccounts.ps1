<#+
.SYNOPSIS
    Finds user accounts with 'Do not require Kerberos preauthentication' set.
.DESCRIPTION
    Audits for AS-REP roastable accounts. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-ASREPBroastableAccounts {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    try {
        $users = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } -Properties DoesNotRequirePreAuth,SamAccountName
        foreach ($user in $users) {
            $finding = "User $($user.SamAccountName) is AS-REP roastable (no Kerberos preauthentication required)."
            $results += [PSCustomObject]@{
                Status    = "Fail"
                Finding   = $finding
                RiskLevel = "Critical"
                Details   = $user | Select-Object SamAccountName, DoesNotRequirePreAuth
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Status    = "Error"
            Finding   = "Could not enumerate AS-REP roastable accounts."
            RiskLevel = "Critical"
            Details   = $_.Exception.Message
        }
    }
    return $results
} 