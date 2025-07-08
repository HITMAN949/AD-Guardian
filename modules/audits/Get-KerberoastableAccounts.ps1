<#+
.SYNOPSIS
    Finds user accounts with Service Principal Names (SPNs) matching keywords in config.json.
.DESCRIPTION
    Audits for Kerberoastable accounts. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-KerberoastableAccounts {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    try {
        $users = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName,SamAccountName
        foreach ($user in $users) {
            foreach ($spn in $user.ServicePrincipalName) {
                foreach ($keyword in $Config.kerberoastableSPNKeywords) {
                    if ($spn -like "*$keyword*") {
                        $finding = "User $($user.SamAccountName) has SPN $spn (Kerberoastable)"
                        $results += [PSCustomObject]@{
                            Status    = "Fail"
                            Finding   = $finding
                            RiskLevel = "High"
                            Details   = $user | Select-Object SamAccountName, ServicePrincipalName
                        }
                    }
                }
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Status    = "Error"
            Finding   = "Could not enumerate Kerberoastable accounts."
            RiskLevel = "High"
            Details   = $_.Exception.Message
        }
    }
    return $results
} 