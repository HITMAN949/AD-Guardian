<#+
.SYNOPSIS
    Finds all computers and users configured for unconstrained Kerberos delegation.
.DESCRIPTION
    Audits for unconstrained delegation. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-UnconstrainedDelegation {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    foreach ($type in @('User','Computer')) {
        try {
            $objects = Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288))' -SearchBase ((Get-ADDomain).DistinguishedName) -Properties SamAccountName,userAccountControl,ObjectClass
            foreach ($obj in $objects) {
                $finding = "$type $($obj.SamAccountName) is configured for unconstrained delegation."
                $results += [PSCustomObject]@{
                    Status    = "Fail"
                    Finding   = $finding
                    RiskLevel = "Critical"
                    Details   = $obj | Select-Object SamAccountName, userAccountControl, ObjectClass
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Status    = "Error"
                Finding   = "Could not enumerate $type objects for unconstrained delegation."
                RiskLevel = "Critical"
                Details   = $_.Exception.Message
            }
        }
    }
    return $results
} 