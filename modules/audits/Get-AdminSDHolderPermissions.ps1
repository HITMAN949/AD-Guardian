<#+
.SYNOPSIS
    Checks the ACL of the AdminSDHolder object for non-default or risky permissions.
.DESCRIPTION
    Audits AdminSDHolder permissions. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-AdminSDHolderPermissions {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    try {
        $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties ntSecurityDescriptor
        $acl = $adminSDHolder.ntSecurityDescriptor
        # TODO: Compare $acl to known-good/default ACLs
        $finding = "Review AdminSDHolder ACL for non-default or risky permissions. Manual review required."
        $results += [PSCustomObject]@{
            Status    = "Info"
            Finding   = $finding
            RiskLevel = "High"
            Details   = $acl
        }
    } catch {
        $results += [PSCustomObject]@{
            Status    = "Error"
            Finding   = "Could not enumerate AdminSDHolder permissions."
            RiskLevel = "High"
            Details   = $_.Exception.Message
        }
    }
    return $results
} 