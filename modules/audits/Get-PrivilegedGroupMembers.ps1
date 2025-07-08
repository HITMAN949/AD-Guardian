<#+
.SYNOPSIS
    Audits membership of privileged groups defined in config.json.
.DESCRIPTION
    Checks for non-standard or excessive members in privileged groups. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-PrivilegedGroupMembers {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    foreach ($group in $Config.privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
            foreach ($member in $members) {
                $isPrivileged = $true # All members of these groups are privileged
                $finding = "Member $($member.SamAccountName) in group $group"
                $risk = "Critical"
                $status = if ($isPrivileged) { "Fail" } else { "Pass" }
                $details = $member | Select-Object Name, SamAccountName, ObjectClass
                $results += [PSCustomObject]@{
                    Status    = $status
                    Finding   = $finding
                    RiskLevel = $risk
                    Details   = $details
                }
            }
        } catch {
            $results += [PSCustomObject]@{
                Status    = "Error"
                Finding   = "Could not enumerate group $group"
                RiskLevel = "Critical"
                Details   = $_.Exception.Message
            }
        }
    }
    return $results
} 