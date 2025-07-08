<#+
.SYNOPSIS
    Audits computers for LAPS compliance (ms-Mcs-AdmPwd attribute populated and recent).
.DESCRIPTION
    Checks if the LAPS password attribute is present and recent. Returns findings as custom objects.
.PARAMETER Config
    The configuration object loaded from config.json.
.OUTPUTS
    [PSCustomObject] with Status, Finding, RiskLevel, and Details.
#>
function Get-LapsCompliance {
    param(
        [Parameter(Mandatory)]
        $Config
    )
    $results = @()
    try {
        $computers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','SamAccountName'
        foreach ($comp in $computers) {
            if ($null -eq $comp.'ms-Mcs-AdmPwd') {
                $finding = "Computer $($comp.SamAccountName) does not have a LAPS password set."
                $results += [PSCustomObject]@{
                    Status    = "Fail"
                    Finding   = $finding
                    RiskLevel = "Medium"
                    Details   = $comp | Select-Object SamAccountName, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
                }
            } else {
                $expTime = [datetime]::FromFileTime($comp.'ms-Mcs-AdmPwdExpirationTime')
                if ($expTime -lt (Get-Date).AddDays(-30)) {
                    $finding = "Computer $($comp.SamAccountName) has an old LAPS password (last set: $expTime)."
                    $results += [PSCustomObject]@{
                        Status    = "Fail"
                        Finding   = $finding
                        RiskLevel = "Medium"
                        Details   = $comp | Select-Object SamAccountName, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
                    }
                } else {
                    $results += [PSCustomObject]@{
                        Status    = "Pass"
                        Finding   = "Computer $($comp.SamAccountName) is LAPS compliant."
                        RiskLevel = "Low"
                        Details   = $comp | Select-Object SamAccountName, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
                    }
                }
            }
        }
    } catch {
        $results += [PSCustomObject]@{
            Status    = "Error"
            Finding   = "Could not enumerate LAPS compliance."
            RiskLevel = "Medium"
            Details   = $_.Exception.Message
        }
    }
    return $results
} 