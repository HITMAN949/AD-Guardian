<#+
.SYNOPSIS
    Disables a stale user or computer account.
.DESCRIPTION
    Prompts for confirmation and disables the specified account.
.PARAMETER SamAccountName
    The SamAccountName of the account to disable.
.PARAMETER ObjectClass
    The object class (User or Computer).
#>
function Disable-StaleAccount {
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,
        [Parameter(Mandatory)]
        [string]$ObjectClass
    )
    Write-Host "You are about to disable the $ObjectClass account: $SamAccountName" -ForegroundColor Yellow
    $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Action cancelled by user." -ForegroundColor Cyan
        return
    }
    try {
        if ($ObjectClass -eq 'User') {
            Disable-ADAccount -Identity $SamAccountName -ErrorAction Stop
        } elseif ($ObjectClass -eq 'Computer') {
            Disable-ADAccount -Identity $SamAccountName -ErrorAction Stop
        } else {
            throw "Unsupported object class: $ObjectClass"
        }
        Write-Host "$ObjectClass account $SamAccountName has been disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable $ObjectClass account $SamAccountName: $_" -ForegroundColor Red
    }
} 