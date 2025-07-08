<#+
.SYNOPSIS
    Disables the 'Password Never Expires' flag for a user account.
.DESCRIPTION
    Prompts for confirmation and disables the flag for the specified user.
.PARAMETER SamAccountName
    The SamAccountName of the user to update.
#>
function Fix-InsecurePasswordSetting {
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )
    Write-Host "You are about to disable 'Password Never Expires' for user: $SamAccountName" -ForegroundColor Yellow
    $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Action cancelled by user." -ForegroundColor Cyan
        return
    }
    try {
        Set-ADUser -Identity $SamAccountName -PasswordNeverExpires $false -ErrorAction Stop
        Write-Host "'Password Never Expires' has been disabled for $SamAccountName." -ForegroundColor Green
    } catch {
        Write-Host "Failed to update $SamAccountName: $_" -ForegroundColor Red
    }
} 