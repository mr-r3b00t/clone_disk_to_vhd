#Requires -RunAsAdministrator

# Script to add Windows PowerShell and PowerShell ISE to Controlled Folder Access allowed apps
# This allows both to write to protected folders without being blocked

Write-Host "Adding Windows PowerShell executables to Controlled Folder Access allow list..." -ForegroundColor Cyan

# Standard paths (work on both Windows 10 and Windows 11, 64-bit systems)
$psPath          = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
$psISEPath       = "$env:windir\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

# Optional: Also add the 32-bit (WOW64) versions if you use them (rare on modern systems)
$psWowPath       = "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$psISEWowPath    = "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"

# Array of paths to add (only add if the file actually exists)
$pathsToAdd = @($psPath, $psISEPath, $psWowPath, $psISEWowPath) | 
    Where-Object { Test-Path $_ -PathType Leaf }

if ($pathsToAdd.Count -eq 0) {
    Write-Warning "None of the expected PowerShell executables were found. Check your system paths."
    exit
}

# Add each one using Add-MpPreference (appends, does NOT overwrite existing list)
foreach ($exe in $pathsToAdd) {
    Write-Host "Adding: $exe" -ForegroundColor Green
    Add-MpPreference -ControlledFolderAccessAllowedApplications $exe -ErrorAction Stop
}

# Optional: Show confirmation of what is now allowed
Write-Host "`nCurrent allowed applications for Controlled Folder Access:" -ForegroundColor Cyan
Get-MpPreference | 
    Select-Object -ExpandProperty ControlledFolderAccessAllowedApplications | 
    Sort-Object | 
    ForEach-Object { Write-Host "  $_" }

Write-Host "`nDone. PowerShell and PowerShell ISE should now be able to write to protected folders." -ForegroundColor Green
Write-Host "If you still see blocks, check Event Viewer → Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational" -ForegroundColor Yellow
