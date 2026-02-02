#Requires -RunAsAdministrator
# Script to add Windows PowerShell, PowerShell ISE, and selected system utilities 
# (like BCDBOOT.exe) to Controlled Folder Access allowed apps
# This allows them to write to protected folders without being blocked

Write-Host "Adding trusted executables to Controlled Folder Access allow list..." -ForegroundColor Cyan

# === Standard PowerShell paths (Windows 10 & 11, 64-bit) ===
$psPath       = "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
$psISEPath    = "$env:windir\System32\WindowsPowerShell\v1.0\powershell_ise.exe"

# 32-bit versions (optional / rare on modern 64-bit systems)
$psWowPath    = "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
$psISEWowPath = "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell_ise.exe"

# === Boot / recovery related tools often blocked ===
$bcdbootPath  = "$env:windir\System32\bcdboot.exe"      # BCDBOOT.exe - creates/updates boot files
$bcdeditPath  = "$env:windir\System32\bcdedit.exe"      # BCDEdit - manages BCD store
$bootrecPath  = "$env:windir\System32\bootrec.exe"      # Bootrec - repairs boot configuration

# You can add more here if needed, for example:
# $reagentPath = "$env:windir\System32\ReAgentc.exe"   # Recovery environment tool
# $diskpartPath = "$env:windir\System32\diskpart.exe"

# Collect only existing files
$pathsToAdd = @(
    $psPath, $psISEPath, $psWowPath, $psISEWowPath,
    $bcdbootPath, $bcdeditPath, $bootrecPath
    # , $reagentPath, $diskpartPath    # uncomment if desired
) | Where-Object { Test-Path $_ -PathType Leaf }

if ($pathsToAdd.Count -eq 0) {
    Write-Warning "None of the expected executables were found. Check your system paths."
    exit
}

# Add each one using Add-MpPreference (appends, does NOT overwrite existing list)
foreach ($exe in $pathsToAdd) {
    Write-Host "Adding: $exe" -ForegroundColor Green
    Add-MpPreference -ControlledFolderAccessAllowedApplications $exe -ErrorAction Stop
}

# Optional: Show current allowed list for confirmation
Write-Host "`nCurrent allowed applications for Controlled Folder Access:" -ForegroundColor Cyan
Get-MpPreference |
    Select-Object -ExpandProperty ControlledFolderAccessAllowedApplications |
    Sort-Object |
    ForEach-Object { Write-Host " $_" }

Write-Host "`nDone. The selected executables (including BCDBOOT.exe) should now be able to write to protected folders." -ForegroundColor Green
Write-Host "If you still see blocks:" -ForegroundColor Yellow
Write-Host "• Check Event Viewer → Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational"
Write-Host "• Or temporarily set Controlled Folder Access to Audit mode to log without blocking"
