#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a live Windows volume to a VHDX file, optionally skipping free space.
.DESCRIPTION
    Creates a VSS snapshot of a running volume and copies it to a VHDX virtual disk.
    By default, only allocated clusters are copied (NTFS only), dramatically reducing
    clone time and VHDX size.
    
    Run without parameters for interactive menu mode.
.PARAMETER SourceVolume
    Drive letter of the volume to clone (e.g., "C:" or "C")
.PARAMETER DestinationVHDX
    Path for the output VHDX file
.PARAMETER FullCopy
    Copy all sectors including free space (slower, larger file)
.PARAMETER FixedSizeVHDX
    Create a fixed-size VHDX instead of dynamic
.PARAMETER BlockSizeMB
    I/O block size in megabytes (default: 4)
.PARAMETER Interactive
    Force interactive menu mode
.EXAMPLE
    .\Clone-Volume.ps1
    Runs in interactive menu mode
.EXAMPLE
    .\Clone-Volume.ps1 -SourceVolume "C:" -DestinationVHDX "D:\Backup\System.vhdx"
.EXAMPLE
    .\Clone-Volume.ps1 -SourceVolume "C:" -DestinationVHDX "D:\Backup\Full.vhdx" -FullCopy
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'CommandLine', Mandatory = $false)]
    [string]$SourceVolume,
    
    [Parameter(ParameterSetName = 'CommandLine', Mandatory = $false)]
    [string]$DestinationVHDX,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [switch]$FullCopy,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [switch]$FixedSizeVHDX,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [ValidateRange(1, 64)]
    [int]$BlockSizeMB = 4,
    
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive
)

# ============================================================
# Initialization
# ============================================================

try {
    if ($null -ne [Console]::OutputEncoding) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
}
catch {
    Write-Verbose "Could not set console encoding (non-console host)"
}

try {
    $OutputEncoding = [System.Text.Encoding]::UTF8
}
catch { }

$currentPrincipal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires Administrator privileges. Please run as Administrator."
}

# ============================================================
# Part 1: P/Invoke Definitions
# ============================================================

$nativeCodeDefinition = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VirtDisk
{
    public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
    public const int CREATE_VIRTUAL_DISK_VERSION_2 = 2;
    public const int ATTACH_VIRTUAL_DISK_VERSION_1 = 1;
    
    public const uint VIRTUAL_DISK_ACCESS_ALL = 0x003f0000;
    
    public const uint CREATE_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION = 1;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct VIRTUAL_STORAGE_TYPE
    {
        public int DeviceId;
        public Guid VendorId;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct CREATE_VIRTUAL_DISK_PARAMETERS
    {
        public int Version;
        public Guid UniqueId;
        public ulong MaximumSize;
        public uint BlockSizeInBytes;
        public uint SectorSizeInBytes;
        public uint PhysicalSectorSizeInBytes;
        public IntPtr ParentPath;
        public IntPtr SourcePath;
        public int OpenFlags;
        public VIRTUAL_STORAGE_TYPE ParentVirtualStorageType;
        public VIRTUAL_STORAGE_TYPE SourceVirtualStorageType;
        public Guid ResiliencyGuid;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct ATTACH_VIRTUAL_DISK_PARAMETERS
    {
        public int Version;
        public int Reserved;
    }
    
    public static readonly Guid VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = 
        new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE VirtualStorageType,
        string Path,
        uint VirtualDiskAccessMask,
        IntPtr SecurityDescriptor,
        uint Flags,
        uint ProviderSpecificFlags,
        ref CREATE_VIRTUAL_DISK_PARAMETERS Parameters,
        IntPtr Overlapped,
        out IntPtr Handle);
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int AttachVirtualDisk(
        IntPtr VirtualDiskHandle,
        IntPtr SecurityDescriptor,
        uint Flags,
        uint ProviderSpecificFlags,
        ref ATTACH_VIRTUAL_DISK_PARAMETERS Parameters,
        IntPtr Overlapped);
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DetachVirtualDisk(
        IntPtr VirtualDiskHandle,
        uint Flags,
        uint ProviderSpecificFlags);
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetVirtualDiskPhysicalPath(
        IntPtr VirtualDiskHandle,
        ref int DiskPathSizeInBytes,
        IntPtr DiskPath);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

public static class NativeDisk
{
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
    public const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    
    public const uint FSCTL_GET_VOLUME_BITMAP = 0x0009006F;
    public const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct NTFS_VOLUME_DATA_BUFFER
    {
        public long VolumeSerialNumber;
        public long NumberSectors;
        public long TotalClusters;
        public long FreeClusters;
        public long TotalReserved;
        public uint BytesPerSector;
        public uint BytesPerCluster;
        public uint BytesPerFileRecordSegment;
        public uint ClustersPerFileRecordSegment;
        public long MftValidDataLength;
        public long MftStartLcn;
        public long Mft2StartLcn;
        public long MftZoneStart;
        public long MftZoneEnd;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTING_LCN_INPUT_BUFFER
    {
        public long StartingLcn;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct VOLUME_BITMAP_BUFFER
    {
        public long StartingLcn;
        public long BitmapSize;
    }
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);
    
    public const uint FILE_BEGIN = 0;
}
'@

$typesLoaded = $false
try {
    $null = [VirtDisk].Name
    $null = [NativeDisk].Name
    $typesLoaded = $true
}
catch {
    $typesLoaded = $false
}

if (-not $typesLoaded) {
    Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop
}

# ============================================================
# Part 2: Interactive Menu Functions
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║           " -ForegroundColor Cyan -NoNewline
    Write-Host "LIVE VOLUME CLONE UTILITY" -ForegroundColor Yellow -NoNewline
    Write-Host "                         ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║     Clone a running Windows volume to a VHDX file           ║" -ForegroundColor Cyan
    Write-Host "  ║     Supports skipping free space for faster clones          ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-VolumeList {
    # Force result to array with @() for PS5 compatibility
    $volumeList = @(Get-Volume | Where-Object { 
        $_.DriveLetter -and 
        $_.DriveType -eq 'Fixed' -and
        $_.Size -gt 0
    } | Sort-Object DriveLetter)
    
    return $volumeList
}

function Show-VolumeMenu {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Volumes
    )
    
    Write-Host "  Available Volumes:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    $index = 1
    foreach ($vol in $Volumes) {
        $sizeGB = [math]::Round($vol.Size / 1GB, 2)
        $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
        $freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
        $usedPct = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 0)
        
        $label = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Local Disk" }
        
        $barLength = 20
        $filledLength = [math]::Round(($usedPct / 100) * $barLength)
        $emptyLength = $barLength - $filledLength
        $progressBar = "[" + ([string]::new([char]0x2588, $filledLength)) + ([string]::new([char]0x2591, $emptyLength)) + "]"
        
        Write-Host "    [$index] " -ForegroundColor Yellow -NoNewline
        Write-Host "$($vol.DriveLetter):" -ForegroundColor White -NoNewline
        Write-Host " $label" -ForegroundColor Gray
        
        Write-Host "        " -NoNewline
        Write-Host "$progressBar " -ForegroundColor DarkCyan -NoNewline
        Write-Host "$usedGB GB / $sizeGB GB " -ForegroundColor Gray -NoNewline
        Write-Host "($($vol.FileSystemType))" -ForegroundColor DarkGray
        Write-Host ""
        
        $index++
    }
    
    Write-Host "    [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit" -ForegroundColor Gray
    Write-Host ""
}

function Read-MenuSelection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        
        [Parameter(Mandatory = $true)]
        [int]$Min,
        
        [Parameter(Mandatory = $true)]
        [int]$Max,
        
        [string]$Default = ""
    )
    
    while ($true) {
        if ($Default) {
            Write-Host "  $Prompt " -ForegroundColor White -NoNewline
            Write-Host "[$Default]" -ForegroundColor DarkGray -NoNewline
            Write-Host ": " -ForegroundColor White -NoNewline
        }
        else {
            Write-Host "  ${Prompt}: " -ForegroundColor White -NoNewline
        }
        
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput) -and $Default) {
            $userInput = $Default
        }
        
        $num = 0
        if ([int]::TryParse($userInput, [ref]$num)) {
            if ($num -ge $Min -and $num -le $Max) {
                return $num
            }
        }
        
        Write-Host "  Please enter a number between $Min and $Max" -ForegroundColor Red
        Write-Host ""
    }
}

function Read-PathInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        
        [string]$Default = "",
        
        [string]$RequiredExtension = ""
    )
    
    while ($true) {
        if ($Default) {
            Write-Host "  $Prompt" -ForegroundColor White
            Write-Host "  [$Default]" -ForegroundColor DarkGray
            Write-Host "  : " -ForegroundColor White -NoNewline
        }
        else {
            Write-Host "  ${Prompt}: " -ForegroundColor White -NoNewline
        }
        
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput) -and $Default) {
            $userInput = $Default
        }
        
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Host "  Path cannot be empty." -ForegroundColor Red
            Write-Host ""
            continue
        }
        
        if ($RequiredExtension -and -not $userInput.ToLower().EndsWith($RequiredExtension.ToLower())) {
            Write-Host "  Path must end with $RequiredExtension" -ForegroundColor Red
            Write-Host ""
            continue
        }
        
        return $userInput
    }
}

function Read-YesNo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        
        [bool]$Default = $false
    )
    
    $defaultStr = if ($Default) { "Y/n" } else { "y/N" }
    
    Write-Host "  $Prompt " -ForegroundColor White -NoNewline
    Write-Host "[$defaultStr]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    
    $userInput = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        return $Default
    }
    
    return $userInput.Trim().ToLower() -in @('y', 'yes', '1', 'true')
}

function Read-BlockSize {
    param(
        [int]$Default = 4
    )
    
    while ($true) {
        Write-Host "  Block size in MB (1-64) " -ForegroundColor White -NoNewline
        Write-Host "[$Default]" -ForegroundColor DarkGray -NoNewline
        Write-Host ": " -ForegroundColor White -NoNewline
        
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            return $Default
        }
        
        $num = 0
        if ([int]::TryParse($userInput, [ref]$num)) {
            if ($num -ge 1 -and $num -le 64) {
                return $num
            }
        }
        
        Write-Host "  Please enter a number between 1 and 64" -ForegroundColor Red
        Write-Host ""
    }
}

function Show-OptionsMenu {
    param(
        [string]$SourceVolume,
        [string]$DestinationPath,
        [bool]$FullCopy,
        [bool]$FixedSizeVHDX,
        [int]$BlockSizeMB
    )
    
    Write-Host ""
    Write-Host "  Clone Options:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [1] Copy Mode:     " -ForegroundColor Yellow -NoNewline
    if ($FullCopy) {
        Write-Host "Full Copy (all sectors)" -ForegroundColor White
    }
    else {
        Write-Host "Smart Copy (skip free space) " -ForegroundColor Green -NoNewline
        Write-Host "[Recommended]" -ForegroundColor DarkGreen
    }
    
    Write-Host "    [2] VHDX Type:     " -ForegroundColor Yellow -NoNewline
    if ($FixedSizeVHDX) {
        Write-Host "Fixed Size (pre-allocated)" -ForegroundColor White
    }
    else {
        Write-Host "Dynamic (grows as needed) " -ForegroundColor Green -NoNewline
        Write-Host "[Recommended]" -ForegroundColor DarkGreen
    }
    
    Write-Host "    [3] Block Size:    " -ForegroundColor Yellow -NoNewline
    Write-Host "$BlockSizeMB MB" -ForegroundColor White
    
    Write-Host ""
    Write-Host "    [S] " -ForegroundColor Green -NoNewline
    Write-Host "Start Clone" -ForegroundColor White
    Write-Host "    [C] " -ForegroundColor Cyan -NoNewline
    Write-Host "Change Destination" -ForegroundColor White
    Write-Host "    [B] " -ForegroundColor DarkYellow -NoNewline
    Write-Host "Back to Volume Selection" -ForegroundColor White
    Write-Host "    [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit" -ForegroundColor Gray
    Write-Host ""
}

function Show-Summary {
    param(
        [string]$SourceVolume,
        [string]$DestinationPath,
        [bool]$FullCopy,
        [bool]$FixedSizeVHDX,
        [int]$BlockSizeMB
    )
    
    $vol = Get-Volume -DriveLetter $SourceVolume -ErrorAction SilentlyContinue
    $sizeGB = [math]::Round($vol.Size / 1GB, 2)
    $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
    
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                      CLONE SUMMARY                           ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "    Source:        " -ForegroundColor Gray -NoNewline
    Write-Host "${SourceVolume}: ($($vol.FileSystemLabel))" -ForegroundColor White
    Write-Host "    Volume Size:   " -ForegroundColor Gray -NoNewline
    Write-Host "$sizeGB GB ($usedGB GB used)" -ForegroundColor White
    Write-Host "    Destination:   " -ForegroundColor Gray -NoNewline
    Write-Host "$DestinationPath" -ForegroundColor White
    Write-Host "    Copy Mode:     " -ForegroundColor Gray -NoNewline
    Write-Host "$(if ($FullCopy) { 'Full Copy' } else { 'Skip Free Space' })" -ForegroundColor White
    Write-Host "    VHDX Type:     " -ForegroundColor Gray -NoNewline
    Write-Host "$(if ($FixedSizeVHDX) { 'Fixed' } else { 'Dynamic' })" -ForegroundColor White
    
    if (-not $FullCopy) {
        Write-Host ""
        Write-Host "    Estimated Data:" -ForegroundColor Gray -NoNewline
        Write-Host " ~$usedGB GB" -ForegroundColor Cyan
    }
    
    Write-Host ""
}

function Start-InteractiveMode {
    $selectedVolume = $null
    $destinationPath = $null
    $optFullCopy = $false
    $optFixedSizeVHDX = $false
    $optBlockSizeMB = 4
    
    :volumeLoop while ($true) {
        Show-Banner
        
        $volumes = Get-VolumeList
        $volumeCount = $volumes.Count
        
        if ($volumeCount -eq 0) {
            Write-Host "  No suitable volumes found!" -ForegroundColor Red
            Write-Host "  Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            return
        }
        
        Show-VolumeMenu -Volumes $volumes
        
        $selection = Read-MenuSelection -Prompt "Select a volume to clone" -Min 0 -Max $volumeCount
        
        if ($selection -eq 0) {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            return
        }
        
        $selectedVolume = $volumes[$selection - 1].DriveLetter
        $volumeInfo = $volumes[$selection - 1]
        
        # Default destination path
        $defaultName = "Clone_${selectedVolume}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        
        # Find a suitable destination drive (not the source)
        $destDrive = @(Get-Volume | Where-Object { 
            $_.DriveLetter -and 
            $_.DriveLetter -ne $selectedVolume -and 
            $_.DriveType -eq 'Fixed' -and
            $_.SizeRemaining -gt ($volumeInfo.Size - $volumeInfo.SizeRemaining + 1GB)
        } | Sort-Object SizeRemaining -Descending | Select-Object -First 1)
        
        if ($destDrive -and $destDrive.Count -gt 0) {
            $defaultPath = "$($destDrive[0].DriveLetter):\Backups\$defaultName"
        }
        else {
            $defaultPath = "${selectedVolume}:\Backups\$defaultName"
        }
        
        Write-Host ""
        $destinationPath = Read-PathInput -Prompt "Destination VHDX path" -Default $defaultPath -RequiredExtension ".vhdx"
        
        # Options Loop
        :optionsLoop while ($true) {
            Show-Banner
            
            Write-Host "  Source: " -ForegroundColor Gray -NoNewline
            Write-Host "${selectedVolume}: " -ForegroundColor White -NoNewline
            $label = if ($volumeInfo.FileSystemLabel) { "($($volumeInfo.FileSystemLabel))" } else { "(Local Disk)" }
            Write-Host $label -ForegroundColor DarkGray
            
            Write-Host "  Destination: " -ForegroundColor Gray -NoNewline
            Write-Host "$destinationPath" -ForegroundColor White
            
            Show-OptionsMenu -SourceVolume $selectedVolume -DestinationPath $destinationPath `
                -FullCopy $optFullCopy -FixedSizeVHDX $optFixedSizeVHDX -BlockSizeMB $optBlockSizeMB
            
            Write-Host "  Enter choice: " -ForegroundColor White -NoNewline
            $choice = Read-Host
            
            switch ($choice.ToUpper()) {
                "1" {
                    $optFullCopy = -not $optFullCopy
                }
                "2" {
                    $optFixedSizeVHDX = -not $optFixedSizeVHDX
                }
                "3" {
                    Write-Host ""
                    $optBlockSizeMB = Read-BlockSize -Default $optBlockSizeMB
                }
                "C" {
                    Write-Host ""
                    $destinationPath = Read-PathInput -Prompt "New destination VHDX path" -Default $destinationPath -RequiredExtension ".vhdx"
                }
                "B" {
                    continue volumeLoop
                }
                "S" {
                    Show-Banner
                    Show-Summary -SourceVolume $selectedVolume -DestinationPath $destinationPath `
                        -FullCopy $optFullCopy -FixedSizeVHDX $optFixedSizeVHDX -BlockSizeMB $optBlockSizeMB
                    
                    if (Test-Path -LiteralPath $destinationPath) {
                        Write-Host "  WARNING: Destination file already exists!" -ForegroundColor Yellow
                        $overwrite = Read-YesNo -Prompt "Overwrite existing file?" -Default $false
                        if (-not $overwrite) {
                            continue optionsLoop
                        }
                        Remove-Item -LiteralPath $destinationPath -Force
                    }
                    
                    $destDir = Split-Path -Path $destinationPath -Parent
                    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                        Write-Host "  Destination directory will be created: $destDir" -ForegroundColor DarkYellow
                    }
                    
                    Write-Host ""
                    $confirm = Read-YesNo -Prompt "Start clone operation?" -Default $true
                    
                    if ($confirm) {
                        Write-Host ""
                        Write-Host "  Starting clone operation..." -ForegroundColor Cyan
                        Write-Host ""
                        
                        try {
                            New-LiveVolumeClone `
                                -SourceVolume $selectedVolume `
                                -DestinationVHDX $destinationPath `
                                -FullCopy:$optFullCopy `
                                -FixedSizeVHDX:$optFixedSizeVHDX `
                                -BlockSizeMB $optBlockSizeMB
                            
                            Write-Host ""
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Green
                            Write-Host "  Clone completed successfully!" -ForegroundColor Green
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Green
                        }
                        catch {
                            Write-Host ""
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Red
                            Write-Host "  Clone failed: $_" -ForegroundColor Red
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Red
                        }
                        
                        Write-Host ""
                        Write-Host "  Press any key to continue..." -ForegroundColor Gray
                        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                        
                        Write-Host ""
                        $another = Read-YesNo -Prompt "Clone another volume?" -Default $false
                        if ($another) {
                            continue volumeLoop
                        }
                        else {
                            Write-Host ""
                            Write-Host "  Goodbye!" -ForegroundColor Cyan
                            return
                        }
                    }
                }
                "0" {
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return
                }
                default {
                    # Invalid input, just refresh
                }
            }
        }
    }
}

# ============================================================
# Part 3: VSS Functions
# ============================================================

function New-VssSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume
    )
    
    if (-not $Volume.EndsWith('\')) { 
        $Volume = $Volume + '\' 
    }
    
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume  = $Volume
        Context = 'ClientAccessible'
    }
    
    if ($result.ReturnValue -ne 0) {
        $errorMessages = @{
            1  = 'Access denied'
            2  = 'Invalid argument'
            3  = 'Specified volume not found'
            4  = 'Specified volume not supported'
            5  = 'Unsupported shadow copy context'
            6  = 'Insufficient storage'
            7  = 'Volume is in use'
            8  = 'Maximum number of shadow copies reached'
            9  = 'Another shadow copy operation is in progress'
            10 = 'Shadow copy provider vetoed the operation'
            11 = 'Shadow copy provider not registered'
            12 = 'Shadow copy provider failure'
        }
        $msg = $errorMessages[[int]$result.ReturnValue]
        if (-not $msg) { $msg = "Unknown error" }
        throw "Failed to create shadow copy. Error $($result.ReturnValue): $msg"
    }
    
    $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | 
        Where-Object { $_.ID -eq $result.ShadowID }
    
    if (-not $shadowCopy) {
        throw "Shadow copy created but could not be retrieved."
    }
    
    return @{
        Id           = $result.ShadowID
        DeviceObject = $shadowCopy.DeviceObject
        VolumeName   = $Volume
    }
}

function Remove-VssSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShadowId
    )
    
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    
    $shadow = Get-CimInstance -ClassName Win32_ShadowCopy | 
        Where-Object { $_.ID -eq $ShadowId }
    
    if ($shadow) {
        Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue
    }
}

# ============================================================
# Part 4: Virtual Disk Functions
# ============================================================

function New-RawVHDX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [uint64]$SizeBytes,
        
        [switch]$FixedSize
    )
    
    $typeStr = if ($FixedSize) { "Fixed" } else { "Dynamic" }
    Write-Host "Creating $typeStr VHDX: $Path ($([math]::Round($SizeBytes/1GB, 2)) GB)..." -ForegroundColor Cyan
    
    $parentDir = Split-Path -Path $Path -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        $null = New-Item -Path $parentDir -ItemType Directory -Force
    }
    
    $storageType = New-Object -TypeName VirtDisk+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $params = New-Object -TypeName VirtDisk+CREATE_VIRTUAL_DISK_PARAMETERS
    $params.Version = 2
    $params.MaximumSize = $SizeBytes
    $params.BlockSizeInBytes = 0
    $params.SectorSizeInBytes = 512
    $params.PhysicalSectorSizeInBytes = 4096
    $params.UniqueId = [Guid]::NewGuid()
    
    $flags = if ($FixedSize) { 
        [VirtDisk]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION 
    }
    else { 
        [VirtDisk]::CREATE_VIRTUAL_DISK_FLAG_NONE 
    }
    
    $handle = [IntPtr]::Zero
    $result = [VirtDisk]::CreateVirtualDisk(
        [ref]$storageType,
        $Path,
        [VirtDisk]::VIRTUAL_DISK_ACCESS_ALL,
        [IntPtr]::Zero,
        $flags,
        0,
        [ref]$params,
        [IntPtr]::Zero,
        [ref]$handle
    )
    
    if ($result -ne 0) {
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
        throw "CreateVirtualDisk failed: $($win32Err.Message) (0x$($result.ToString('X8')))"
    }
    
    return $handle
}

function Mount-RawVHDX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IntPtr]$Handle
    )
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object -TypeName VirtDisk+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = 1
    
    $result = [VirtDisk]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        1,
        0,
        [ref]$attachParams,
        [IntPtr]::Zero
    )
    
    if ($result -ne 0) {
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
        throw "AttachVirtualDisk failed: $($win32Err.Message) (0x$($result.ToString('X8')))"
    }
    
    $pathSizeBytes = 520
    $pathBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pathSizeBytes)
    
    try {
        $result = [VirtDisk]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSizeBytes, $pathBuffer)
        
        if ($result -ne 0) {
            $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
            throw "GetVirtualDiskPhysicalPath failed: $($win32Err.Message)"
        }
        
        $physicalPath = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pathBuffer)
        return $physicalPath
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathBuffer)
    }
}

function Dismount-RawVHDX {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [IntPtr]$Handle
    )
    
    if ($Handle -eq [IntPtr]::Zero) {
        return
    }
    
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    
    $result = [VirtDisk]::DetachVirtualDisk($Handle, 0, 0)
    if ($result -ne 0) {
        Write-Warning "DetachVirtualDisk returned error: $result"
    }
    
    $null = [VirtDisk]::CloseHandle($Handle)
}

# ============================================================
# Part 5: Volume Bitmap Functions
# ============================================================

function Get-NtfsVolumeData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDisk]::CreateFile(
        $volumePath,
        [NativeDisk]::GENERIC_READ,
        ([NativeDisk]::FILE_SHARE_READ -bor [NativeDisk]::FILE_SHARE_WRITE),
        [IntPtr]::Zero,
        [NativeDisk]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
        throw "Failed to open volume $volumePath : $($win32Err.Message)"
    }
    
    try {
        $bufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][NativeDisk+NTFS_VOLUME_DATA_BUFFER])
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
        
        try {
            $bytesReturned = [uint32]0
            $success = [NativeDisk]::DeviceIoControl(
                $handle,
                [NativeDisk]::FSCTL_GET_NTFS_VOLUME_DATA,
                [IntPtr]::Zero,
                0,
                $buffer,
                [uint32]$bufferSize,
                [ref]$bytesReturned,
                [IntPtr]::Zero
            )
            
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
                throw "FSCTL_GET_NTFS_VOLUME_DATA failed: $($win32Err.Message)"
            }
            
            $volumeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $buffer, 
                [type][NativeDisk+NTFS_VOLUME_DATA_BUFFER]
            )
            
            return @{
                TotalClusters   = $volumeData.TotalClusters
                FreeClusters    = $volumeData.FreeClusters
                BytesPerCluster = $volumeData.BytesPerCluster
                BytesPerSector  = $volumeData.BytesPerSector
            }
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }
    finally {
        $handle.Close()
    }
}

function Get-VolumeBitmap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter,
        
        [Parameter(Mandatory = $true)]
        [long]$TotalClusters
    )
    
    Write-Host "Reading volume allocation bitmap..." -ForegroundColor Cyan
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDisk]::CreateFile(
        $volumePath,
        [NativeDisk]::GENERIC_READ,
        ([NativeDisk]::FILE_SHARE_READ -bor [NativeDisk]::FILE_SHARE_WRITE),
        [IntPtr]::Zero,
        [NativeDisk]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
        throw "Failed to open volume: $($win32Err.Message)"
    }
    
    try {
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $fullBitmap = New-Object -TypeName byte[] -ArgumentList $bitmapBytes
        
        $startingLcn = [long]0
        $headerSize = 16
        $chunkSize = 1048576
        $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $inputBufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][NativeDisk+STARTING_LCN_INPUT_BUFFER])
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($inputBufferSize)
        $bitmapOffset = 0
        
        try {
            while ($startingLcn -lt $TotalClusters) {
                [System.Runtime.InteropServices.Marshal]::WriteInt64($inputBuffer, 0, $startingLcn)
                
                $bytesReturned = [uint32]0
                $success = [NativeDisk]::DeviceIoControl(
                    $handle,
                    [NativeDisk]::FSCTL_GET_VOLUME_BITMAP,
                    $inputBuffer,
                    [uint32]$inputBufferSize,
                    $outputBuffer,
                    [uint32]$chunkSize,
                    [ref]$bytesReturned,
                    [IntPtr]::Zero
                )
                
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($err -ne 234) {
                        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
                        throw "FSCTL_GET_VOLUME_BITMAP failed: $($win32Err.Message)"
                    }
                }
                
                $returnedStartLcn = [System.Runtime.InteropServices.Marshal]::ReadInt64($outputBuffer, 0)
                $bitmapSize = [System.Runtime.InteropServices.Marshal]::ReadInt64($outputBuffer, 8)
                
                $dataBytes = [int]($bytesReturned - $headerSize)
                if ($dataBytes -gt 0) {
                    $copyLen = [math]::Min($dataBytes, $fullBitmap.Length - $bitmapOffset)
                    if ($copyLen -gt 0) {
                        [System.Runtime.InteropServices.Marshal]::Copy(
                            [IntPtr]::Add($outputBuffer, $headerSize),
                            $fullBitmap,
                            $bitmapOffset,
                            $copyLen
                        )
                        $bitmapOffset += $copyLen
                    }
                }
                
                $clustersRead = [long]$dataBytes * 8
                if ($clustersRead -le 0) { break }
                $startingLcn += $clustersRead
                
                $pct = [math]::Min(100, [int](($startingLcn / $TotalClusters) * 100))
                Write-Progress -Activity "Reading Bitmap" -Status "$pct%" -PercentComplete $pct
            }
            
            Write-Progress -Activity "Reading Bitmap" -Completed
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outputBuffer)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($inputBuffer)
        }
        
        return $fullBitmap
    }
    finally {
        $handle.Close()
    }
}

function Get-AllocatedRanges {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bitmap,
        
        [Parameter(Mandatory = $true)]
        [long]$TotalClusters,
        
        [Parameter(Mandatory = $true)]
        [uint32]$BytesPerCluster,
        
        [int]$MinRunClusters = 256
    )
    
    Write-Host "Analyzing allocation bitmap..." -ForegroundColor Cyan
    
    $ranges = New-Object -TypeName System.Collections.ArrayList
    $currentStart = [long]-1
    $allocatedClusters = [long]0
    $progressInterval = [math]::Max(1, [int]($TotalClusters / 100))
    
    for ($cluster = [long]0; $cluster -lt $TotalClusters; $cluster++) {
        $byteIndex = [int][math]::Floor($cluster / 8)
        $bitIndex = [int]($cluster % 8)
        
        $isAllocated = ($Bitmap[$byteIndex] -band (1 -shl $bitIndex)) -ne 0
        
        if ($isAllocated) {
            if ($currentStart -eq -1) {
                $currentStart = $cluster
            }
            $allocatedClusters++
        }
        else {
            if ($currentStart -ne -1) {
                $null = $ranges.Add([PSCustomObject]@{
                    StartCluster = $currentStart
                    EndCluster   = $cluster - 1
                    ClusterCount = $cluster - $currentStart
                })
                $currentStart = -1
            }
        }
        
        if ($cluster % $progressInterval -eq 0) {
            $pct = [int](($cluster / $TotalClusters) * 100)
            Write-Progress -Activity "Analyzing Bitmap" -Status "$pct%" -PercentComplete $pct
        }
    }
    
    if ($currentStart -ne -1) {
        $null = $ranges.Add([PSCustomObject]@{
            StartCluster = $currentStart
            EndCluster   = $TotalClusters - 1
            ClusterCount = $TotalClusters - $currentStart
        })
    }
    
    Write-Progress -Activity "Analyzing Bitmap" -Completed
    
    Write-Host "Merging adjacent ranges (gap threshold: $MinRunClusters clusters)..." -ForegroundColor Cyan
    
    $mergedRanges = New-Object -TypeName System.Collections.ArrayList
    $prev = $null
    
    foreach ($range in $ranges) {
        if ($null -eq $prev) {
            $prev = $range
            continue
        }
        
        $gap = $range.StartCluster - $prev.EndCluster - 1
        if ($gap -le $MinRunClusters) {
            $prev = [PSCustomObject]@{
                StartCluster = $prev.StartCluster
                EndCluster   = $range.EndCluster
                ClusterCount = $range.EndCluster - $prev.StartCluster + 1
            }
        }
        else {
            $null = $mergedRanges.Add($prev)
            $prev = $range
        }
    }
    
    if ($null -ne $prev) {
        $null = $mergedRanges.Add($prev)
    }
    
    $totalBytes = [long]$TotalClusters * $BytesPerCluster
    $allocatedBytes = [long]$allocatedClusters * $BytesPerCluster
    $savingsPercent = [math]::Round((1 - ($allocatedBytes / $totalBytes)) * 100, 1)
    
    Write-Host "  Total clusters: $TotalClusters ($([math]::Round($totalBytes/1GB, 2)) GB)" -ForegroundColor DarkGray
    Write-Host "  Allocated clusters: $allocatedClusters ($([math]::Round($allocatedBytes/1GB, 2)) GB)" -ForegroundColor DarkGray
    Write-Host "  Ranges before merge: $($ranges.Count)" -ForegroundColor DarkGray
    Write-Host "  Ranges after merge: $($mergedRanges.Count)" -ForegroundColor DarkGray
    Write-Host "  Space savings: $savingsPercent%" -ForegroundColor Green
    
    return @{
        Ranges            = $mergedRanges
        AllocatedClusters = $allocatedClusters
        AllocatedBytes    = $allocatedBytes
    }
}

# ============================================================
# Part 6: Raw Disk I/O
# ============================================================

function Open-RawDisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Read', 'Write', 'ReadWrite')]
        [string]$Access
    )
    
    $accessFlags = switch ($Access) {
        'Read'      { [NativeDisk]::GENERIC_READ }
        'Write'     { [NativeDisk]::GENERIC_WRITE }
        'ReadWrite' { [NativeDisk]::GENERIC_READ -bor [NativeDisk]::GENERIC_WRITE }
    }
    
    $shareMode = [NativeDisk]::FILE_SHARE_READ -bor [NativeDisk]::FILE_SHARE_WRITE
    $flags = [NativeDisk]::FILE_FLAG_NO_BUFFERING -bor [NativeDisk]::FILE_FLAG_WRITE_THROUGH
    
    $handle = [NativeDisk]::CreateFile(
        $Path,
        $accessFlags,
        $shareMode,
        [IntPtr]::Zero,
        [NativeDisk]::OPEN_EXISTING,
        $flags,
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
        throw "Failed to open $Path : $($win32Err.Message)"
    }
    
    return $handle
}

# ============================================================
# Part 7: Block Copy Functions
# ============================================================

function Copy-AllocatedBlocks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Ranges,
        
        [Parameter(Mandatory = $true)]
        [uint32]$BytesPerCluster,
        
        [Parameter(Mandatory = $true)]
        [long]$AllocatedBytes,
        
        [int]$BlockSize = 4194304
    )
    
    if ($BlockSize % $BytesPerCluster -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $BytesPerCluster) * $BytesPerCluster)
    }
    
    $clustersPerBlock = [long]($BlockSize / $BytesPerCluster)
    
    Write-Host "Copying $([math]::Round($AllocatedBytes/1GB, 2)) GB of allocated data..." -ForegroundColor Cyan
    Write-Host "  Block size: $($BlockSize / 1MB) MB ($clustersPerBlock clusters)" -ForegroundColor DarkGray
    
    $sourceHandle = $null
    $destHandle = $null
    
    try {
        $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
        $destHandle = Open-RawDisk -Path $DestinationPath -Access Write
        
        $buffer = New-Object -TypeName byte[] -ArgumentList $BlockSize
        $totalCopied = [long]0
        $stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
        $stopwatch.Start()
        $lastProgressPercent = -1
        
        foreach ($range in $Ranges) {
            $clusterOffset = [long]$range.StartCluster
            $clustersRemaining = [long]$range.ClusterCount
            
            while ($clustersRemaining -gt 0) {
                $clustersToRead = [math]::Min($clustersPerBlock, $clustersRemaining)
                $bytesToRead = [uint32]($clustersToRead * $BytesPerCluster)
                $byteOffset = [long]$clusterOffset * $BytesPerCluster
                
                $newPos = [long]0
                $success = [NativeDisk]::SetFilePointerEx($sourceHandle, $byteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Source seek failed at offset $byteOffset. Error: $err"
                }
                
                $bytesRead = [uint32]0
                $success = [NativeDisk]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Read failed at cluster $clusterOffset. Error: $err"
                }
                
                $success = [NativeDisk]::SetFilePointerEx($destHandle, $byteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Destination seek failed at offset $byteOffset. Error: $err"
                }
                
                $bytesWritten = [uint32]0
                $success = [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Write failed at cluster $clusterOffset. Error: $err"
                }
                
                $totalCopied += $bytesRead
                $clusterOffset += $clustersToRead
                $clustersRemaining -= $clustersToRead
                
                $progressPercent = [math]::Floor(($totalCopied / $AllocatedBytes) * 100)
                if ($progressPercent -gt $lastProgressPercent) {
                    $elapsed = $stopwatch.Elapsed.TotalSeconds
                    $speed = if ($elapsed -gt 0) { $totalCopied / $elapsed / 1MB } else { 0 }
                    $remaining = if ($speed -gt 0) { ($AllocatedBytes - $totalCopied) / 1MB / $speed } else { 0 }
                    
                    Write-Progress -Activity "Cloning Allocated Blocks" `
                        -Status "$progressPercent% - $([math]::Round($speed, 1)) MB/s - ETA: $([math]::Round($remaining/60, 1)) min" `
                        -PercentComplete $progressPercent
                    $lastProgressPercent = $progressPercent
                }
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Cloning Allocated Blocks" -Completed
        
        $avgSpeed = $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if ($null -ne $sourceHandle -and -not $sourceHandle.IsClosed) { 
            $sourceHandle.Close() 
        }
        if ($null -ne $destHandle -and -not $destHandle.IsClosed) { 
            $destHandle.Close() 
        }
    }
}

function Copy-VolumeBlocksFull {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $true)]
        [uint64]$TotalBytes,
        
        [int]$BlockSize = 4194304
    )
    
    Write-Host "Performing full sector copy of $([math]::Round($TotalBytes/1GB, 2)) GB..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DestinationPath -Access Write
    
    try {
        $buffer = New-Object -TypeName byte[] -ArgumentList $BlockSize
        $totalCopied = [uint64]0
        $stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
        $stopwatch.Start()
        $lastPct = -1
        
        while ($totalCopied -lt $TotalBytes) {
            $bytesToRead = [uint32][Math]::Min($BlockSize, $TotalBytes - $totalCopied)
            $alignedBytes = [uint32]([math]::Ceiling($bytesToRead / 4096) * 4096)
            
            $bytesRead = [uint32]0
            $success = [NativeDisk]::ReadFile($sourceHandle, $buffer, $alignedBytes, [ref]$bytesRead, [IntPtr]::Zero)
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Read failed at offset $totalCopied. Error: $err"
            }
            
            if ($bytesRead -eq 0) { break }
            
            $bytesWritten = [uint32]0
            $success = [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Write failed at offset $totalCopied. Error: $err"
            }
            
            $totalCopied += $bytesRead
            
            $pct = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($pct -gt $lastPct) {
                $speed = $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB
                Write-Progress -Activity "Full Clone" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                $lastPct = $pct
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Full Clone" -Completed
        
        $avgSpeed = $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if (-not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if (-not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

# ============================================================
# Part 8: Main Clone Function
# ============================================================

function New-LiveVolumeClone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceVolume,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationVHDX,
        
        [switch]$FullCopy,
        
        [switch]$FixedSizeVHDX,
        
        [ValidateRange(1, 64)]
        [int]$BlockSizeMB = 4
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    
    try {
        $driveLetter = $SourceVolume.TrimEnd(':', '\').ToUpper()
        
        $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
        $partitionSize = $partition.Size
        
        $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        if ($volume.FileSystemType -ne 'NTFS' -and -not $FullCopy) {
            Write-Warning "Volume is $($volume.FileSystemType), not NTFS. Forcing full copy mode."
            $FullCopy = $true
        }
        
        Write-Host ""
        Write-Host "=== Live Volume Clone ===" -ForegroundColor Yellow
        Write-Host "Source: ${driveLetter}:" -ForegroundColor White
        Write-Host "Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "Partition Size: $([math]::Round($partitionSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "File System: $($volume.FileSystemType)" -ForegroundColor White
        Write-Host "Mode: $(if ($FullCopy) { 'Full Copy' } else { 'Skip Free Space' })" -ForegroundColor White
        Write-Host "VHDX Type: $(if ($FixedSizeVHDX) { 'Fixed' } else { 'Dynamic' })" -ForegroundColor White
        Write-Host ""
        
        $volumeData = $null
        if (-not $FullCopy) {
            $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
            Write-Host "Cluster size: $($volumeData.BytesPerCluster) bytes" -ForegroundColor DarkGray
            Write-Host "Total clusters: $($volumeData.TotalClusters)" -ForegroundColor DarkGray
            Write-Host "Free clusters: $($volumeData.FreeClusters)" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        $vhdxSize = [uint64]([math]::Ceiling($partitionSize / 1MB) * 1MB)
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle
        Write-Host "VHDX attached at: $physicalPath" -ForegroundColor Green
        Write-Host ""
        
        Start-Sleep -Seconds 3
        
        $blockSizeBytes = $BlockSizeMB * 1MB
        
        if ($FullCopy) {
            Copy-VolumeBlocksFull `
                -SourcePath $snapshot.DeviceObject `
                -DestinationPath $physicalPath `
                -TotalBytes $partitionSize `
                -BlockSize $blockSizeBytes
        }
        else {
            $bitmap = Get-VolumeBitmap -DriveLetter $driveLetter -TotalClusters $volumeData.TotalClusters
            
            $allocation = Get-AllocatedRanges `
                -Bitmap $bitmap `
                -TotalClusters $volumeData.TotalClusters `
                -BytesPerCluster $volumeData.BytesPerCluster `
                -MinRunClusters 256
            
            Write-Host ""
            
            Copy-AllocatedBlocks `
                -SourcePath $snapshot.DeviceObject `
                -DestinationPath $physicalPath `
                -Ranges $allocation.Ranges `
                -BytesPerCluster $volumeData.BytesPerCluster `
                -AllocatedBytes $allocation.AllocatedBytes `
                -BlockSize $blockSizeBytes
        }
        
        Write-Host ""
        Write-Host "=== Clone Complete ===" -ForegroundColor Yellow
        Write-Host "VHDX saved to: $DestinationVHDX" -ForegroundColor Green
        
        $vhdxFile = Get-Item -LiteralPath $DestinationVHDX
        Write-Host "VHDX file size: $([math]::Round($vhdxFile.Length/1GB, 2)) GB" -ForegroundColor Cyan
        
        return $DestinationVHDX
    }
    catch {
        Write-Error "Clone failed: $_"
        
        if ($vhdHandle -ne [IntPtr]::Zero) {
            try { Dismount-RawVHDX -Handle $vhdHandle } catch { }
            $vhdHandle = [IntPtr]::Zero
        }
        
        if (Test-Path -LiteralPath $DestinationVHDX -ErrorAction SilentlyContinue) {
            Write-Host "Cleaning up partial VHDX..." -ForegroundColor Yellow
            Remove-Item -LiteralPath $DestinationVHDX -Force -ErrorAction SilentlyContinue
        }
        
        throw
    }
    finally {
        if ($vhdHandle -ne [IntPtr]::Zero) {
            Dismount-RawVHDX -Handle $vhdHandle
        }
        
        if ($null -ne $snapshot) {
            Remove-VssSnapshot -ShadowId $snapshot.Id
        }
    }
}

# ============================================================
# Script Entry Point
# ============================================================

$runInteractive = $false

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    $runInteractive = $true
}
elseif (-not $SourceVolume -and -not $DestinationVHDX) {
    $runInteractive = $true
}

if ($runInteractive) {
    Start-InteractiveMode
}
else {
    if (-not $SourceVolume) {
        throw "SourceVolume is required in command-line mode. Use -Interactive for menu mode."
    }
    if (-not $DestinationVHDX) {
        throw "DestinationVHDX is required in command-line mode. Use -Interactive for menu mode."
    }
    
    New-LiveVolumeClone `
        -SourceVolume $SourceVolume `
        -DestinationVHDX $DestinationVHDX `
        -FullCopy:$FullCopy `
        -FixedSizeVHDX:$FixedSizeVHDX `
        -BlockSizeMB $BlockSizeMB
}
