#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a live Windows volume to a bootable VHDX file.
.DESCRIPTION
    Creates a VSS snapshot of a running Windows volume and copies it to a bootable
    VHDX virtual disk using the Windows virtdisk.dll API (no Hyper-V module required).
    The resulting VHDX can be used in Hyper-V or for Native VHD Boot.
    
    IMPORTANT: If you get "PtrToStructure" errors, close PowerShell completely
    and open a new window. This happens when types are cached from previous runs.
.PARAMETER SourceVolume
    The drive letter of the volume to clone (e.g., "C" or "C:")
.PARAMETER DestinationVHDX
    The full path for the output VHDX file
.PARAMETER BootMode
    Boot mode: UEFI (GPT) or BIOS (MBR). Default is UEFI.
.PARAMETER FullCopy
    Copy entire partition instead of only allocated clusters
.PARAMETER FixedSizeVHDX
    Create a fixed-size VHDX instead of dynamic
.PARAMETER BlockSizeMB
    Block size for copy operations in MB (1-64). Default is 4.
.PARAMETER SkipBootFix
    Skip boot file installation (bcdboot)
.EXAMPLE
    .\BootableVolumeClone.ps1
    Runs in interactive mode with menu-driven interface
.EXAMPLE
    .\BootableVolumeClone.ps1 -SourceVolume C -DestinationVHDX D:\VMs\Clone.vhdx
    Clone C: drive to specified VHDX with default options
.EXAMPLE
    .\BootableVolumeClone.ps1 -SourceVolume C -DestinationVHDX D:\Clone.vhdx -BootMode BIOS -FullCopy
    Clone with BIOS boot mode and full sector copy
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'CommandLine')]
    [string]$SourceVolume,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [string]$DestinationVHDX,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [ValidateSet('UEFI', 'BIOS')]
    [string]$BootMode = 'UEFI',
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [switch]$FullCopy,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [switch]$FixedSizeVHDX,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [ValidateRange(1, 64)]
    [int]$BlockSizeMB = 4,
    
    [Parameter(ParameterSetName = 'CommandLine')]
    [switch]$SkipBootFix,
    
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive
)

# ============================================================
# Initialization
# ============================================================

$ErrorActionPreference = 'Stop'

try {
    if ($null -ne [Console]::OutputEncoding) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
}
catch { }

$currentPrincipal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires Administrator privileges."
}

# ============================================================
# Helper Functions
# ============================================================

function Get-SafeCount {
    param([object]$Collection)
    return [int]($Collection | Measure-Object).Count
}

function Wait-KeyPress {
    param([string]$Message = "Press any key to continue...")
    
    Write-Host "  $Message" -ForegroundColor Gray
    
    try {
        if ($Host.Name -eq 'ConsoleHost') {
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        else {
            Read-Host
        }
    }
    catch {
        Read-Host
    }
}

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return "$([math]::Round($Bytes / 1TB, 2)) TB" }
    if ($Bytes -ge 1GB) { return "$([math]::Round($Bytes / 1GB, 2)) GB" }
    if ($Bytes -ge 1MB) { return "$([math]::Round($Bytes / 1MB, 2)) MB" }
    return "$([math]::Round($Bytes / 1KB, 2)) KB"
}

function Test-DestinationSpace {
    param([string]$DestPath, [uint64]$RequiredBytes)
    
    $parentDir = Split-Path $DestPath -Parent
    if (-not $parentDir) { $parentDir = $DestPath }
    
    if ($parentDir -match '^([A-Za-z]):') {
        $driveLetter = $Matches[1]
        $destVolume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
        if ($destVolume) {
            if ($destVolume.SizeRemaining -lt $RequiredBytes) {
                throw "Insufficient space on ${driveLetter}: drive. Required: $(Format-Size $RequiredBytes), Available: $(Format-Size $destVolume.SizeRemaining)"
            }
            Write-Host "  Destination space: $(Format-Size $destVolume.SizeRemaining) available, ~$(Format-Size $RequiredBytes) needed" -ForegroundColor DarkGray
            return $true
        }
    }
    
    Write-Warning "Could not verify destination space"
    return $true
}

function Get-AvailableDriveLetter {
    param([array]$Exclude = @())
    
    $used = @()
    Get-Volume | ForEach-Object { if ($_.DriveLetter) { $used += $_.DriveLetter } }
    $used += $Exclude
    
    foreach ($letter in 'S','T','U','V','W','X','Y','Z','N','O','P','Q','R','M','L','K','J','I','H','G','F','E') {
        if ($letter -notin $used -and -not (Test-Path -LiteralPath "${letter}:\")) {
            return $letter
        }
    }
    return $null
}

# ============================================================
# P/Invoke Definitions
# ============================================================

$nativeCodeDefinition = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VirtDiskApi
{
    public const uint VIRTUAL_DISK_ACCESS_ALL = 0x003f0000;
    
    public const uint CREATE_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION = 1;
    
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 1;
    
    public const uint OPEN_VIRTUAL_DISK_FLAG_NONE = 0;
    
    public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
    
    public static readonly Guid VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = 
        new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");
    
    [StructLayout(LayoutKind.Sequential)]
    public struct VIRTUAL_STORAGE_TYPE
    {
        public int DeviceId;
        public Guid VendorId;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct ATTACH_VIRTUAL_DISK_PARAMETERS
    {
        public int Version;
        public int Reserved;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct OPEN_VIRTUAL_DISK_PARAMETERS
    {
        public int Version;
        public int RWDepth;
    }
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE VirtualStorageType,
        string Path,
        uint VirtualDiskAccessMask,
        IntPtr SecurityDescriptor,
        uint Flags,
        uint ProviderSpecificFlags,
        IntPtr Parameters,
        IntPtr Overlapped,
        out IntPtr Handle);
    
    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int OpenVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE VirtualStorageType,
        string Path,
        uint VirtualDiskAccessMask,
        uint Flags,
        ref OPEN_VIRTUAL_DISK_PARAMETERS Parameters,
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

public static class NativeDiskApi
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

# Check if types already exist and are valid
$typesOK = $false
try {
    $null = [VirtDiskApi].Name
    $null = [NativeDiskApi].Name
    $null = [NativeDiskApi+NTFS_VOLUME_DATA_BUFFER].Name
    # Test that we can get the size (this fails if type cache is corrupted)
    $testSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
    if ($testSize -gt 0) { $typesOK = $true }
}
catch { }

if (-not $typesOK) {
    try {
        Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Host ""
        Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║  ERROR: Type loading failed due to cached types from previous run ║" -ForegroundColor Red
        Write-Host "╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "║                                                                   ║" -ForegroundColor Red
        Write-Host "║  SOLUTION: Close this PowerShell window completely and open       ║" -ForegroundColor Yellow
        Write-Host "║            a NEW PowerShell window (as Administrator).            ║" -ForegroundColor Yellow
        Write-Host "║                                                                   ║" -ForegroundColor Red
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        throw "Please restart PowerShell and try again. Error: $_"
    }
}

# ============================================================
# PowerShell Function to Create VHDX Parameters Buffer
# ============================================================

function New-CreateVirtualDiskParametersV1 {
    param(
        [Parameter(Mandatory)]
        [Guid]$UniqueId,
        
        [Parameter(Mandatory)]
        [uint64]$MaximumSize,
        
        [uint32]$BlockSizeInBytes = 0,
        
        [uint32]$SectorSizeInBytes = 512
    )
    
    # CREATE_VIRTUAL_DISK_PARAMETERS Version 1 layout (x64):
    # Offset 0:  Version (4 bytes) = 1
    # Offset 4:  UniqueId (16 bytes GUID)
    # Offset 20: [4 bytes padding to align MaximumSize to 8-byte boundary]
    # Offset 24: MaximumSize (8 bytes)
    # Offset 32: BlockSizeInBytes (4 bytes)
    # Offset 36: SectorSizeInBytes (4 bytes)
    # Offset 40: ParentPath (8 bytes pointer = IntPtr.Zero)
    # Offset 48: SourcePath (8 bytes pointer = IntPtr.Zero)
    # Total: 56 bytes
    
    $size = 56
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    
    # Zero out the entire buffer
    for ($i = 0; $i -lt $size; $i++) {
        [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, 0)
    }
    
    # Version = 1 at offset 0
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 1)
    
    # UniqueId at offset 4
    $guidBytes = $UniqueId.ToByteArray()
    [System.Runtime.InteropServices.Marshal]::Copy($guidBytes, 0, [IntPtr]::Add($ptr, 4), 16)
    
    # MaximumSize at offset 24
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, 24, [long]$MaximumSize)
    
    # BlockSizeInBytes at offset 32
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 32, [int]$BlockSizeInBytes)
    
    # SectorSizeInBytes at offset 36
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 36, [int]$SectorSizeInBytes)
    
    # ParentPath and SourcePath at offsets 40 and 48 are already zero (null pointers)
    
    return $ptr
}

function Remove-CreateVirtualDiskParameters {
    param([IntPtr]$Ptr)
    
    if ($Ptr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Ptr)
    }
}

# ============================================================
# Interactive Menu Functions
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║        " -ForegroundColor Cyan -NoNewline
    Write-Host "BOOTABLE VOLUME CLONE UTILITY" -ForegroundColor Yellow -NoNewline
    Write-Host "                      ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║   Clone a running Windows volume to a bootable VHDX file    ║" -ForegroundColor Cyan
    Write-Host "  ║   Supports Hyper-V VMs and Native VHD Boot                  ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ║   Uses virtdisk.dll - No Hyper-V module required            ║" -ForegroundColor Cyan
    Write-Host "  ║                                                              ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-VolumeList {
    @(Get-Volume | Where-Object { 
        $_.DriveLetter -and 
        $_.DriveType -eq 'Fixed' -and
        $_.Size -gt 0
    } | Sort-Object DriveLetter)
}

function Show-VolumeMenu {
    param([array]$Volumes)
    
    Write-Host "  Available Volumes:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    $index = 1
    foreach ($vol in $Volumes) {
        $sizeGB = [math]::Round($vol.Size / 1GB, 2)
        $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
        $usedPct = if ($vol.Size -gt 0) { [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 0) } else { 0 }
        $label = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Local Disk" }
        
        # Create progress bar
        $barLength = 20
        $filledLength = [math]::Min($barLength, [math]::Max(0, [math]::Round(($usedPct / 100) * $barLength)))
        $emptyLength = $barLength - $filledLength
        
        $filledBar = ""
        $emptyBar = ""
        if ($filledLength -gt 0) { $filledBar = [string]::new([char]0x2588, $filledLength) }
        if ($emptyLength -gt 0) { $emptyBar = [string]::new([char]0x2591, $emptyLength) }
        $progressBar = "[$filledBar$emptyBar]"
        
        Write-Host "    [$index] " -ForegroundColor Yellow -NoNewline
        Write-Host "$($vol.DriveLetter):" -ForegroundColor White -NoNewline
        Write-Host " $label" -ForegroundColor Gray
        Write-Host "        $progressBar " -ForegroundColor DarkCyan -NoNewline
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
    param([string]$Prompt, [int]$Min, [int]$Max, [string]$Default = "")
    
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
        if ([string]::IsNullOrWhiteSpace($userInput) -and $Default) { $userInput = $Default }
        
        $num = 0
        if ([int]::TryParse($userInput, [ref]$num) -and $num -ge $Min -and $num -le $Max) {
            return $num
        }
        
        Write-Host "  Please enter a number between $Min and $Max" -ForegroundColor Red
        Write-Host ""
    }
}

function Read-PathInput {
    param([string]$Prompt, [string]$Default = "", [string]$RequiredExtension = "")
    
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
        if ([string]::IsNullOrWhiteSpace($userInput) -and $Default) { $userInput = $Default }
        
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
    param([string]$Prompt, [bool]$Default = $false)
    
    $defaultStr = if ($Default) { "Y/n" } else { "y/N" }
    Write-Host "  $Prompt " -ForegroundColor White -NoNewline
    Write-Host "[$defaultStr]" -ForegroundColor DarkGray -NoNewline
    Write-Host ": " -ForegroundColor White -NoNewline
    
    $userInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($userInput)) { return $Default }
    return $userInput.Trim().ToLower() -in @('y', 'yes', '1', 'true')
}

# ============================================================
# VSS Functions
# ============================================================

function New-VssSnapshot {
    param([string]$Volume)
    
    if (-not $Volume.EndsWith('\')) { $Volume = $Volume + '\' }
    
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume  = $Volume
        Context = 'ClientAccessible'
    }
    
    if ($result.ReturnValue -ne 0) {
        $errorMessages = @{
            1='Access denied'; 2='Invalid argument'; 3='Volume not found'
            4='Volume not supported'; 5='Unsupported context'; 6='Insufficient storage'
            7='Volume in use'; 8='Max shadow copies reached'; 9='Operation in progress'
            10='Provider vetoed'; 11='Provider not registered'; 12='Provider failure'
        }
        $msg = $errorMessages[[int]$result.ReturnValue]
        if (-not $msg) { $msg = "Unknown error" }
        throw "Failed to create shadow copy. Error $($result.ReturnValue): $msg"
    }
    
    $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
    if (-not $shadowCopy) { throw "Shadow copy created but could not be retrieved." }
    
    return @{
        Id           = $result.ShadowID
        DeviceObject = $shadowCopy.DeviceObject
        VolumeName   = $Volume
    }
}

function Remove-VssSnapshot {
    param([string]$ShadowId)
    
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    $shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) { Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue }
}

# ============================================================
# Virtual Disk Functions (virtdisk.dll - no Hyper-V required)
# ============================================================

function New-RawVHDX {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [uint64]$SizeBytes,
        
        [switch]$FixedSize
    )
    
    $typeStr = if ($FixedSize) { "Fixed" } else { "Dynamic" }
    Write-Host "Creating $typeStr VHDX: $Path ($(Format-Size $SizeBytes))..." -ForegroundColor Cyan
    
    # Ensure directory exists
    $parentDir = Split-Path -Path $Path -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        $null = New-Item -Path $parentDir -ItemType Directory -Force
    }
    
    # Remove existing file
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
    
    # Align size to MB boundary
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    
    Write-Host "  Using VirtDisk API (virtdisk.dll)..." -ForegroundColor DarkGray
    
    $storageType = New-Object -TypeName VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    # Create parameters using PowerShell function
    $uniqueId = [Guid]::NewGuid()
    $paramsPtr = New-CreateVirtualDiskParametersV1 -UniqueId $uniqueId -MaximumSize $SizeBytes -BlockSizeInBytes 0 -SectorSizeInBytes 512
    
    try {
        $flags = if ($FixedSize) { 
            [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION 
        } 
        else { 
            [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_NONE 
        }
        
        $handle = [IntPtr]::Zero
        $result = [VirtDiskApi]::CreateVirtualDisk(
            [ref]$storageType,
            $Path,
            [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL,
            [IntPtr]::Zero,
            $flags,
            0,
            $paramsPtr,
            [IntPtr]::Zero,
            [ref]$handle
        )
        
        if ($result -ne 0) {
            $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
            throw "CreateVirtualDisk failed: $($win32Err.Message) (Error: $result)"
        }
        
        Write-Host "  VHDX created successfully" -ForegroundColor Green
        return $handle
    }
    finally {
        Remove-CreateVirtualDiskParameters -Ptr $paramsPtr
    }
}

function Mount-RawVHDX {
    param([IntPtr]$Handle, [switch]$WithDriveLetter)
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object -TypeName VirtDiskApi+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = 1
    
    $flags = if ($WithDriveLetter) { [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NONE } 
             else { [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER }
    
    $result = [VirtDiskApi]::AttachVirtualDisk($Handle, [IntPtr]::Zero, $flags, 0, [ref]$attachParams, [IntPtr]::Zero)
    
    if ($result -ne 0) {
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
        throw "AttachVirtualDisk failed: $($win32Err.Message)"
    }
    
    $pathSizeBytes = 520
    $pathBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pathSizeBytes)
    
    try {
        $result = [VirtDiskApi]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSizeBytes, $pathBuffer)
        if ($result -ne 0) {
            $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
            throw "GetVirtualDiskPhysicalPath failed: $($win32Err.Message)"
        }
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pathBuffer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathBuffer)
    }
}

function Dismount-RawVHDX {
    param([IntPtr]$Handle)
    
    if ($Handle -eq [IntPtr]::Zero) { return }
    
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    $null = [VirtDiskApi]::DetachVirtualDisk($Handle, 0, 0)
    $null = [VirtDiskApi]::CloseHandle($Handle)
}

# ============================================================
# Disk Initialization and Partitioning
# ============================================================

function Initialize-BootableVHDX {
    param(
        [string]$PhysicalPath,
        [ValidateSet('UEFI', 'BIOS')][string]$BootMode,
        [uint64]$WindowsPartitionSize
    )
    
    Write-Host "Initializing disk structure for $BootMode boot..." -ForegroundColor Cyan
    
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') {
        $diskNumber = [int]$Matches[1]
    }
    else {
        throw "Could not determine disk number from path: $PhysicalPath"
    }
    
    # Wait for disk to appear
    $retries = 20
    $disk = $null
    while ($retries -gt 0 -and -not $disk) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
        $retries--
    }
    
    if (-not $disk) { throw "Could not find disk $diskNumber" }
    
    Write-Host "  Disk $diskNumber found: $(Format-Size $disk.Size)" -ForegroundColor DarkGray
    
    if ($BootMode -eq 'UEFI') {
        Write-Host "  Initializing as GPT..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating EFI System Partition (260 MB)..." -ForegroundColor DarkGray
        $espPartition = New-Partition -DiskNumber $diskNumber -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        Format-Volume -Partition $espPartition -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false | Out-Null
        
        Write-Host "  Creating Microsoft Reserved Partition (16 MB)..." -ForegroundColor DarkGray
        $null = New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $winPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
        
        return @{ DiskNumber = $diskNumber; EspPartition = $espPartition; WindowsPartition = $winPartition; BootMode = 'UEFI' }
    }
    else {
        Write-Host "  Initializing as MBR..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle MBR -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating System Reserved partition (500 MB)..." -ForegroundColor DarkGray
        $sysPartition = New-Partition -DiskNumber $diskNumber -Size 500MB -IsActive
        Format-Volume -Partition $sysPartition -FileSystem NTFS -NewFileSystemLabel "System Reserved" -Confirm:$false | Out-Null
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $winPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize
        
        return @{ DiskNumber = $diskNumber; SystemPartition = $sysPartition; WindowsPartition = $winPartition; BootMode = 'BIOS' }
    }
}

function Install-BootFiles {
    param([hashtable]$DiskInfo, [string]$WindowsDriveLetter)
    
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $windowsPath = "${WindowsDriveLetter}:\Windows"
    if (-not (Test-Path -LiteralPath $windowsPath)) {
        throw "Windows directory not found at $windowsPath"
    }
    
    if ($DiskInfo.BootMode -eq 'UEFI') {
        $espLetter = Get-AvailableDriveLetter -Exclude @($WindowsDriveLetter)
        if (-not $espLetter) { throw "No available drive letters for ESP" }
        
        Write-Host "  Assigning drive letter $espLetter to ESP..." -ForegroundColor DarkGray
        $DiskInfo.EspPartition | Set-Partition -NewDriveLetter $espLetter
        Start-Sleep -Seconds 2
        
        try {
            Write-Host "  Running bcdboot for UEFI..." -ForegroundColor DarkGray
            $bcdbootOutput = & bcdboot.exe "$windowsPath" /s "${espLetter}:" /f UEFI 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "bcdboot failed: $bcdbootOutput"
            }
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            try { $DiskInfo.EspPartition | Remove-PartitionAccessPath -AccessPath "${espLetter}:\" -ErrorAction SilentlyContinue } catch { }
        }
    }
    else {
        $sysLetter = Get-AvailableDriveLetter -Exclude @($WindowsDriveLetter)
        if (-not $sysLetter) { throw "No available drive letters for System partition" }
        
        Write-Host "  Assigning drive letter $sysLetter to System partition..." -ForegroundColor DarkGray
        $DiskInfo.SystemPartition | Set-Partition -NewDriveLetter $sysLetter
        Start-Sleep -Seconds 2
        
        try {
            Write-Host "  Running bcdboot for BIOS..." -ForegroundColor DarkGray
            $bcdbootOutput = & bcdboot.exe "$windowsPath" /s "${sysLetter}:" /f BIOS 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "bcdboot failed: $bcdbootOutput"
            }
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            try { $DiskInfo.SystemPartition | Remove-PartitionAccessPath -AccessPath "${sysLetter}:\" -ErrorAction SilentlyContinue } catch { }
        }
    }
}

# ============================================================
# Volume Bitmap Functions
# ============================================================

function Get-NtfsVolumeData {
    param([string]$DriveLetter)
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDiskApi]::CreateFile($volumePath, [NativeDiskApi]::GENERIC_READ, 
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, [NativeDiskApi]::OPEN_EXISTING, 0, [IntPtr]::Zero)
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume: $(New-Object System.ComponentModel.Win32Exception $err)"
    }
    
    try {
        $bufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
        
        try {
            [uint32]$bytesReturned = 0
            $success = [NativeDiskApi]::DeviceIoControl($handle, [NativeDiskApi]::FSCTL_GET_NTFS_VOLUME_DATA,
                [IntPtr]::Zero, [uint32]0, $buffer, [uint32]$bufferSize, [ref]$bytesReturned, [IntPtr]::Zero)
            
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "FSCTL_GET_NTFS_VOLUME_DATA failed: $(New-Object System.ComponentModel.Win32Exception $err)"
            }
            
            $volumeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
            
            return @{
                TotalClusters   = $volumeData.TotalClusters
                FreeClusters    = $volumeData.FreeClusters
                BytesPerCluster = $volumeData.BytesPerCluster
                BytesPerSector  = $volumeData.BytesPerSector
            }
        }
        finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) }
    }
    finally { $handle.Close() }
}

function Get-VolumeBitmap {
    param([string]$DriveLetter, [long]$TotalClusters)
    
    Write-Host "Reading volume allocation bitmap..." -ForegroundColor Cyan
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDiskApi]::CreateFile($volumePath, [NativeDiskApi]::GENERIC_READ,
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, [NativeDiskApi]::OPEN_EXISTING, 0, [IntPtr]::Zero)
    
    if ($handle.IsInvalid) { throw "Failed to open volume" }
    
    try {
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $fullBitmap = New-Object byte[] $bitmapBytes
        
        $startingLcn = [long]0
        $headerSize = 16
        $chunkSize = 1048576  # 1 MB chunks
        $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        $bitmapOffset = 0
        
        try {
            while ($startingLcn -lt $TotalClusters) {
                [System.Runtime.InteropServices.Marshal]::WriteInt64($inputBuffer, 0, $startingLcn)
                
                $bytesReturned = [uint32]0
                $success = [NativeDiskApi]::DeviceIoControl($handle, [NativeDiskApi]::FSCTL_GET_VOLUME_BITMAP,
                    $inputBuffer, 8, $outputBuffer, [uint32]$chunkSize, [ref]$bytesReturned, [IntPtr]::Zero)
                
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($err -ne 234) { throw "FSCTL_GET_VOLUME_BITMAP failed: error $err" }
                }
                
                $dataBytes = [int]($bytesReturned - $headerSize)
                if ($dataBytes -gt 0) {
                    $copyLen = [math]::Min($dataBytes, $fullBitmap.Length - $bitmapOffset)
                    if ($copyLen -gt 0) {
                        [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($outputBuffer, $headerSize), $fullBitmap, $bitmapOffset, $copyLen)
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
    finally { $handle.Close() }
}

function Get-AllocatedRanges {
    param([byte[]]$Bitmap, [long]$TotalClusters, [uint32]$BytesPerCluster, [int]$MinRunClusters = 256)
    
    Write-Host "Analyzing allocation bitmap..." -ForegroundColor Cyan
    
    $ranges = New-Object System.Collections.ArrayList
    $currentStart = [long]-1
    $allocatedClusters = [long]0
    $totalBytes = [long][math]::Ceiling($TotalClusters / 8.0)
    $progressInterval = [math]::Max(1, [int]($totalBytes / 100))
    
    # Process byte by byte for better performance
    for ($byteIndex = [long]0; $byteIndex -lt $totalBytes; $byteIndex++) {
        $byte = $Bitmap[$byteIndex]
        $baseCluster = $byteIndex * 8
        
        if ($byte -eq 0xFF) {
            # All 8 clusters allocated
            $clustersInByte = [math]::Min(8, $TotalClusters - $baseCluster)
            if ($currentStart -eq -1) { $currentStart = $baseCluster }
            $allocatedClusters += $clustersInByte
        }
        elseif ($byte -eq 0) {
            # All 8 clusters free
            if ($currentStart -ne -1) {
                $null = $ranges.Add([PSCustomObject]@{ StartCluster = $currentStart; EndCluster = $baseCluster - 1; ClusterCount = $baseCluster - $currentStart })
                $currentStart = -1
            }
        }
        else {
            # Mixed - check individual bits
            for ($bit = 0; $bit -lt 8; $bit++) {
                $cluster = $baseCluster + $bit
                if ($cluster -ge $TotalClusters) { break }
                
                $isAllocated = ($byte -band (1 -shl $bit)) -ne 0
                if ($isAllocated) {
                    if ($currentStart -eq -1) { $currentStart = $cluster }
                    $allocatedClusters++
                }
                else {
                    if ($currentStart -ne -1) {
                        $null = $ranges.Add([PSCustomObject]@{ StartCluster = $currentStart; EndCluster = $cluster - 1; ClusterCount = $cluster - $currentStart })
                        $currentStart = -1
                    }
                }
            }
        }
        
        if ($byteIndex % $progressInterval -eq 0) {
            $pct = [int](($byteIndex / $totalBytes) * 100)
            Write-Progress -Activity "Analyzing Bitmap" -Status "$pct%" -PercentComplete $pct
        }
    }
    
    if ($currentStart -ne -1) {
        $null = $ranges.Add([PSCustomObject]@{ StartCluster = $currentStart; EndCluster = $TotalClusters - 1; ClusterCount = $TotalClusters - $currentStart })
    }
    Write-Progress -Activity "Analyzing Bitmap" -Completed
    
    # Merge adjacent/nearby ranges
    Write-Host "Merging adjacent ranges..." -ForegroundColor Cyan
    $mergedRanges = New-Object System.Collections.ArrayList
    $prev = $null
    
    foreach ($range in $ranges) {
        if ($null -eq $prev) { $prev = $range; continue }
        $gap = $range.StartCluster - $prev.EndCluster - 1
        if ($gap -le $MinRunClusters) {
            $prev = [PSCustomObject]@{ StartCluster = $prev.StartCluster; EndCluster = $range.EndCluster; ClusterCount = $range.EndCluster - $prev.StartCluster + 1 }
        }
        else {
            $null = $mergedRanges.Add($prev)
            $prev = $range
        }
    }
    if ($prev) { $null = $mergedRanges.Add($prev) }
    
    $totalVolumeBytes = [long]$TotalClusters * $BytesPerCluster
    $allocatedBytes = [long]$allocatedClusters * $BytesPerCluster
    Write-Host "  Allocated: $(Format-Size $allocatedBytes) of $(Format-Size $totalVolumeBytes) in $($mergedRanges.Count) ranges" -ForegroundColor DarkGray
    
    return @{ Ranges = $mergedRanges; AllocatedClusters = $allocatedClusters; AllocatedBytes = $allocatedBytes }
}

# ============================================================
# Raw Disk I/O
# ============================================================

function Open-RawDisk {
    param([string]$Path, [ValidateSet('Read', 'Write', 'ReadWrite')][string]$Access)
    
    $accessFlags = switch ($Access) {
        'Read' { [NativeDiskApi]::GENERIC_READ }
        'Write' { [NativeDiskApi]::GENERIC_WRITE }
        'ReadWrite' { [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE }
    }
    
    $handle = [NativeDiskApi]::CreateFile($Path, $accessFlags,
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, [NativeDiskApi]::OPEN_EXISTING,
        ([NativeDiskApi]::FILE_FLAG_NO_BUFFERING -bor [NativeDiskApi]::FILE_FLAG_WRITE_THROUGH),
        [IntPtr]::Zero)
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open $Path : $(New-Object System.ComponentModel.Win32Exception $err)"
    }
    
    return $handle
}

# ============================================================
# Block Copy Functions
# ============================================================

function Copy-VolumeToPartition {
    param([string]$SourcePath, [string]$DiskPath, [long]$PartitionOffset, [uint64]$TotalBytes, [int]$BlockSize = 4194304)
    
    Write-Host "Copying $(Format-Size $TotalBytes) to partition..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DiskPath -Access Write
    
    try {
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [uint64]0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        while ($totalCopied -lt $TotalBytes) {
            $alignedBytes = [uint32]([math]::Ceiling([Math]::Min($BlockSize, $TotalBytes - $totalCopied) / 4096) * 4096)
            
            $bytesRead = [uint32]0
            if (-not [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $alignedBytes, [ref]$bytesRead, [IntPtr]::Zero)) {
                $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $errMsg = (New-Object System.ComponentModel.Win32Exception($win32Err)).Message
                throw "Read failed at source offset $totalCopied. Attempted $alignedBytes bytes. Error $win32Err - $errMsg"
            }
            if ($bytesRead -eq 0) { break }
            
            $destOffset = $PartitionOffset + $totalCopied
            $newPos = [long]0
            if (-not [NativeDiskApi]::SetFilePointerEx($destHandle, $destOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)) {
                $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $errMsg = (New-Object System.ComponentModel.Win32Exception($win32Err)).Message
                throw "Seek failed to offset $destOffset. Error $win32Err - $errMsg"
            }
            
            $bytesWritten = [uint32]0
            if (-not [NativeDiskApi]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)) {
                $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $errMsg = (New-Object System.ComponentModel.Win32Exception($win32Err)).Message
                throw "Write failed at offset $destOffset. Tried $bytesRead bytes, wrote $bytesWritten. Error $win32Err - $errMsg"
            }
            
            $totalCopied += $bytesRead
            $pct = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($pct -gt $lastPct) {
                $speed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
                Write-Progress -Activity "Copying" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                $lastPct = $pct
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $(Format-Size $totalCopied) in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if (-not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if (-not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

function Copy-AllocatedBlocksToPartition {
    param([string]$SourcePath, [string]$DiskPath, [long]$PartitionOffset, [System.Collections.ArrayList]$Ranges, [uint32]$BytesPerCluster, [long]$AllocatedBytes, [int]$BlockSize = 4194304)
    
    if ($BlockSize % $BytesPerCluster -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $BytesPerCluster) * $BytesPerCluster)
    }
    $clustersPerBlock = [long]($BlockSize / $BytesPerCluster)
    
    Write-Host "Copying $(Format-Size $AllocatedBytes) of allocated data..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DiskPath -Access Write
    
    try {
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [long]0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        foreach ($range in $Ranges) {
            $clusterOffset = [long]$range.StartCluster
            $clustersRemaining = [long]$range.ClusterCount
            
            while ($clustersRemaining -gt 0) {
                $clustersToRead = [math]::Min($clustersPerBlock, $clustersRemaining)
                $bytesToRead = [uint32]($clustersToRead * $BytesPerCluster)
                $sourceByteOffset = [long]$clusterOffset * $BytesPerCluster
                
                $newPos = [long]0
                [NativeDiskApi]::SetFilePointerEx($sourceHandle, $sourceByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN) | Out-Null
                
                $bytesRead = [uint32]0
                if (-not [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)) {
                    $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $errMsg = (New-Object System.ComponentModel.Win32Exception($win32Err)).Message
                    throw "Read failed at offset $sourceByteOffset (cluster $clusterOffset). Tried $bytesToRead bytes. Error $win32Err - $errMsg"
                }
                
                $destByteOffset = $PartitionOffset + $sourceByteOffset
                [NativeDiskApi]::SetFilePointerEx($destHandle, $destByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN) | Out-Null
                
                $bytesWritten = [uint32]0
                if (-not [NativeDiskApi]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)) {
                    $win32Err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $errMsg = (New-Object System.ComponentModel.Win32Exception($win32Err)).Message
                    throw "Write failed at offset $destByteOffset (cluster $clusterOffset). Tried $bytesRead bytes, wrote $bytesWritten. Error $win32Err - $errMsg"
                }
                
                $totalCopied += $bytesRead
                $clusterOffset += $clustersToRead
                $clustersRemaining -= $clustersToRead
                
                $pct = [math]::Floor(($totalCopied / $AllocatedBytes) * 100)
                if ($pct -gt $lastPct) {
                    $speed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
                    Write-Progress -Activity "Copying" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $(Format-Size $totalCopied) in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if (-not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if (-not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

# ============================================================
# Main Clone Function
# ============================================================

function New-BootableVolumeClone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceVolume,
        [Parameter(Mandatory)][string]$DestinationVHDX,
        [ValidateSet('UEFI', 'BIOS')][string]$BootMode = 'UEFI',
        [switch]$FullCopy,
        [switch]$FixedSizeVHDX,
        [switch]$SkipBootFix,
        [int]$BlockSizeMB = 4
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    $windowsDriveLetter = $null
    $diskInfo = $null
    
    try {
        $driveLetter = $SourceVolume.TrimEnd(':', '\').ToUpper()
        $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
        $partitionSize = $partition.Size
        $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        $usedSpace = $volume.Size - $volume.SizeRemaining
        
        if ($volume.FileSystemType -ne 'NTFS' -and -not $FullCopy) {
            Write-Warning "Volume is $($volume.FileSystemType), not NTFS. Forcing full copy."
            $FullCopy = $true
        }
        
        $bootPartitionSize = if ($BootMode -eq 'UEFI') { 300MB } else { 550MB }
        $vhdxSize = [uint64]($partitionSize + $bootPartitionSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        # FIX: Calculate actual disk space needed based on USED space (not total partition size)
        if ($FixedSizeVHDX -or $FullCopy) {
            $requiredDiskSpace = $vhdxSize
        }
        else {
            # Dynamic VHDX with smart copy: used space + boot + overhead
            $requiredDiskSpace = [uint64](($usedSpace + $bootPartitionSize + 100MB) * 1.05)
        }
        
        # Check destination space
        Test-DestinationSpace -DestPath $DestinationVHDX -RequiredBytes $requiredDiskSpace
        
        Write-Host ""
        Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║                    BOOTABLE VOLUME CLONE                          ║" -ForegroundColor Yellow
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Source:      ${driveLetter}:" -ForegroundColor White
        Write-Host "  Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "  Used Space:  $(Format-Size $usedSpace)" -ForegroundColor White
        Write-Host "  VHDX Size:   $(Format-Size $vhdxSize) (virtual)" -ForegroundColor White
        Write-Host "  Disk Needed: ~$(Format-Size $requiredDiskSpace)" -ForegroundColor White
        Write-Host "  Boot Mode:   $BootMode" -ForegroundColor White
        Write-Host "  Copy Mode:   $(if ($FullCopy) { 'Full' } else { 'Smart (allocated blocks only)' })" -ForegroundColor White
        Write-Host ""
        
        $volumeData = $null
        if (-not $FullCopy) {
            $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
            Write-Host "  Cluster size: $($volumeData.BytesPerCluster) bytes" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        # Create VSS snapshot
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "  Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        # Create VHDX
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        # Attach VHDX
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle -WithDriveLetter
        Write-Host "  VHDX attached at: $physicalPath" -ForegroundColor Green
        
        # Wait for disk to be ready
        Start-Sleep -Seconds 3
        
        # Initialize disk
        $diskInfo = Initialize-BootableVHDX -PhysicalPath $physicalPath -BootMode $BootMode -WindowsPartitionSize $partitionSize
        
        Start-Sleep -Seconds 2
        
        $winPartition = $diskInfo.WindowsPartition
        $winPartitionOffset = $winPartition.Offset
        $diskPath = "\\.\PhysicalDrive$($diskInfo.DiskNumber)"
        
        Write-Host ""
        Write-Host "  Copying to partition at offset $winPartitionOffset..." -ForegroundColor Cyan
        Write-Host ""
        
        $blockSizeBytes = $BlockSizeMB * 1MB
        
        if ($FullCopy) {
            Copy-VolumeToPartition -SourcePath $snapshot.DeviceObject -DiskPath $diskPath -PartitionOffset $winPartitionOffset -TotalBytes $partitionSize -BlockSize $blockSizeBytes
        }
        else {
            $bitmap = Get-VolumeBitmap -DriveLetter $driveLetter -TotalClusters $volumeData.TotalClusters
            $allocation = Get-AllocatedRanges -Bitmap $bitmap -TotalClusters $volumeData.TotalClusters -BytesPerCluster $volumeData.BytesPerCluster -MinRunClusters 256
            Write-Host ""
            Copy-AllocatedBlocksToPartition -SourcePath $snapshot.DeviceObject -DiskPath $diskPath -PartitionOffset $winPartitionOffset -Ranges $allocation.Ranges -BytesPerCluster $volumeData.BytesPerCluster -AllocatedBytes $allocation.AllocatedBytes -BlockSize $blockSizeBytes
        }
        
        # Install boot files
        if (-not $SkipBootFix) {
            $windowsDriveLetter = Get-AvailableDriveLetter
            if (-not $windowsDriveLetter) { throw "No available drive letters" }
            
            Write-Host ""
            Write-Host "  Assigning drive letter $windowsDriveLetter to Windows partition..." -ForegroundColor Cyan
            $winPartition | Set-Partition -NewDriveLetter $windowsDriveLetter
            Start-Sleep -Seconds 2
            
            Install-BootFiles -DiskInfo $diskInfo -WindowsDriveLetter $windowsDriveLetter
            
            Write-Host "  Removing drive letter..." -ForegroundColor Cyan
            try { $winPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue } catch { }
            $windowsDriveLetter = $null
        }
        
        Write-Host ""
        Write-Host "╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                    CLONE COMPLETED SUCCESSFULLY                   ║" -ForegroundColor Green
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  VHDX File: $DestinationVHDX" -ForegroundColor White
        
        $vhdxFile = Get-Item -LiteralPath $DestinationVHDX
        Write-Host "  File Size: $(Format-Size $vhdxFile.Length)" -ForegroundColor Cyan
        Write-Host ""
        
        return $DestinationVHDX
    }
    catch {
        Write-Error "Clone failed: $_"
        
        # Cleanup on error
        if ($windowsDriveLetter -and $diskInfo) {
            try { $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue } catch { }
        }
        
        if ($vhdHandle -ne [IntPtr]::Zero) {
            try { Dismount-RawVHDX -Handle $vhdHandle } catch { }
            $vhdHandle = [IntPtr]::Zero
        }
        
        if (Test-Path -LiteralPath $DestinationVHDX -ErrorAction SilentlyContinue) {
            Write-Host "  Cleaning up partial VHDX file..." -ForegroundColor Yellow
            Remove-Item -LiteralPath $DestinationVHDX -Force -ErrorAction SilentlyContinue
        }
        
        throw
    }
    finally {
        if ($vhdHandle -ne [IntPtr]::Zero) { Dismount-RawVHDX -Handle $vhdHandle }
        if ($snapshot) { Remove-VssSnapshot -ShadowId $snapshot.Id }
    }
}

# ============================================================
# Interactive Mode
# ============================================================

function Start-InteractiveMode {
    $selectedVolume = $null
    $destinationPath = $null
    $optBootMode = 'UEFI'
    $optFullCopy = $false
    $optFixedSizeVHDX = $false
    $optBlockSizeMB = 4
    
    :volumeLoop while ($true) {
        Show-Banner
        
        $volumes = @(Get-VolumeList)
        $volumeCount = Get-SafeCount $volumes
        
        if ($volumeCount -eq 0) {
            Write-Host "  No suitable volumes found!" -ForegroundColor Red
            Wait-KeyPress
            return
        }
        
        Show-VolumeMenu -Volumes $volumes
        
        $selection = Read-MenuSelection -Prompt "Select volume to clone" -Min 0 -Max $volumeCount
        if ($selection -eq 0) { Write-Host "`n  Goodbye!" -ForegroundColor Cyan; return }
        
        $selectedVolume = $volumes[$selection - 1].DriveLetter
        $volumeInfo = $volumes[$selection - 1]
        
        # FIX: Calculate required space based on USED space, not total partition size
        $usedSpace = $volumeInfo.Size - $volumeInfo.SizeRemaining
        $requiredSpace = [uint64](($usedSpace + 600MB) * 1.1)  # Used space + boot partition + 10% buffer
        
        $defaultName = "Bootable_${selectedVolume}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        $destDrives = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne $selectedVolume -and $_.DriveType -eq 'Fixed' -and $_.SizeRemaining -gt $requiredSpace } | Sort-Object SizeRemaining -Descending)
        $defaultPath = if ((Get-SafeCount $destDrives) -gt 0) { "$($destDrives[0].DriveLetter):\VMs\$defaultName" } else { "${selectedVolume}:\VMs\$defaultName" }
        
        Write-Host ""
        $destinationPath = Read-PathInput -Prompt "Destination VHDX path" -Default $defaultPath -RequiredExtension ".vhdx"
        
        :optionsLoop while ($true) {
            Show-Banner
            $volumeLabel = if ($volumeInfo.FileSystemLabel) { $volumeInfo.FileSystemLabel } else { "Local Disk" }
            
            Write-Host "  Source: ${selectedVolume}: ($volumeLabel)" -ForegroundColor White
            Write-Host "  Destination: $destinationPath" -ForegroundColor White
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor White
            Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "    [1] Boot Mode:     $optBootMode" -ForegroundColor Yellow
            Write-Host "    [2] Copy Mode:     $(if ($optFullCopy) { 'Full (all sectors)' } else { 'Smart (allocated only)' })" -ForegroundColor Yellow
            Write-Host "    [3] VHDX Type:     $(if ($optFixedSizeVHDX) { 'Fixed' } else { 'Dynamic' })" -ForegroundColor Yellow
            Write-Host "    [4] Block Size:    $optBlockSizeMB MB" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    [S] Start Clone  [C] Change Path  [B] Back  [0] Exit" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Choice: " -ForegroundColor White -NoNewline
            
            switch ((Read-Host).ToUpper()) {
                "1" { $optBootMode = if ($optBootMode -eq 'UEFI') { 'BIOS' } else { 'UEFI' } }
                "2" { $optFullCopy = -not $optFullCopy }
                "3" { $optFixedSizeVHDX = -not $optFixedSizeVHDX }
                "4" {
                    Write-Host "  Enter block size (1-64 MB) [$optBlockSizeMB]: " -NoNewline
                    $inp = Read-Host
                    if ($inp -match '^\d+$' -and [int]$inp -ge 1 -and [int]$inp -le 64) { $optBlockSizeMB = [int]$inp }
                }
                "C" { Write-Host ""; $destinationPath = Read-PathInput -Prompt "New destination path" -Default $destinationPath -RequiredExtension ".vhdx" }
                "B" { continue volumeLoop }
                "S" {
                    if (Test-Path -LiteralPath $destinationPath) {
                        if (-not (Read-YesNo -Prompt "File exists. Overwrite?" -Default $false)) { continue }
                        Remove-Item -LiteralPath $destinationPath -Force
                    }
                    
                    if (Read-YesNo -Prompt "Start cloning now?" -Default $true) {
                        Write-Host ""
                        try {
                            New-BootableVolumeClone -SourceVolume $selectedVolume -DestinationVHDX $destinationPath -BootMode $optBootMode -FullCopy:$optFullCopy -FixedSizeVHDX:$optFixedSizeVHDX -BlockSizeMB $optBlockSizeMB
                        }
                        catch { 
                            Write-Host ""
                            Write-Host "  Clone failed: $_" -ForegroundColor Red 
                        }
                        
                        Write-Host ""
                        Wait-KeyPress
                        
                        if (-not (Read-YesNo -Prompt "Clone another volume?" -Default $false)) { return }
                        continue volumeLoop
                    }
                }
                "0" { Write-Host "`n  Goodbye!" -ForegroundColor Cyan; return }
            }
        }
    }
}

# ============================================================
# Entry Point
# ============================================================

if ($PSCmdlet.ParameterSetName -eq 'Interactive' -or (-not $SourceVolume -and -not $DestinationVHDX)) {
    Start-InteractiveMode
}
else {
    if (-not $SourceVolume -or -not $DestinationVHDX) {
        throw "SourceVolume and DestinationVHDX are required. Run without parameters for interactive mode."
    }
    
    New-BootableVolumeClone -SourceVolume $SourceVolume -DestinationVHDX $DestinationVHDX -BootMode $BootMode -FullCopy:$FullCopy -FixedSizeVHDX:$FixedSizeVHDX -SkipBootFix:$SkipBootFix -BlockSizeMB $BlockSizeMB
}
