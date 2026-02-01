#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a live Windows volume to a bootable VHDX file.
.DESCRIPTION
    Creates a VSS snapshot of a running Windows volume and copies it to a bootable
    VHDX virtual disk. The resulting VHDX can be used in Hyper-V or for Native VHD Boot.
    
    Supports both UEFI (GPT) and Legacy BIOS (MBR) boot modes.
    Supports skipping free space for faster clones (NTFS only).
.PARAMETER SourceVolume
    Drive letter of the Windows volume to clone (e.g., "C:" or "C")
.PARAMETER DestinationVHDX
    Path for the output VHDX file
.PARAMETER BootMode
    Boot mode: "UEFI" (default) or "BIOS"
.PARAMETER FullCopy
    Copy all sectors including free space (slower, larger file)
.PARAMETER FixedSizeVHDX
    Create a fixed-size VHDX instead of dynamic
.PARAMETER BlockSizeMB
    I/O block size in megabytes (default: 4)
.PARAMETER SkipBootFix
    Skip boot configuration (creates non-bootable raw clone)
.PARAMETER Interactive
    Force interactive menu mode
.EXAMPLE
    .\Clone-BootableVolume.ps1
    Runs in interactive menu mode
.EXAMPLE
    .\Clone-BootableVolume.ps1 -SourceVolume "C:" -DestinationVHDX "D:\VMs\Windows.vhdx"
.EXAMPLE
    .\Clone-BootableVolume.ps1 -SourceVolume "C:" -DestinationVHDX "D:\VMs\Windows.vhdx" -BootMode BIOS
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
    if ($null -eq $Collection) { return 0 }
    $result = @($Collection)
    return $result.Count
}

function Get-ClampedPercent {
    param(
        [Parameter(Mandatory)][double]$Current, 
        [Parameter(Mandatory)][double]$Total
    )
    if ($Total -le 0) { return 0 }
    $pct = [math]::Floor(($Current / $Total) * 100)
    return [math]::Min(100, [math]::Max(0, [int]$pct))
}

function Wait-KeyPress {
    param([string]$Message = "Press any key to continue...")
    
    Write-Host "  $Message" -ForegroundColor Gray
    
    try {
        if ($Host.Name -eq 'ConsoleHost') {
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
        else {
            $null = Read-Host
        }
    }
    catch {
        $null = Read-Host
    }
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

$typesLoaded = $false
try {
    $null = [VirtDiskApi].Name
    $null = [NativeDiskApi].Name
    $typesLoaded = $true
}
catch { }

if (-not $typesLoaded) {
    Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop
}

# ============================================================
# PowerShell Function to Create VHDX Parameters Buffer
# ============================================================

function New-CreateVirtualDiskParametersV1 {
    param(
        [Parameter(Mandatory)][Guid]$UniqueId,
        [Parameter(Mandatory)][uint64]$MaximumSize,
        [uint32]$BlockSizeInBytes = 0,
        [uint32]$SectorSizeInBytes = 512
    )
    
    # CREATE_VIRTUAL_DISK_PARAMETERS Version 1 layout (x64):
    # Offset 0:  Version (4 bytes) = 1
    # Offset 4:  UniqueId (16 bytes GUID)
    # Offset 20: [4 bytes padding]
    # Offset 24: MaximumSize (8 bytes)
    # Offset 32: BlockSizeInBytes (4 bytes)
    # Offset 36: SectorSizeInBytes (4 bytes)
    # Offset 40: ParentPath (8 bytes pointer)
    # Offset 48: SourcePath (8 bytes pointer)
    # Total: 56 bytes
    
    $size = 56
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    
    # Zero out
    for ($i = 0; $i -lt $size; $i++) {
        [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, 0)
    }
    
    # Version = 1
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
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Get-VolumeList {
    $vols = Get-Volume | Where-Object { 
        $_.DriveLetter -and 
        $_.DriveType -eq 'Fixed' -and
        $_.Size -gt 0
    } | Sort-Object DriveLetter
    
    return @($vols)
}

function Show-VolumeMenu {
    param([array]$Volumes)
    
    Write-Host "  Available Volumes:" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    for ($i = 0; $i -lt $Volumes.Count; $i++) {
        $vol = $Volumes[$i]
        $index = $i + 1
        $sizeGB = [math]::Round($vol.Size / 1GB, 2)
        $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
        $usedPct = 0
        if ($vol.Size -gt 0) {
            $usedPct = [math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100, 0)
        }
        $label = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Local Disk" }
        
        $barLength = 20
        $filledLength = [int][math]::Min($barLength, [math]::Max(0, [math]::Round(($usedPct / 100) * $barLength)))
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
    }
    
    Write-Host "    [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit" -ForegroundColor Gray
    Write-Host ""
}

function Read-MenuSelection {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter(Mandatory)][int]$Min,
        [Parameter(Mandatory)][int]$Max
    )
    
    while ($true) {
        Write-Host "  ${Prompt}: " -ForegroundColor White -NoNewline
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            Write-Host "  Please enter a number between $Min and $Max" -ForegroundColor Red
            continue
        }
        
        $num = 0
        $parsed = [int]::TryParse($userInput.Trim(), [ref]$num)
        
        if ($parsed -and $num -ge $Min -and $num -le $Max) {
            return $num
        }
        
        Write-Host "  Please enter a number between $Min and $Max" -ForegroundColor Red
    }
}

function Read-PathInput {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [string]$Default = "",
        [string]$RequiredExtension = ""
    )
    
    while ($true) {
        if ($Default) {
            Write-Host "  $Prompt" -ForegroundColor White
            Write-Host "  Default: $Default" -ForegroundColor DarkGray
            Write-Host "  (Press Enter to use default): " -ForegroundColor White -NoNewline
        }
        else {
            Write-Host "  ${Prompt}: " -ForegroundColor White -NoNewline
        }
        
        $userInput = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($userInput)) {
            if ($Default) {
                $userInput = $Default
            }
            else {
                Write-Host "  Path cannot be empty." -ForegroundColor Red
                continue
            }
        }
        
        $userInput = $userInput.Trim()
        
        if ($RequiredExtension -and -not $userInput.ToLower().EndsWith($RequiredExtension.ToLower())) {
            Write-Host "  Path must end with $RequiredExtension" -ForegroundColor Red
            continue
        }
        
        return $userInput
    }
}

function Read-YesNo {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [bool]$Default = $false
    )
    
    $defaultStr = if ($Default) { "Y/n" } else { "y/N" }
    Write-Host "  $Prompt [$defaultStr]: " -ForegroundColor White -NoNewline
    
    $userInput = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        return $Default
    }
    
    $answer = $userInput.Trim().ToLower()
    return ($answer -eq 'y' -or $answer -eq 'yes')
}

function Read-BlockSize {
    param([int]$Current)
    
    Write-Host "  Enter block size in MB (1-64) [$Current]: " -ForegroundColor White -NoNewline
    $userInput = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        return $Current
    }
    
    $num = 0
    if ([int]::TryParse($userInput.Trim(), [ref]$num)) {
        if ($num -ge 1 -and $num -le 64) {
            return $num
        }
    }
    
    Write-Host "  Invalid input. Keeping current value: $Current MB" -ForegroundColor Yellow
    return $Current
}

# ============================================================
# VSS Functions
# ============================================================

function New-VssSnapshot {
    param([Parameter(Mandatory)][string]$Volume)
    
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
    param([Parameter(Mandatory)][string]$ShadowId)
    
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    $shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) { 
        Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue 
    }
}

# ============================================================
# Virtual Disk Functions
# ============================================================

function New-RawVHDX {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][uint64]$SizeBytes,
        [switch]$FixedSize
    )
    
    $typeStr = if ($FixedSize) { "Fixed" } else { "Dynamic" }
    Write-Host "Creating $typeStr VHDX: $Path ($([math]::Round($SizeBytes/1GB, 2)) GB)..." -ForegroundColor Cyan
    
    # Ensure directory exists
    $parentDir = Split-Path -Path $Path -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        $null = New-Item -Path $parentDir -ItemType Directory -Force
    }
    
    # Remove existing file
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
    
    # Try using Hyper-V cmdlet first (most reliable)
    $hyperVAvailable = $false
    try {
        $null = Get-Command -Name New-VHD -ErrorAction Stop
        $hyperVAvailable = $true
    }
    catch { }
    
    if ($hyperVAvailable) {
        Write-Host "  Using Hyper-V cmdlet..." -ForegroundColor DarkGray
        
        try {
            if ($FixedSize) {
                $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Fixed -ErrorAction Stop
            }
            else {
                $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic -ErrorAction Stop
            }
            
            # Open with virtdisk API to get a handle
            $storageType = New-Object -TypeName VirtDiskApi+VIRTUAL_STORAGE_TYPE
            $storageType.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
            $storageType.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
            
            $openParams = New-Object -TypeName VirtDiskApi+OPEN_VIRTUAL_DISK_PARAMETERS
            $openParams.Version = 1
            $openParams.RWDepth = 0
            
            $handle = [IntPtr]::Zero
            $result = [VirtDiskApi]::OpenVirtualDisk(
                [ref]$storageType,
                $Path,
                [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL,
                [VirtDiskApi]::OPEN_VIRTUAL_DISK_FLAG_NONE,
                [ref]$openParams,
                [ref]$handle
            )
            
            if ($result -ne 0) {
                $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
                throw "OpenVirtualDisk failed: $($win32Err.Message)"
            }
            
            return $handle
        }
        catch {
            Write-Host "  Hyper-V method failed: $_" -ForegroundColor Yellow
            Write-Host "  Trying VirtDisk API..." -ForegroundColor Yellow
            
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Method 2: Manual P/Invoke
    Write-Host "  Using VirtDisk API..." -ForegroundColor DarkGray
    
    # Align size to MB boundary
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    
    $storageType = New-Object -TypeName VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
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
        
        return $handle
    }
    finally {
        Remove-CreateVirtualDiskParameters -Ptr $paramsPtr
    }
}

function Mount-RawVHDX {
    param(
        [Parameter(Mandatory)][IntPtr]$Handle,
        [switch]$WithDriveLetter
    )
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object -TypeName VirtDiskApi+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = 1
    
    $flags = if ($WithDriveLetter) { 
        [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NONE 
    } 
    else { 
        [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER 
    }
    
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
    param([Parameter(Mandatory)][IntPtr]$Handle)
    
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
        [Parameter(Mandatory)][string]$PhysicalPath,
        [Parameter(Mandatory)][ValidateSet('UEFI', 'BIOS')][string]$BootMode,
        [Parameter(Mandatory)][uint64]$WindowsPartitionSize
    )
    
    Write-Host "Initializing disk structure for $BootMode boot..." -ForegroundColor Cyan
    
    $diskNumber = -1
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') {
        $diskNumber = [int]$Matches[1]
    }
    else {
        throw "Could not determine disk number from path: $PhysicalPath"
    }
    
    # Wait for disk
    $retries = 30
    $disk = $null
    while ($retries -gt 0) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
        if ($disk) { break }
        $retries--
    }
    
    if (-not $disk) { throw "Could not find disk $diskNumber" }
    
    Write-Host "  Disk $diskNumber found: $([math]::Round($disk.Size/1GB, 2)) GB" -ForegroundColor DarkGray
    
    if ($BootMode -eq 'UEFI') {
        Write-Host "  Initializing as GPT..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating EFI System Partition (260 MB)..." -ForegroundColor DarkGray
        $espPartition = New-Partition -DiskNumber $diskNumber -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $null = Format-Volume -Partition $espPartition -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false
        
        Write-Host "  Creating Microsoft Reserved Partition (16 MB)..." -ForegroundColor DarkGray
        $null = New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $winPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
        
        return @{ 
            DiskNumber = $diskNumber
            EspPartition = $espPartition
            WindowsPartition = $winPartition
            BootMode = 'UEFI' 
        }
    }
    else {
        Write-Host "  Initializing as MBR..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle MBR -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating System Reserved partition (500 MB)..." -ForegroundColor DarkGray
        $sysPartition = New-Partition -DiskNumber $diskNumber -Size 500MB -IsActive
        $null = Format-Volume -Partition $sysPartition -FileSystem NTFS -NewFileSystemLabel "System Reserved" -Confirm:$false
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $winPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize
        
        return @{ 
            DiskNumber = $diskNumber
            SystemPartition = $sysPartition
            WindowsPartition = $winPartition
            BootMode = 'BIOS' 
        }
    }
}

function Install-BootFiles {
    param(
        [Parameter(Mandatory)][hashtable]$DiskInfo,
        [Parameter(Mandatory)][string]$WindowsDriveLetter
    )
    
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $windowsPath = "${WindowsDriveLetter}:\Windows"
    if (-not (Test-Path -LiteralPath $windowsPath)) {
        throw "Windows directory not found at $windowsPath"
    }
    
    # Find available drive letter
    $usedLetters = @((Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter)
    $availableLetters = @()
    foreach ($letter in [char[]]('S'..'Z')) {
        if ($letter -notin $usedLetters) {
            $availableLetters += $letter
        }
    }
    
    if ($availableLetters.Count -eq 0) { 
        throw "No available drive letters for boot partition" 
    }
    
    $bootLetter = $availableLetters[0]
    
    if ($DiskInfo.BootMode -eq 'UEFI') {
        Write-Host "  Assigning drive letter $bootLetter to ESP..." -ForegroundColor DarkGray
        $DiskInfo.EspPartition | Set-Partition -NewDriveLetter $bootLetter
        Start-Sleep -Seconds 2
        
        try {
            Write-Host "  Running bcdboot for UEFI..." -ForegroundColor DarkGray
            $bcdbootOutput = & bcdboot.exe "$windowsPath" /s "${bootLetter}:" /f UEFI 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "bcdboot failed (exit code $LASTEXITCODE): $bcdbootOutput"
            }
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            try { 
                $DiskInfo.EspPartition | Remove-PartitionAccessPath -AccessPath "${bootLetter}:\" -ErrorAction SilentlyContinue 
            } catch { }
        }
    }
    else {
        Write-Host "  Assigning drive letter $bootLetter to System partition..." -ForegroundColor DarkGray
        $DiskInfo.SystemPartition | Set-Partition -NewDriveLetter $bootLetter
        Start-Sleep -Seconds 2
        
        try {
            Write-Host "  Running bcdboot for BIOS..." -ForegroundColor DarkGray
            $bcdbootOutput = & bcdboot.exe "$windowsPath" /s "${bootLetter}:" /f BIOS 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "bcdboot failed (exit code $LASTEXITCODE): $bcdbootOutput"
            }
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            try { 
                $DiskInfo.SystemPartition | Remove-PartitionAccessPath -AccessPath "${bootLetter}:\" -ErrorAction SilentlyContinue 
            } catch { }
        }
    }
}

# ============================================================
# Volume Bitmap Functions
# ============================================================

function Get-NtfsVolumeData {
    param([Parameter(Mandatory)][string]$DriveLetter)
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDiskApi]::CreateFile(
        $volumePath, 
        [NativeDiskApi]::GENERIC_READ, 
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, 
        [NativeDiskApi]::OPEN_EXISTING, 
        0, 
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume: $(New-Object System.ComponentModel.Win32Exception $err)"
    }
    
    try {
        $bufferSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
        
        try {
            $bytesReturned = [uint32]0
            $success = [NativeDiskApi]::DeviceIoControl(
                $handle, 
                [NativeDiskApi]::FSCTL_GET_NTFS_VOLUME_DATA,
                [IntPtr]::Zero, 
                0, 
                $buffer, 
                [uint32]$bufferSize, 
                [ref]$bytesReturned, 
                [IntPtr]::Zero
            )
            
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
        finally { 
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer) 
        }
    }
    finally { 
        $handle.Close() 
    }
}

function Get-VolumeBitmap {
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][long]$TotalClusters
    )
    
    Write-Host "Reading volume allocation bitmap..." -ForegroundColor Cyan
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = '\\.\' + $DriveLetter + ':'
    
    $handle = [NativeDiskApi]::CreateFile(
        $volumePath, 
        [NativeDiskApi]::GENERIC_READ,
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, 
        [NativeDiskApi]::OPEN_EXISTING, 
        0, 
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) { 
        throw "Failed to open volume" 
    }
    
    try {
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $fullBitmap = New-Object byte[] $bitmapBytes
        
        $startingLcn = [long]0
        $headerSize = 16
        $chunkSize = 1048576
        $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $inputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        $bitmapOffset = 0
        
        try {
            while ($startingLcn -lt $TotalClusters) {
                [System.Runtime.InteropServices.Marshal]::WriteInt64($inputBuffer, 0, $startingLcn)
                
                $bytesReturned = [uint32]0
                $success = [NativeDiskApi]::DeviceIoControl(
                    $handle, 
                    [NativeDiskApi]::FSCTL_GET_VOLUME_BITMAP,
                    $inputBuffer, 
                    8, 
                    $outputBuffer, 
                    [uint32]$chunkSize, 
                    [ref]$bytesReturned, 
                    [IntPtr]::Zero
                )
                
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($err -ne 234) { 
                        throw "FSCTL_GET_VOLUME_BITMAP failed: error $err" 
                    }
                }
                
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
                
                $pct = Get-ClampedPercent -Current $startingLcn -Total $TotalClusters
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
    param(
        [Parameter(Mandatory)][byte[]]$Bitmap,
        [Parameter(Mandatory)][long]$TotalClusters,
        [Parameter(Mandatory)][uint32]$BytesPerCluster,
        [int]$MinRunClusters = 256
    )
    
    Write-Host "Analyzing allocation bitmap..." -ForegroundColor Cyan
    
    $ranges = [System.Collections.ArrayList]::new()
    $currentStart = [long]-1
    $allocatedClusters = [long]0
    $progressInterval = [math]::Max(1, [int]($TotalClusters / 100))
    
    for ($cluster = [long]0; $cluster -lt $TotalClusters; $cluster++) {
        $byteIndex = [int][math]::Floor($cluster / 8)
        $bitIndex = [int]($cluster % 8)
        $isAllocated = ($Bitmap[$byteIndex] -band (1 -shl $bitIndex)) -ne 0
        
        if ($isAllocated) {
            if ($currentStart -eq -1) { $currentStart = $cluster }
            $allocatedClusters++
        }
        else {
            if ($currentStart -ne -1) {
                $null = $ranges.Add([PSCustomObject]@{ 
                    StartCluster = $currentStart
                    EndCluster = $cluster - 1
                    ClusterCount = $cluster - $currentStart 
                })
                $currentStart = -1
            }
        }
        
        if ($cluster % $progressInterval -eq 0) {
            $pct = Get-ClampedPercent -Current $cluster -Total $TotalClusters
            Write-Progress -Activity "Analyzing Bitmap" -Status "$pct%" -PercentComplete $pct
        }
    }
    
    if ($currentStart -ne -1) {
        $null = $ranges.Add([PSCustomObject]@{ 
            StartCluster = $currentStart
            EndCluster = $TotalClusters - 1
            ClusterCount = $TotalClusters - $currentStart 
        })
    }
    Write-Progress -Activity "Analyzing Bitmap" -Completed
    
    Write-Host "Merging adjacent ranges..." -ForegroundColor Cyan
    $mergedRanges = [System.Collections.ArrayList]::new()
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
                EndCluster = $range.EndCluster
                ClusterCount = $range.EndCluster - $prev.StartCluster + 1 
            }
        }
        else {
            $null = $mergedRanges.Add($prev)
            $prev = $range
        }
    }
    if ($prev) { 
        $null = $mergedRanges.Add($prev) 
    }
    
    $totalBytes = [long]$TotalClusters * $BytesPerCluster
    $allocatedBytes = [long]$allocatedClusters * $BytesPerCluster
    Write-Host "  Allocated: $([math]::Round($allocatedBytes/1GB, 2)) GB of $([math]::Round($totalBytes/1GB, 2)) GB" -ForegroundColor DarkGray
    Write-Host "  Ranges: $($mergedRanges.Count)" -ForegroundColor DarkGray
    
    return @{ 
        Ranges = $mergedRanges
        AllocatedClusters = $allocatedClusters
        AllocatedBytes = $allocatedBytes 
    }
}

# ============================================================
# Raw Disk I/O
# ============================================================

function Open-RawDisk {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Read', 'Write', 'ReadWrite')][string]$Access
    )
    
    $accessFlags = switch ($Access) {
        'Read'      { [NativeDiskApi]::GENERIC_READ }
        'Write'     { [NativeDiskApi]::GENERIC_WRITE }
        'ReadWrite' { [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE }
    }
    
    $handle = [NativeDiskApi]::CreateFile(
        $Path, 
        $accessFlags,
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero, 
        [NativeDiskApi]::OPEN_EXISTING,
        ([NativeDiskApi]::FILE_FLAG_NO_BUFFERING -bor [NativeDiskApi]::FILE_FLAG_WRITE_THROUGH),
        [IntPtr]::Zero
    )
    
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
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DiskPath,
        [Parameter(Mandatory)][long]$PartitionOffset,
        [Parameter(Mandatory)][uint64]$TotalBytes,
        [int]$BlockSize = 4194304
    )
    
    Write-Host "Copying $([math]::Round($TotalBytes/1GB, 2)) GB to partition..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DiskPath -Access Write
    
    try {
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [uint64]0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        while ($totalCopied -lt $TotalBytes) {
            $remainingBytes = $TotalBytes - $totalCopied
            $bytesToProcess = [math]::Min([uint64]$BlockSize, $remainingBytes)
            $alignedBytes = [uint32]([math]::Ceiling($bytesToProcess / 4096) * 4096)
            
            $bytesRead = [uint32]0
            $readSuccess = [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $alignedBytes, [ref]$bytesRead, [IntPtr]::Zero)
            if (-not $readSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Read failed at offset $totalCopied (Error: $err)"
            }
            if ($bytesRead -eq 0) { break }
            
            $destOffset = $PartitionOffset + $totalCopied
            $newPos = [long]0
            $seekSuccess = [NativeDiskApi]::SetFilePointerEx($destHandle, $destOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
            if (-not $seekSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Seek failed at offset $destOffset (Error: $err)"
            }
            
            $writeBytes = [math]::Min($bytesRead, $remainingBytes)
            $alignedWrite = [uint32]([math]::Ceiling($writeBytes / 4096) * 4096)
            
            $bytesWritten = [uint32]0
            $writeSuccess = [NativeDiskApi]::WriteFile($destHandle, $buffer, $alignedWrite, [ref]$bytesWritten, [IntPtr]::Zero)
            if (-not $writeSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Write failed at offset $destOffset (Error: $err)"
            }
            
            $totalCopied += $writeBytes
            
            $pct = Get-ClampedPercent -Current $totalCopied -Total $TotalBytes
            if ($pct -gt $lastPct) {
                $elapsed = $stopwatch.Elapsed.TotalSeconds
                $speed = 0
                $eta = 0
                if ($elapsed -gt 0) {
                    $speed = $totalCopied / $elapsed / 1MB
                    if ($speed -gt 0) {
                        $eta = ($TotalBytes - $totalCopied) / 1MB / $speed / 60
                    }
                }
                Write-Progress -Activity "Copying Data" -Status "$pct% - $([math]::Round($speed,1)) MB/s - ETA: $([math]::Round($eta,1)) min" -PercentComplete $pct
                $lastPct = $pct
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying Data" -Completed
        
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        $avgSpeed = 0
        if ($elapsed -gt 0) {
            $avgSpeed = $totalCopied / $elapsed / 1MB
        }
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if ($sourceHandle -and -not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if ($destHandle -and -not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

function Copy-AllocatedBlocksToPartition {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DiskPath,
        [Parameter(Mandatory)][long]$PartitionOffset,
        [Parameter(Mandatory)][System.Collections.ArrayList]$Ranges,
        [Parameter(Mandatory)][uint32]$BytesPerCluster,
        [Parameter(Mandatory)][long]$AllocatedBytes,
        [int]$BlockSize = 4194304
    )
    
    # Align block size to cluster size
    if ($BlockSize % $BytesPerCluster -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $BytesPerCluster) * $BytesPerCluster)
    }
    $clustersPerBlock = [long]($BlockSize / $BytesPerCluster)
    
    Write-Host "Copying $([math]::Round($AllocatedBytes/1GB, 2)) GB of allocated data..." -ForegroundColor Cyan
    
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
                $seekSuccess = [NativeDiskApi]::SetFilePointerEx($sourceHandle, $sourceByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
                if (-not $seekSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Source seek failed at offset $sourceByteOffset (Error: $err)"
                }
                
                $bytesRead = [uint32]0
                $readSuccess = [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
                if (-not $readSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Read failed at cluster $clusterOffset (Error: $err)"
                }
                
                $destByteOffset = $PartitionOffset + $sourceByteOffset
                $seekSuccess = [NativeDiskApi]::SetFilePointerEx($destHandle, $destByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
                if (-not $seekSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Dest seek failed at offset $destByteOffset (Error: $err)"
                }
                
                $bytesWritten = [uint32]0
                $writeSuccess = [NativeDiskApi]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
                if (-not $writeSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Write failed at cluster $clusterOffset (Error: $err)"
                }
                
                $totalCopied += $bytesRead
                $clusterOffset += $clustersToRead
                $clustersRemaining -= $clustersToRead
                
                $pct = Get-ClampedPercent -Current $totalCopied -Total $AllocatedBytes
                if ($pct -gt $lastPct) {
                    $elapsed = $stopwatch.Elapsed.TotalSeconds
                    $speed = 0
                    $eta = 0
                    if ($elapsed -gt 0) {
                        $speed = $totalCopied / $elapsed / 1MB
                        if ($speed -gt 0) {
                            $eta = ($AllocatedBytes - $totalCopied) / 1MB / $speed / 60
                        }
                    }
                    Write-Progress -Activity "Copying Data" -Status "$pct% - $([math]::Round($speed,1)) MB/s - ETA: $([math]::Round($eta,1)) min" -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying Data" -Completed
        
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        $avgSpeed = 0
        if ($elapsed -gt 0) {
            $avgSpeed = $totalCopied / $elapsed / 1MB
        }
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if ($sourceHandle -and -not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if ($destHandle -and -not $destHandle.IsClosed) { $destHandle.Close() }
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
        
        if ($volume.FileSystemType -ne 'NTFS' -and -not $FullCopy) {
            Write-Warning "Volume is $($volume.FileSystemType), not NTFS. Forcing full copy."
            $FullCopy = $true
        }
        
        $bootPartitionSize = if ($BootMode -eq 'UEFI') { 300MB } else { 550MB }
        $vhdxSize = [uint64]($partitionSize + $bootPartitionSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "                    BOOTABLE VOLUME CLONE                       " -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Source:         ${driveLetter}:" -ForegroundColor White
        Write-Host "  Destination:    $DestinationVHDX" -ForegroundColor White
        Write-Host "  Partition Size: $([math]::Round($partitionSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "  VHDX Size:      $([math]::Round($vhdxSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "  Boot Mode:      $BootMode" -ForegroundColor White
        Write-Host "  Copy Mode:      $(if ($FullCopy) { 'Full (all sectors)' } else { 'Smart (skip free space)' })" -ForegroundColor White
        Write-Host ""
        
        $volumeData = $null
        if (-not $FullCopy) {
            $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
            $usedBytes = ($volumeData.TotalClusters - $volumeData.FreeClusters) * $volumeData.BytesPerCluster
            $freeBytes = $volumeData.FreeClusters * $volumeData.BytesPerCluster
            Write-Host "  Used space:     $([math]::Round($usedBytes / 1GB, 2)) GB" -ForegroundColor DarkGray
            Write-Host "  Free space:     $([math]::Round($freeBytes / 1GB, 2)) GB (will be skipped)" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        Write-Host ""
        
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle -WithDriveLetter
        Write-Host "VHDX attached at: $physicalPath" -ForegroundColor Green
        Write-Host ""
        
        Start-Sleep -Seconds 3
        
        $diskInfo = Initialize-BootableVHDX -PhysicalPath $physicalPath -BootMode $BootMode -WindowsPartitionSize $partitionSize
        
        Start-Sleep -Seconds 2
        
        $winPartition = $diskInfo.WindowsPartition
        $winPartitionOffset = $winPartition.Offset
        $diskPath = "\\.\PhysicalDrive$($diskInfo.DiskNumber)"
        
        Write-Host ""
        Write-Host "Windows partition offset: $winPartitionOffset bytes" -ForegroundColor DarkGray
        Write-Host "Windows partition size: $([math]::Round($winPartition.Size/1GB, 2)) GB" -ForegroundColor DarkGray
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
        
        if (-not $SkipBootFix) {
            # Find available drive letter for Windows partition
            $usedLetters = @((Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter)
            $windowsDriveLetter = $null
            foreach ($letter in [char[]]('W'..'Z' + 'N'..'V')) {
                if ($letter -notin $usedLetters) {
                    $windowsDriveLetter = $letter
                    break
                }
            }
            
            if (-not $windowsDriveLetter) { 
                throw "No available drive letters for Windows partition" 
            }
            
            Write-Host ""
            Write-Host "Assigning drive letter $windowsDriveLetter to Windows partition..." -ForegroundColor Cyan
            $winPartition | Set-Partition -NewDriveLetter $windowsDriveLetter
            Start-Sleep -Seconds 2
            
            Install-BootFiles -DiskInfo $diskInfo -WindowsDriveLetter $windowsDriveLetter
            
            Write-Host "Removing drive letter..." -ForegroundColor Cyan
            try { 
                $winPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue 
            } catch { }
            $windowsDriveLetter = $null
        }
        
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "                  BOOTABLE CLONE COMPLETE                       " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "  VHDX File: $DestinationVHDX" -ForegroundColor White
        
        $vhdxFile = Get-Item -LiteralPath $DestinationVHDX
        Write-Host "  File Size: $([math]::Round($vhdxFile.Length/1GB, 2)) GB" -ForegroundColor White
        Write-Host ""
        Write-Host "  Usage:" -ForegroundColor Cyan
        Write-Host "    Hyper-V:     Create a new VM and attach this VHDX as the primary disk" -ForegroundColor Gray
        Write-Host "    Native Boot: Use bcdedit to add a boot entry (requires Pro/Enterprise)" -ForegroundColor Gray
        Write-Host ""
        
        return $DestinationVHDX
    }
    catch {
        Write-Host ""
        Write-Host "Clone failed: $_" -ForegroundColor Red
        
        if ($windowsDriveLetter -and $diskInfo -and $diskInfo.WindowsPartition) {
            try { 
                $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue 
            } catch { }
        }
        
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
        if ($snapshot) { 
            Remove-VssSnapshot -ShadowId $snapshot.Id 
        }
    }
}

# ============================================================
# Interactive Mode
# ============================================================

function Start-InteractiveMode {
    $optBootMode = 'UEFI'
    $optFullCopy = $false
    $optFixedSizeVHDX = $false
    $optBlockSizeMB = 4
    
    :mainLoop while ($true) {
        Show-Banner
        
        $volumes = Get-VolumeList
        $volumeCount = $volumes.Count
        
        if ($volumeCount -eq 0) {
            Write-Host "  No suitable volumes found!" -ForegroundColor Red
            Wait-KeyPress
            return
        }
        
        Show-VolumeMenu -Volumes $volumes
        
        $selection = Read-MenuSelection -Prompt "Select volume to clone" -Min 0 -Max $volumeCount
        
        if ($selection -eq 0) { 
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            return 
        }
        
        $volIndex = $selection - 1
        $selectedVolume = $volumes[$volIndex].DriveLetter
        $volumeInfo = $volumes[$volIndex]
        
        # Build default destination path
        $defaultName = "Bootable_${selectedVolume}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        
        $destDrives = @(Get-Volume | Where-Object { 
            $_.DriveLetter -and 
            $_.DriveLetter -ne $selectedVolume -and 
            $_.DriveType -eq 'Fixed' -and 
            $_.SizeRemaining -gt ($volumeInfo.Size + 1GB) 
        } | Sort-Object SizeRemaining -Descending)
        
        $defaultPath = "${selectedVolume}:\VMs\$defaultName"
        if ($destDrives.Count -gt 0) {
            $defaultPath = "$($destDrives[0].DriveLetter):\VMs\$defaultName"
        }
        
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
            
            $bootColor = if ($optBootMode -eq 'UEFI') { 'Green' } else { 'White' }
            Write-Host "    [1] Boot Mode:     " -ForegroundColor Yellow -NoNewline
            Write-Host "$optBootMode" -ForegroundColor $bootColor
            
            $copyColor = if (-not $optFullCopy) { 'Green' } else { 'White' }
            $copyText = if ($optFullCopy) { 'Full (all sectors)' } else { 'Smart (skip free)' }
            Write-Host "    [2] Copy Mode:     " -ForegroundColor Yellow -NoNewline
            Write-Host "$copyText" -ForegroundColor $copyColor
            
            $vhdxColor = if (-not $optFixedSizeVHDX) { 'Green' } else { 'White' }
            $vhdxText = if ($optFixedSizeVHDX) { 'Fixed' } else { 'Dynamic' }
            Write-Host "    [3] VHDX Type:     " -ForegroundColor Yellow -NoNewline
            Write-Host "$vhdxText" -ForegroundColor $vhdxColor
            
            Write-Host "    [4] Block Size:    " -ForegroundColor Yellow -NoNewline
            Write-Host "$optBlockSizeMB MB" -ForegroundColor White
            
            Write-Host ""
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Destination Path" -ForegroundColor Cyan
            Write-Host "    [B] Back to Volume Selection" -ForegroundColor DarkYellow
            Write-Host "    [Q] Quit" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Choice: " -ForegroundColor White -NoNewline
            
            $choice = Read-Host
            
            if ([string]::IsNullOrWhiteSpace($choice)) {
                continue optionsLoop
            }
            
            $choice = $choice.Trim().ToUpper()
            
            switch ($choice) {
                "1" { 
                    $optBootMode = if ($optBootMode -eq 'UEFI') { 'BIOS' } else { 'UEFI' } 
                }
                "2" { 
                    $optFullCopy = -not $optFullCopy 
                }
                "3" { 
                    $optFixedSizeVHDX = -not $optFixedSizeVHDX 
                }
                "4" { 
                    Write-Host ""
                    $optBlockSizeMB = Read-BlockSize -Current $optBlockSizeMB
                }
                "C" { 
                    Write-Host ""
                    $destinationPath = Read-PathInput -Prompt "New destination path" -Default $destinationPath -RequiredExtension ".vhdx"
                }
                "B" { 
                    continue mainLoop 
                }
                "S" {
                    if (Test-Path -LiteralPath $destinationPath) {
                        Write-Host ""
                        $overwrite = Read-YesNo -Prompt "Destination file exists. Overwrite?" -Default $false
                        if (-not $overwrite) { 
                            continue optionsLoop 
                        }
                        Remove-Item -LiteralPath $destinationPath -Force
                    }
                    
                    Write-Host ""
                    $confirm = Read-YesNo -Prompt "Start bootable clone?" -Default $true
                    
                    if ($confirm) {
                        Write-Host ""
                        try {
                            New-BootableVolumeClone `
                                -SourceVolume $selectedVolume `
                                -DestinationVHDX $destinationPath `
                                -BootMode $optBootMode `
                                -FullCopy:$optFullCopy `
                                -FixedSizeVHDX:$optFixedSizeVHDX `
                                -BlockSizeMB $optBlockSizeMB
                            
                            Write-Host "  Clone completed successfully!" -ForegroundColor Green
                        }
                        catch { 
                            Write-Host ""
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Red
                            Write-Host "  Clone failed: $_" -ForegroundColor Red
                            Write-Host "  ════════════════════════════════════════════════════════════" -ForegroundColor Red
                        }
                        
                        Write-Host ""
                        Wait-KeyPress
                        
                        Write-Host ""
                        $another = Read-YesNo -Prompt "Clone another volume?" -Default $false
                        if (-not $another) { 
                            Write-Host ""
                            Write-Host "  Goodbye!" -ForegroundColor Cyan
                            return 
                        }
                        continue mainLoop
                    }
                }
                "Q" { 
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return 
                }
                "0" { 
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return 
                }
                default {
                    # Invalid input - just continue the loop
                }
            }
        }
    }
}

# ============================================================
# Entry Point
# ============================================================

$runInteractive = $false

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    $runInteractive = $true
}
elseif ([string]::IsNullOrWhiteSpace($SourceVolume) -and [string]::IsNullOrWhiteSpace($DestinationVHDX)) {
    $runInteractive = $true
}

if ($runInteractive) {
    Start-InteractiveMode
}
else {
    if ([string]::IsNullOrWhiteSpace($SourceVolume)) {
        throw "SourceVolume is required. Run without parameters for interactive mode."
    }
    if ([string]::IsNullOrWhiteSpace($DestinationVHDX)) {
        throw "DestinationVHDX is required. Run without parameters for interactive mode."
    }
    
    New-BootableVolumeClone `
        -SourceVolume $SourceVolume `
        -DestinationVHDX $DestinationVHDX `
        -BootMode $BootMode `
        -FullCopy:$FullCopy `
        -FixedSizeVHDX:$FixedSizeVHDX `
        -SkipBootFix:$SkipBootFix `
        -BlockSizeMB $BlockSizeMB
}
