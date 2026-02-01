#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a running Windows volume to a bootable VHDX file.

.DESCRIPTION
    This script creates a bootable VHDX from a live Windows volume using VSS snapshots.
    Supports both UEFI and BIOS boot modes, smart copying (allocated blocks only), and
    full volume copying.

.PARAMETER SourceVolume
    The drive letter of the source volume (e.g., "C" or "C:").

.PARAMETER DestinationVHDX
    The full path for the destination VHDX file.

.PARAMETER BootMode
    Boot mode for the VHDX: UEFI (default) or BIOS.

.PARAMETER FullCopy
    Copy entire volume instead of only allocated blocks.

.PARAMETER FixedSizeVHDX
    Create a fixed-size VHDX instead of dynamic.

.PARAMETER BlockSizeMB
    Block size for VHDX and copy operations (1-64 MB, default 4).

.PARAMETER SkipBootFix
    Skip installing boot files (for data-only clones).

.PARAMETER Interactive
    Run in interactive menu mode.

.EXAMPLE
    .\BootableVolumeClone.ps1 -Interactive

.EXAMPLE
    .\BootableVolumeClone.ps1 -SourceVolume C -DestinationVHDX D:\Backup\System.vhdx -BootMode UEFI
#>

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'CommandLine')][string]$SourceVolume,
    [Parameter(ParameterSetName = 'CommandLine')][string]$DestinationVHDX,
    [Parameter(ParameterSetName = 'CommandLine')][ValidateSet('UEFI', 'BIOS')][string]$BootMode = 'UEFI',
    [Parameter(ParameterSetName = 'CommandLine')][switch]$FullCopy,
    [Parameter(ParameterSetName = 'CommandLine')][switch]$FixedSizeVHDX,
    [Parameter(ParameterSetName = 'CommandLine')][ValidateRange(1, 64)][int]$BlockSizeMB = 4,
    [Parameter(ParameterSetName = 'CommandLine')][switch]$SkipBootFix,
    [Parameter(ParameterSetName = 'Interactive')][switch]$Interactive
)

$ErrorActionPreference = 'Stop'
$script:ScriptVersion = "2.0.0"

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires Administrator privileges."
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-ClampedPercent {
    param([double]$Current, [double]$Total)
    if ($Total -le 0) { return 0 }
    $pct = [math]::Floor(($Current / $Total) * 100)
    return [int][math]::Min(100, [math]::Max(0, $pct))
}

function Wait-ForKeyPress {
    Write-Host "  Press Enter to continue..." -ForegroundColor Gray
    $null = Read-Host
}

function Get-AvailableDriveLetter {
    $usedLetters = [System.Collections.ArrayList]::new()
    
    $allVolumes = Get-Volume
    foreach ($v in $allVolumes) {
        if ($v.DriveLetter) {
            $null = $usedLetters.Add([string]$v.DriveLetter)
        }
    }
    
    $candidates = @('S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'N', 'O', 'P', 'Q', 'R')
    foreach ($letter in $candidates) {
        if ($letter -notin $usedLetters) {
            $testPath = $letter + ":\"
            if (-not (Test-Path -LiteralPath $testPath -ErrorAction SilentlyContinue)) {
                return $letter
            }
        }
    }
    return $null
}

function Format-ByteSize {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ([math]::Round($Bytes / 1TB, 2)).ToString() + " TB" }
    if ($Bytes -ge 1GB) { return ([math]::Round($Bytes / 1GB, 2)).ToString() + " GB" }
    if ($Bytes -ge 1MB) { return ([math]::Round($Bytes / 1MB, 2)).ToString() + " MB" }
    return ([math]::Round($Bytes / 1KB, 2)).ToString() + " KB"
}

function Format-TimeSpan {
    param([TimeSpan]$Span)
    if ($Span.TotalHours -ge 1) {
        return "{0:0}h {1:0}m {2:0}s" -f [math]::Floor($Span.TotalHours), $Span.Minutes, $Span.Seconds
    }
    elseif ($Span.TotalMinutes -ge 1) {
        return "{0:0}m {1:0}s" -f [math]::Floor($Span.TotalMinutes), $Span.Seconds
    }
    else {
        return "{0:0}s" -f $Span.TotalSeconds
    }
}

function Test-DestinationSpace {
    param([string]$DestPath, [uint64]$RequiredBytes)
    
    $parentDir = Split-Path $DestPath -Parent
    if (-not $parentDir) { $parentDir = $DestPath }
    
    # Extract drive letter
    $driveLetter = $null
    if ($parentDir -match '^([A-Za-z]):') {
        $driveLetter = $Matches[1]
    }
    
    if ($driveLetter) {
        $destVolume = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
        if ($destVolume) {
            if ($destVolume.SizeRemaining -lt $RequiredBytes) {
                $available = Format-ByteSize $destVolume.SizeRemaining
                $required = Format-ByteSize $RequiredBytes
                throw "Insufficient space on ${driveLetter}: drive. Required: $required, Available: $available"
            }
            Write-Host ("  Destination space: " + (Format-ByteSize $destVolume.SizeRemaining) + " available, ~" + (Format-ByteSize $RequiredBytes) + " needed") -ForegroundColor DarkGray
            return $true
        }
    }
    
    Write-Warning "Could not verify destination space - proceeding anyway"
    return $true
}

function Get-VolumeSectorSize {
    param([string]$DriveLetter)
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    
    try {
        $partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop
        $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
        
        $physicalSectorSize = $disk.PhysicalSectorSize
        $logicalSectorSize = $disk.LogicalSectorSize
        
        # Return the larger of the two for safety
        return [math]::Max($physicalSectorSize, $logicalSectorSize)
    }
    catch {
        # Default to 512 if we can't determine
        return 512
    }
}

# ============================================================
# P/INVOKE DEFINITIONS
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

    // Properly defined structure for Version 2 CREATE_VIRTUAL_DISK_PARAMETERS
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREATE_VIRTUAL_DISK_PARAMETERS_V2
    {
        public int Version;              // Offset 0, must be 2
        public Guid UniqueId;            // Offset 4 (8 on x64 with padding)
        public ulong MaximumSize;        // Maximum size in bytes
        public uint BlockSizeInBytes;    // Block size (0 for default)
        public uint SectorSizeInBytes;   // 512 or 4096
        public uint PhysicalSectorSizeInBytes;
        public IntPtr ParentPath;        // NULL for non-differencing
        public IntPtr SourcePath;        // NULL
        public int OpenFlags;
        public VIRTUAL_STORAGE_TYPE ParentVirtualStorageType;
        public VIRTUAL_STORAGE_TYPE SourceVirtualStorageType;
        public Guid ResiliencyGuid;
    }

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateVirtualDisk(
        ref VIRTUAL_STORAGE_TYPE VirtualStorageType,
        string Path,
        uint VirtualDiskAccessMask,
        IntPtr SecurityDescriptor,
        uint Flags,
        uint ProviderSpecificFlags,
        ref CREATE_VIRTUAL_DISK_PARAMETERS_V2 Parameters,
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
    public const uint FILE_BEGIN = 0;
    public const int ERROR_MORE_DATA = 234;

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
    public struct VOLUME_BITMAP_BUFFER
    {
        public long StartingLcn;
        public long BitmapSize;
        // Buffer follows
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

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int GetLastError();
}
'@

$typesLoaded = $false
try { $null = [VirtDiskApi].Name; $null = [NativeDiskApi].Name; $typesLoaded = $true } catch { }
if (-not $typesLoaded) { Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop }

# ============================================================
# VSS FUNCTIONS
# ============================================================

function New-VssSnapshot {
    param([string]$Volume)
    
    if (-not $Volume.EndsWith("\")) { $Volume = $Volume + "\" }
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume = $Volume
        Context = 'ClientAccessible'
    }
    
    if ($result.ReturnValue -ne 0) {
        $errorMessages = @{
            1 = "Access denied"
            2 = "Invalid argument"
            3 = "Specified volume not found"
            4 = "Specified volume not supported"
            5 = "Unsupported shadow copy context"
            6 = "Insufficient storage"
            7 = "Volume is in use"
            8 = "Maximum number of shadow copies reached"
            9 = "Another shadow copy operation is in progress"
            10 = "Shadow copy provider vetoed the operation"
            11 = "Shadow copy provider not registered"
            12 = "Shadow copy provider failure"
        }
        $msg = $errorMessages[[int]$result.ReturnValue]
        if (-not $msg) { $msg = "Unknown error" }
        throw ("Failed to create shadow copy. Error $($result.ReturnValue): $msg")
    }
    
    $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
    if (-not $shadow) { throw "Shadow copy created but not found." }
    
    return @{ Id = $result.ShadowID; DeviceObject = $shadow.DeviceObject; VolumeName = $Volume }
}

function Remove-VssSnapshot {
    param([string]$ShadowId)
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) { Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue }
}

# ============================================================
# VIRTUAL DISK FUNCTIONS
# ============================================================

function New-RawVHDX {
    param(
        [string]$Path,
        [uint64]$SizeBytes,
        [switch]$FixedSize,
        [int]$BlockSizeMB = 4,
        [int]$SectorSize = 512
    )
    
    $typeStr = "Dynamic"
    if ($FixedSize) { $typeStr = "Fixed" }
    Write-Host ("Creating " + $typeStr + " VHDX: " + $Path + " (" + (Format-ByteSize $SizeBytes) + ")...") -ForegroundColor Cyan
    
    $parentDir = Split-Path $Path -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        $null = New-Item $parentDir -ItemType Directory -Force
    }
    if (Test-Path $Path) { Remove-Item $Path -Force }
    
    # Ensure sector size is valid
    if ($SectorSize -ne 512 -and $SectorSize -ne 4096) {
        $SectorSize = 512
    }
    
    # Calculate block size in bytes (must be power of 2, between 1MB and 256MB)
    $blockSizeBytes = [uint32]($BlockSizeMB * 1MB)
    if ($blockSizeBytes -lt 1MB) { $blockSizeBytes = 1MB }
    if ($blockSizeBytes -gt 256MB) { $blockSizeBytes = 256MB }
    
    # Try Hyper-V cmdlet first (most reliable)
    $hyperVOK = $false
    try { $null = Get-Command New-VHD -ErrorAction Stop; $hyperVOK = $true } catch { }
    
    if ($hyperVOK) {
        Write-Host "  Using Hyper-V cmdlet..." -ForegroundColor DarkGray
        try {
            $vhdParams = @{
                Path = $Path
                SizeBytes = $SizeBytes
                BlockSizeBytes = $blockSizeBytes
                LogicalSectorSizeBytes = $SectorSize
            }
            
            if ($FixedSize) {
                Write-Host "  Allocating fixed disk (this may take a while)..." -ForegroundColor DarkGray
                $null = New-VHD @vhdParams -Fixed
            }
            else {
                $null = New-VHD @vhdParams -Dynamic
            }
            
            # Open the created VHDX
            $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
            $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
            $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
            $op = New-Object VirtDiskApi+OPEN_VIRTUAL_DISK_PARAMETERS
            $op.Version = 1
            $handle = [IntPtr]::Zero
            $r = [VirtDiskApi]::OpenVirtualDisk([ref]$st, $Path, [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL, 0, [ref]$op, [ref]$handle)
            if ($r -ne 0) { throw ("OpenVirtualDisk failed: " + (New-Object ComponentModel.Win32Exception $r).Message) }
            return $handle
        }
        catch {
            Write-Host ("  Hyper-V failed: " + $_) -ForegroundColor Yellow
            if (Test-Path $Path) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }
        }
    }
    
    # Fall back to VirtDisk API with properly aligned structure
    Write-Host "  Using VirtDisk API..." -ForegroundColor DarkGray
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    
    $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    # Create properly initialized parameter structure
    $params = New-Object VirtDiskApi+CREATE_VIRTUAL_DISK_PARAMETERS_V2
    $params.Version = 2
    $params.UniqueId = [Guid]::NewGuid()
    $params.MaximumSize = $SizeBytes
    $params.BlockSizeInBytes = $blockSizeBytes
    $params.SectorSizeInBytes = [uint32]$SectorSize
    $params.PhysicalSectorSizeInBytes = [uint32]$SectorSize
    $params.ParentPath = [IntPtr]::Zero
    $params.SourcePath = [IntPtr]::Zero
    $params.OpenFlags = 0
    $params.ResiliencyGuid = [Guid]::Empty
    
    $flags = [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_NONE
    if ($FixedSize) {
        $flags = [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION
        Write-Host "  Allocating fixed disk (this may take a while)..." -ForegroundColor DarkGray
    }
    
    $handle = [IntPtr]::Zero
    $r = [VirtDiskApi]::CreateVirtualDisk(
        [ref]$st,
        $Path,
        [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL,
        [IntPtr]::Zero,
        $flags,
        0,
        [ref]$params,
        [IntPtr]::Zero,
        [ref]$handle
    )
    
    if ($r -ne 0) {
        throw ("CreateVirtualDisk failed: " + (New-Object ComponentModel.Win32Exception $r).Message)
    }
    
    return $handle
}

function Mount-RawVHDX {
    param([IntPtr]$Handle)
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    $ap = New-Object VirtDiskApi+ATTACH_VIRTUAL_DISK_PARAMETERS
    $ap.Version = 1
    $r = [VirtDiskApi]::AttachVirtualDisk($Handle, [IntPtr]::Zero, [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 0, [ref]$ap, [IntPtr]::Zero)
    if ($r -ne 0) { throw ("AttachVirtualDisk failed: " + (New-Object ComponentModel.Win32Exception $r).Message) }
    
    $pathSize = 520
    $pathBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($pathSize)
    try {
        $r = [VirtDiskApi]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSize, $pathBuf)
        if ($r -ne 0) { throw ("GetVirtualDiskPhysicalPath failed: " + (New-Object ComponentModel.Win32Exception $r).Message) }
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($pathBuf)
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($pathBuf) }
}

function Dismount-RawVHDX {
    param([IntPtr]$Handle)
    if ($Handle -eq [IntPtr]::Zero) { return }
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    $null = [VirtDiskApi]::DetachVirtualDisk($Handle, 0, 0)
    $null = [VirtDiskApi]::CloseHandle($Handle)
}

# ============================================================
# DISK INITIALIZATION
# ============================================================

function Initialize-BootableVHDX {
    param([string]$PhysicalPath, [string]$BootMode)
    
    Write-Host ("Initializing disk for " + $BootMode + " boot...") -ForegroundColor Cyan
    
    $diskNum = -1
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') { $diskNum = [int]$Matches[1] }
    else { throw ("Cannot parse disk number from: " + $PhysicalPath) }
    
    $disk = $null
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNum -ErrorAction SilentlyContinue
        if ($disk) { break }
    }
    if (-not $disk) { throw ("Disk " + $diskNum + " not found after waiting") }
    
    Write-Host ("  Disk " + $diskNum + ": " + (Format-ByteSize $disk.Size)) -ForegroundColor DarkGray
    
    # Clear any existing partitions
    if ($disk.PartitionStyle -ne 'RAW') {
        Write-Host "  Clearing existing partition table..." -ForegroundColor DarkGray
        Clear-Disk -Number $diskNum -RemoveData -RemoveOEM -Confirm:$false -ErrorAction SilentlyContinue
    }
    
    if ($BootMode -eq 'UEFI') {
        Initialize-Disk -Number $diskNum -PartitionStyle GPT
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating EFI partition (260MB)..." -ForegroundColor DarkGray
        $esp = New-Partition -DiskNumber $diskNum -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $null = Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false
        
        Write-Host "  Creating MSR partition (16MB)..." -ForegroundColor DarkGray
        $null = New-Partition -DiskNumber $diskNum -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $win = New-Partition -DiskNumber $diskNum -UseMaximumSize -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
        
        return @{ DiskNumber = $diskNum; EspPartition = $esp; WindowsPartition = $win; BootMode = 'UEFI' }
    }
    else {
        Initialize-Disk -Number $diskNum -PartitionStyle MBR
        Start-Sleep -Seconds 2
        
        Write-Host "  Creating System partition (500MB)..." -ForegroundColor DarkGray
        $sys = New-Partition -DiskNumber $diskNum -Size 500MB -IsActive
        $null = Format-Volume -Partition $sys -FileSystem NTFS -NewFileSystemLabel "System Reserved" -Confirm:$false
        
        Write-Host "  Creating Windows partition..." -ForegroundColor DarkGray
        $win = New-Partition -DiskNumber $diskNum -UseMaximumSize
        
        return @{ DiskNumber = $diskNum; SystemPartition = $sys; WindowsPartition = $win; BootMode = 'BIOS' }
    }
}

function Install-BootFiles {
    param([hashtable]$DiskInfo, [string]$WinLetter)
    
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $winPath = $WinLetter + ":\Windows"
    if (-not (Test-Path $winPath)) { throw ("Windows not found at " + $winPath) }
    
    $bootLetter = Get-AvailableDriveLetter
    if (-not $bootLetter) { throw "No available drive letters for boot partition" }
    
    $bootPart = $null
    $firmware = $null
    if ($DiskInfo.BootMode -eq 'UEFI') {
        $bootPart = $DiskInfo.EspPartition
        $firmware = 'UEFI'
    }
    else {
        $bootPart = $DiskInfo.SystemPartition
        $firmware = 'BIOS'
    }
    
    Write-Host ("  Assigning " + $bootLetter + " to boot partition...") -ForegroundColor DarkGray
    $bootPart | Set-Partition -NewDriveLetter $bootLetter
    Start-Sleep -Seconds 2
    
    try {
        Write-Host ("  Running bcdboot for " + $firmware + "...") -ForegroundColor DarkGray
        $bootDrive = $bootLetter + ":"
        $output = & bcdboot.exe $winPath /s $bootDrive /f $firmware 2>&1
        if ($LASTEXITCODE -ne 0) { throw ("bcdboot failed with exit code $LASTEXITCODE`: " + ($output -join ' ')) }
        Write-Host "  Boot files installed successfully" -ForegroundColor Green
    }
    finally {
        $accessPath = $bootLetter + ":\"
        try { $bootPart | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue } catch { }
    }
}

# ============================================================
# NTFS BITMAP FUNCTIONS
# ============================================================

function Get-NtfsVolumeData {
    param([string]$DriveLetter)
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = "\\.\" + $DriveLetter + ":"
    
    $handle = [NativeDiskApi]::CreateFile($volumePath, [NativeDiskApi]::GENERIC_READ, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($handle.IsInvalid) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume $volumePath (Error: $err)"
    }
    
    try {
        $bufSize = [Runtime.InteropServices.Marshal]::SizeOf([type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
        $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
        try {
            $ret = [uint32]0
            if (-not [NativeDiskApi]::DeviceIoControl($handle, [NativeDiskApi]::FSCTL_GET_NTFS_VOLUME_DATA, [IntPtr]::Zero, 0, $buf, $bufSize, [ref]$ret, [IntPtr]::Zero)) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "FSCTL_GET_NTFS_VOLUME_DATA failed (Error: $err)"
            }
            $data = [Runtime.InteropServices.Marshal]::PtrToStructure($buf, [type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
            return @{
                TotalClusters = $data.TotalClusters
                FreeClusters = $data.FreeClusters
                BytesPerCluster = $data.BytesPerCluster
                BytesPerSector = $data.BytesPerSector
            }
        }
        finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    }
    finally { $handle.Close() }
}

function Get-VolumeBitmap {
    param([string]$DriveLetter, [long]$TotalClusters)
    
    Write-Host "Reading allocation bitmap..." -ForegroundColor Cyan
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = "\\.\" + $DriveLetter + ":"
    
    $handle = [NativeDiskApi]::CreateFile($volumePath, [NativeDiskApi]::GENERIC_READ, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($handle.IsInvalid) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume for bitmap (Error: $err)"
    }
    
    try {
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $bitmap = New-Object byte[] $bitmapBytes
        
        $lcn = [long]0
        $chunkSize = 1048576  # 1MB buffer
        $outBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $inBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        $offset = [long]0
        
        try {
            while ($lcn -lt $TotalClusters) {
                [Runtime.InteropServices.Marshal]::WriteInt64($inBuf, 0, $lcn)
                $ret = [uint32]0
                $success = [NativeDiskApi]::DeviceIoControl(
                    $handle,
                    [NativeDiskApi]::FSCTL_GET_VOLUME_BITMAP,
                    $inBuf, 8,
                    $outBuf, $chunkSize,
                    [ref]$ret,
                    [IntPtr]::Zero
                )
                
                $lastErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                
                # ERROR_MORE_DATA (234) is expected when there's more bitmap data
                if (-not $success -and $lastErr -ne [NativeDiskApi]::ERROR_MORE_DATA) {
                    throw "FSCTL_GET_VOLUME_BITMAP failed (Error: $lastErr)"
                }
                
                if ($ret -lt 16) { break }  # No data returned
                
                $dataBytes = [int]($ret - 16)
                if ($dataBytes -gt 0) {
                    $copyLen = [long][math]::Min($dataBytes, $bitmap.Length - $offset)
                    if ($copyLen -gt 0) {
                        [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($outBuf, 16), $bitmap, [int]$offset, [int]$copyLen)
                        $offset += $copyLen
                    }
                }
                
                $read = [long]$dataBytes * 8
                if ($read -le 0) { break }
                $lcn += $read
                
                $pct = Get-ClampedPercent $lcn $TotalClusters
                Write-Progress -Activity "Reading Bitmap" -PercentComplete $pct -Status "$pct%"
            }
            Write-Progress -Activity "Reading Bitmap" -Completed
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($outBuf)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($inBuf)
        }
        return $bitmap
    }
    finally { $handle.Close() }
}

function Get-AllocatedRanges {
    param([byte[]]$Bitmap, [long]$TotalClusters, [uint32]$BytesPerCluster)
    
    Write-Host "Analyzing bitmap (optimized)..." -ForegroundColor Cyan
    $ranges = [Collections.ArrayList]::new()
    $totalBytes = [long][math]::Ceiling($TotalClusters / 8.0)
    $start = [long]-1
    $allocated = [long]0
    
    # Pre-compute lookup table for popcount (number of set bits in a byte)
    $popCount = New-Object int[] 256
    for ($i = 0; $i -lt 256; $i++) {
        $count = 0
        $val = $i
        while ($val -ne 0) {
            $count += ($val -band 1)
            $val = $val -shr 1
        }
        $popCount[$i] = $count
    }
    
    $progressInterval = [math]::Max(1, [int]($totalBytes / 100))
    
    for ($byteIdx = [long]0; $byteIdx -lt $totalBytes; $byteIdx++) {
        $b = $Bitmap[$byteIdx]
        $clusterBase = $byteIdx * 8
        
        if ($b -eq 0xFF) {
            # All 8 clusters allocated
            $clustersInByte = [math]::Min(8, $TotalClusters - $clusterBase)
            if ($start -eq -1) { $start = $clusterBase }
            $allocated += $clustersInByte
        }
        elseif ($b -eq 0) {
            # All 8 clusters free - close any open range
            if ($start -ne -1) {
                $null = $ranges.Add([PSCustomObject]@{
                    Start = $start
                    End = $clusterBase - 1
                    Count = $clusterBase - $start
                })
                $start = -1
            }
        }
        else {
            # Mixed byte - check individual bits
            $allocated += $popCount[$b]
            
            for ($bit = 0; $bit -lt 8; $bit++) {
                $cluster = $clusterBase + $bit
                if ($cluster -ge $TotalClusters) { break }
                
                $isAlloc = ($b -band (1 -shl $bit)) -ne 0
                if ($isAlloc) {
                    if ($start -eq -1) { $start = $cluster }
                }
                elseif ($start -ne -1) {
                    $null = $ranges.Add([PSCustomObject]@{
                        Start = $start
                        End = $cluster - 1
                        Count = $cluster - $start
                    })
                    $start = -1
                }
            }
        }
        
        if ($byteIdx % $progressInterval -eq 0) {
            $pct = Get-ClampedPercent $byteIdx $totalBytes
            Write-Progress -Activity "Analyzing" -PercentComplete $pct -Status "$pct%"
        }
    }
    
    # Close final range
    if ($start -ne -1) {
        $null = $ranges.Add([PSCustomObject]@{
            Start = $start
            End = $TotalClusters - 1
            Count = $TotalClusters - $start
        })
    }
    Write-Progress -Activity "Analyzing" -Completed
    
    # Merge nearby ranges (within 256 clusters / ~1MB gap)
    Write-Host "Merging adjacent ranges..." -ForegroundColor Cyan
    $merged = [Collections.ArrayList]::new()
    $prev = $null
    
    foreach ($r in $ranges) {
        if ($null -eq $prev) {
            $prev = $r
            continue
        }
        
        $gap = $r.Start - $prev.End - 1
        if ($gap -le 256) {
            # Merge ranges
            $prev = [PSCustomObject]@{
                Start = $prev.Start
                End = $r.End
                Count = $r.End - $prev.Start + 1
            }
        }
        else {
            $null = $merged.Add($prev)
            $prev = $r
        }
    }
    if ($prev) { $null = $merged.Add($prev) }
    
    $allocBytes = [long]$allocated * $BytesPerCluster
    Write-Host ("  Allocated: " + (Format-ByteSize $allocBytes) + " in " + $merged.Count + " ranges") -ForegroundColor DarkGray
    
    return @{
        Ranges = $merged
        AllocatedClusters = $allocated
        AllocatedBytes = $allocBytes
    }
}

# ============================================================
# RAW I/O FUNCTIONS
# ============================================================

function Open-RawDisk {
    param([string]$Path, [string]$Access)
    
    $flags = [NativeDiskApi]::GENERIC_READ
    if ($Access -eq 'Write') { $flags = [NativeDiskApi]::GENERIC_WRITE }
    elseif ($Access -eq 'ReadWrite') { $flags = [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE }
    
    $handle = [NativeDiskApi]::CreateFile(
        $Path,
        $flags,
        ([NativeDiskApi]::FILE_SHARE_READ -bor [NativeDiskApi]::FILE_SHARE_WRITE),
        [IntPtr]::Zero,
        [NativeDiskApi]::OPEN_EXISTING,
        ([NativeDiskApi]::FILE_FLAG_NO_BUFFERING -bor [NativeDiskApi]::FILE_FLAG_WRITE_THROUGH),
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw ("Failed to open $Path for $Access access (Error: $err)")
    }
    return $handle
}

function Copy-FullVolume {
    param(
        [string]$Source,
        [string]$DiskPath,
        [long]$Offset,
        [uint64]$Total,
        [int]$BlockSize
    )
    
    Write-Host ("Copying " + (Format-ByteSize $Total) + " (full copy)...") -ForegroundColor Cyan
    $srcH = Open-RawDisk $Source 'Read'
    $dstH = Open-RawDisk $DiskPath 'Write'
    
    try {
        $buf = New-Object byte[] $BlockSize
        $copied = [uint64]0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        $lastUpdate = [DateTime]::Now
        
        while ($copied -lt $Total) {
            $remaining = $Total - $copied
            $toRead = [math]::Min([uint64]$BlockSize, $remaining)
            $aligned = [uint32]([math]::Ceiling($toRead / 4096) * 4096)
            
            $read = [uint32]0
            if (-not [NativeDiskApi]::ReadFile($srcH, $buf, $aligned, [ref]$read, [IntPtr]::Zero)) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Read failed at offset $copied (Error: $err)"
            }
            if ($read -eq 0) { break }
            
            $pos = [long]0
            if (-not [NativeDiskApi]::SetFilePointerEx($dstH, ($Offset + $copied), [ref]$pos, 0)) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Seek failed to offset $($Offset + $copied) (Error: $err)"
            }
            
            $toWrite = [math]::Min($read, $remaining)
            $alignedW = [uint32]([math]::Ceiling($toWrite / 4096) * 4096)
            $written = [uint32]0
            if (-not [NativeDiskApi]::WriteFile($dstH, $buf, $alignedW, [ref]$written, [IntPtr]::Zero)) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Write failed at offset $($Offset + $copied) (Error: $err)"
            }
            
            $copied += $toWrite
            $pct = Get-ClampedPercent $copied $Total
            
            # Update progress every 500ms or on percentage change
            $now = [DateTime]::Now
            if ($pct -gt $lastPct -or ($now - $lastUpdate).TotalMilliseconds -gt 500) {
                $speed = 0
                $eta = ""
                if ($sw.Elapsed.TotalSeconds -gt 0) {
                    $speed = $copied / $sw.Elapsed.TotalSeconds / 1MB
                    if ($speed -gt 0) {
                        $remainingBytes = $Total - $copied
                        $remainingSec = $remainingBytes / ($speed * 1MB)
                        $eta = " ETA: " + (Format-TimeSpan ([TimeSpan]::FromSeconds($remainingSec)))
                    }
                }
                Write-Progress -Activity "Copying" -Status ("{0}% - {1:N1} MB/s{2}" -f $pct, $speed, $eta) -PercentComplete $pct
                $lastPct = $pct
                $lastUpdate = $now
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        
        $avgSpeed = 0
        if ($sw.Elapsed.TotalSeconds -gt 0) { $avgSpeed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
        Write-Host ("Copied " + (Format-ByteSize $copied) + " in " + (Format-TimeSpan $sw.Elapsed) + " (" + [math]::Round($avgSpeed,1).ToString() + " MB/s avg)") -ForegroundColor Green
    }
    finally {
        if ($srcH -and -not $srcH.IsClosed) { $srcH.Close() }
        if ($dstH -and -not $dstH.IsClosed) { $dstH.Close() }
    }
}

function Copy-AllocatedBlocks {
    param(
        [string]$Source,
        [string]$DiskPath,
        [long]$Offset,
        $Ranges,
        [uint32]$ClusterSize,
        [long]$AllocBytes,
        [int]$BlockSize
    )
    
    # Align block size to cluster size
    if ($BlockSize % $ClusterSize -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $ClusterSize) * $ClusterSize)
    }
    $clustersPerBlock = [long]($BlockSize / $ClusterSize)
    
    Write-Host ("Copying " + (Format-ByteSize $AllocBytes) + " allocated data...") -ForegroundColor Cyan
    $srcH = Open-RawDisk $Source 'Read'
    $dstH = Open-RawDisk $DiskPath 'Write'
    
    try {
        $buf = New-Object byte[] $BlockSize
        $copied = [long]0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        $lastUpdate = [DateTime]::Now
        
        foreach ($r in $Ranges) {
            $cluster = [long]$r.Start
            $remaining = [long]$r.Count
            
            while ($remaining -gt 0) {
                $toRead = [math]::Min($clustersPerBlock, $remaining)
                $bytes = [uint32]($toRead * $ClusterSize)
                $srcOffset = [long]$cluster * $ClusterSize
                
                $pos = [long]0
                if (-not [NativeDiskApi]::SetFilePointerEx($srcH, $srcOffset, [ref]$pos, 0)) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Source seek failed to cluster $cluster (Error: $err)"
                }
                
                $read = [uint32]0
                if (-not [NativeDiskApi]::ReadFile($srcH, $buf, $bytes, [ref]$read, [IntPtr]::Zero)) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Read failed at cluster $cluster (Error: $err)"
                }
                
                if (-not [NativeDiskApi]::SetFilePointerEx($dstH, ($Offset + $srcOffset), [ref]$pos, 0)) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Destination seek failed (Error: $err)"
                }
                
                $written = [uint32]0
                if (-not [NativeDiskApi]::WriteFile($dstH, $buf, $read, [ref]$written, [IntPtr]::Zero)) {
                    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Write failed (Error: $err)"
                }
                
                $copied += $read
                $cluster += $toRead
                $remaining -= $toRead
                
                $pct = Get-ClampedPercent $copied $AllocBytes
                $now = [DateTime]::Now
                
                if ($pct -gt $lastPct -or ($now - $lastUpdate).TotalMilliseconds -gt 500) {
                    $speed = 0
                    $eta = ""
                    if ($sw.Elapsed.TotalSeconds -gt 0) {
                        $speed = $copied / $sw.Elapsed.TotalSeconds / 1MB
                        if ($speed -gt 0) {
                            $remainingBytes = $AllocBytes - $copied
                            $remainingSec = $remainingBytes / ($speed * 1MB)
                            $eta = " ETA: " + (Format-TimeSpan ([TimeSpan]::FromSeconds($remainingSec)))
                        }
                    }
                    Write-Progress -Activity "Copying" -Status ("{0}% - {1:N1} MB/s{2}" -f $pct, $speed, $eta) -PercentComplete $pct
                    $lastPct = $pct
                    $lastUpdate = $now
                }
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        
        $avgSpeed = 0
        if ($sw.Elapsed.TotalSeconds -gt 0) { $avgSpeed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
        Write-Host ("Copied " + (Format-ByteSize $copied) + " in " + (Format-TimeSpan $sw.Elapsed) + " (" + [math]::Round($avgSpeed,1).ToString() + " MB/s avg)") -ForegroundColor Green
    }
    finally {
        if ($srcH -and -not $srcH.IsClosed) { $srcH.Close() }
        if ($dstH -and -not $dstH.IsClosed) { $dstH.Close() }
    }
}

# ============================================================
# MAIN CLONE FUNCTION
# ============================================================

function New-BootableVolumeClone {
    param(
        [string]$SourceVolume,
        [string]$DestinationVHDX,
        [string]$BootMode = 'UEFI',
        [switch]$FullCopy,
        [switch]$FixedSizeVHDX,
        [switch]$SkipBootFix,
        [int]$BlockSizeMB = 4
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    $winLetter = $null
    $diskInfo = $null
    $startTime = [DateTime]::Now
    
    try {
        # Validate source volume
        $letter = $SourceVolume.TrimEnd(':', '\').ToUpper()
        if ($letter.Length -ne 1 -or $letter -lt 'A' -or $letter -gt 'Z') {
            throw "Invalid source volume: $SourceVolume. Please specify a drive letter (e.g., 'C' or 'C:')"
        }
        
        $partition = Get-Partition -DriveLetter $letter -ErrorAction Stop
        $volume = Get-Volume -DriveLetter $letter -ErrorAction Stop
        
        # Check file system type
        if ($volume.FileSystemType -ne 'NTFS') {
            if (-not $FullCopy) {
                Write-Warning "Non-NTFS volume ($($volume.FileSystemType)) - forcing full copy mode"
                $FullCopy = $true
            }
        }
        
        # Check for BitLocker
        try {
            $blStatus = Get-BitLockerVolume -MountPoint "$letter`:" -ErrorAction SilentlyContinue
            if ($blStatus -and $blStatus.ProtectionStatus -eq 'On') {
                throw "Volume $letter`: is BitLocker encrypted. Please unlock or disable BitLocker before cloning."
            }
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            # BitLocker cmdlet not available, skip check
        }
        
        # Get source sector size for VHDX creation
        $sourceSectorSize = Get-VolumeSectorSize $letter
        Write-Host ("  Source sector size: " + $sourceSectorSize + " bytes") -ForegroundColor DarkGray
        
        # Calculate VHDX size (virtual size is always based on full partition)
        $bootSize = 300MB
        if ($BootMode -ne 'UEFI') { $bootSize = 550MB }
        $vhdxSize = [uint64]($partition.Size + $bootSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        # Calculate actual space needed on destination
        # For dynamic VHDX with smart copy: only used space + boot + overhead
        # For fixed VHDX or full copy: full VHDX size
        $usedSpace = $volume.Size - $volume.SizeRemaining
        if ($FixedSizeVHDX -or $FullCopy) {
            $requiredDestSpace = $vhdxSize
        }
        else {
            # Dynamic VHDX with smart copy - need used space + boot partitions + VHDX metadata overhead (~5%)
            $requiredDestSpace = [uint64](($usedSpace + $bootSize + 100MB) * 1.05)
        }
        
        # Verify destination space
        Test-DestinationSpace $DestinationVHDX $requiredDestSpace
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host "BOOTABLE VOLUME CLONE" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("  Source:      " + $letter + ": (" + $volume.FileSystemLabel + ")") -ForegroundColor White
        Write-Host ("  Destination: " + $DestinationVHDX) -ForegroundColor White
        Write-Host ("  Used Space:  " + (Format-ByteSize $usedSpace)) -ForegroundColor White
        Write-Host ("  VHDX Size:   " + (Format-ByteSize $vhdxSize) + " (virtual)") -ForegroundColor White
        Write-Host ("  Disk Needed: ~" + (Format-ByteSize $requiredDestSpace)) -ForegroundColor White
        Write-Host ("  Boot Mode:   " + $BootMode) -ForegroundColor White
        $copyModeText = "Smart (allocated blocks only)"
        if ($FullCopy) { $copyModeText = "Full (entire volume)" }
        Write-Host ("  Copy Mode:   " + $copyModeText) -ForegroundColor White
        $vhdxTypeText = "Dynamic"
        if ($FixedSizeVHDX) { $vhdxTypeText = "Fixed" }
        Write-Host ("  VHDX Type:   " + $vhdxTypeText) -ForegroundColor White
        Write-Host ("  Block Size:  " + $BlockSizeMB + " MB") -ForegroundColor White
        Write-Host ""
        
        $volData = $null
        if (-not $FullCopy) {
            $volData = Get-NtfsVolumeData $letter
            $used = ($volData.TotalClusters - $volData.FreeClusters) * $volData.BytesPerCluster
            $free = $volData.FreeClusters * $volData.BytesPerCluster
            Write-Host ("  Volume Data:") -ForegroundColor DarkGray
            Write-Host ("    Total clusters: " + $volData.TotalClusters.ToString("N0")) -ForegroundColor DarkGray
            Write-Host ("    Cluster size:   " + $volData.BytesPerCluster + " bytes") -ForegroundColor DarkGray
            Write-Host ("    Used space:     " + (Format-ByteSize $used)) -ForegroundColor DarkGray
            Write-Host ("    Free space:     " + (Format-ByteSize $free)) -ForegroundColor DarkGray
            Write-Host ""
        }
        
        # Create VSS snapshot
        $volPath = $letter + ":\"
        $snapshot = New-VssSnapshot $volPath
        Write-Host ("  Snapshot device: " + $snapshot.DeviceObject) -ForegroundColor Green
        Write-Host ""
        
        # Create and attach VHDX
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX -BlockSizeMB $BlockSizeMB -SectorSize $sourceSectorSize
        $physPath = Mount-RawVHDX $vhdHandle
        Write-Host ("  Physical path: " + $physPath) -ForegroundColor Green
        Write-Host ""
        
        # Wait for disk to be recognized
        Start-Sleep -Seconds 3
        
        # Initialize disk with boot structure
        $diskInfo = Initialize-BootableVHDX $physPath $BootMode
        Start-Sleep -Seconds 2
        
        $winPart = $diskInfo.WindowsPartition
        $diskPath = "\\.\PhysicalDrive" + $diskInfo.DiskNumber
        $blockBytes = $BlockSizeMB * 1MB
        
        Write-Host ""
        Write-Host ("  Target partition offset: " + $winPart.Offset) -ForegroundColor DarkGray
        Write-Host ""
        
        # Perform the copy
        if ($FullCopy) {
            Copy-FullVolume $snapshot.DeviceObject $diskPath $winPart.Offset $partition.Size $blockBytes
        }
        else {
            $bitmap = Get-VolumeBitmap $letter $volData.TotalClusters
            $alloc = Get-AllocatedRanges $bitmap $volData.TotalClusters $volData.BytesPerCluster
            Copy-AllocatedBlocks $snapshot.DeviceObject $diskPath $winPart.Offset $alloc.Ranges $volData.BytesPerCluster $alloc.AllocatedBytes $blockBytes
        }
        
        # Install boot files
        if (-not $SkipBootFix) {
            $winLetter = Get-AvailableDriveLetter
            if (-not $winLetter) { throw "No drive letters available for Windows partition" }
            
            Write-Host ""
            Write-Host ("Assigning " + $winLetter + ": to Windows partition...") -ForegroundColor Cyan
            $winPart | Set-Partition -NewDriveLetter $winLetter
            Start-Sleep -Seconds 2
            
            # Format the Windows partition
            Write-Host "Formatting Windows partition..." -ForegroundColor Cyan
            $null = Format-Volume -Partition $winPart -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            
            Install-BootFiles $diskInfo $winLetter
            
            Write-Host "Removing temporary drive letter..." -ForegroundColor Cyan
            $accessPath = $winLetter + ":\"
            try { $winPart | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue } catch { }
            $winLetter = $null
        }
        
        $totalTime = [DateTime]::Now - $startTime
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host "CLONE COMPLETE" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host ""
        Write-Host ("  File:       " + $DestinationVHDX) -ForegroundColor White
        $fileSize = (Get-Item $DestinationVHDX).Length
        Write-Host ("  File Size:  " + (Format-ByteSize $fileSize)) -ForegroundColor White
        Write-Host ("  VHDX Size:  " + (Format-ByteSize $vhdxSize)) -ForegroundColor White
        Write-Host ("  Duration:   " + (Format-TimeSpan $totalTime)) -ForegroundColor White
        Write-Host ""
        Write-Host "  The VHDX is ready to boot in Hyper-V or other hypervisors." -ForegroundColor Cyan
        Write-Host ""
        
        return $DestinationVHDX
    }
    catch {
        Write-Host ""
        Write-Host ("Clone failed: " + $_.Exception.Message) -ForegroundColor Red
        Write-Host ("  " + $_.ScriptStackTrace) -ForegroundColor DarkRed
        
        # Cleanup on failure
        if ($winLetter -and $diskInfo -and $diskInfo.WindowsPartition) {
            $accessPath = $winLetter + ":\"
            try { $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue } catch { }
        }
        
        if ($vhdHandle -ne [IntPtr]::Zero) {
            try { Dismount-RawVHDX $vhdHandle } catch { }
            $vhdHandle = [IntPtr]::Zero
        }
        
        if (Test-Path $DestinationVHDX -ErrorAction SilentlyContinue) {
            Write-Host "Cleaning up partial VHDX file..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            Remove-Item $DestinationVHDX -Force -ErrorAction SilentlyContinue
        }
        
        throw
    }
    finally {
        if ($vhdHandle -ne [IntPtr]::Zero) {
            Dismount-RawVHDX $vhdHandle
        }
        if ($snapshot) {
            Remove-VssSnapshot $snapshot.Id
        }
    }
}

# ============================================================
# INTERACTIVE MODE
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "              BOOTABLE VOLUME CLONE UTILITY v$script:ScriptVersion" -ForegroundColor Yellow
    Write-Host "        Clone a running Windows volume to bootable VHDX" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Start-InteractiveMode {
    $bootMode = 'UEFI'
    $fullCopy = $false
    $fixedVhdx = $false
    $blockSize = 4
    
    while ($true) {
        Show-Banner
        
        # Get volumes using explicit loop
        $volumeList = [System.Collections.ArrayList]::new()
        $allVolumes = Get-Volume
        foreach ($v in $allVolumes) {
            if ($v.DriveLetter -and $v.DriveType -eq 'Fixed' -and $v.Size -gt 0) {
                $null = $volumeList.Add($v)
            }
        }
        
        # Sort by drive letter
        $volumes = $volumeList | Sort-Object DriveLetter
        $volumeCount = $volumeList.Count
        
        if ($volumeCount -eq 0) {
            Write-Host "  No suitable volumes found!" -ForegroundColor Red
            Wait-ForKeyPress
            return
        }
        
        Write-Host "  Available Volumes:" -ForegroundColor White
        Write-Host ""
        
        for ($i = 0; $i -lt $volumeCount; $i++) {
            $v = $volumeList[$i]
            $num = $i + 1
            $used = [math]::Round(($v.Size - $v.SizeRemaining) / 1GB, 1)
            $total = [math]::Round($v.Size / 1GB, 1)
            $label = $v.FileSystemLabel
            if (-not $label) { $label = "Local Disk" }
            $fs = $v.FileSystemType
            if (-not $fs) { $fs = "Unknown" }
            Write-Host ("    [" + $num + "] " + $v.DriveLetter + ": " + $label + " - " + $used + " GB used / " + $total + " GB total (" + $fs + ")") -ForegroundColor Yellow
        }
        Write-Host "    [0] Exit" -ForegroundColor Red
        Write-Host ""
        
        Write-Host ("  Select volume (0-" + $volumeCount + "): ") -ForegroundColor White -NoNewline
        $input1 = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($input1)) { continue }
        
        $sel = -1
        $parseOK = [int]::TryParse($input1.Trim(), [ref]$sel)
        if (-not $parseOK -or $sel -lt 0 -or $sel -gt $volumeCount) {
            Write-Host ("  Invalid selection. Enter a number from 0 to " + $volumeCount + ".") -ForegroundColor Red
            Start-Sleep -Seconds 2
            continue
        }
        if ($sel -eq 0) { Write-Host ""; Write-Host "  Goodbye!" -ForegroundColor Cyan; return }
        
        $srcVol = $volumeList[$sel - 1]
        $srcLetter = [string]$srcVol.DriveLetter
        
        # Default destination - prefer different drive with most space
        $dateStr = Get-Date -Format 'yyyyMMdd_HHmmss'
        $defaultDest = $srcLetter + ":\VMs\Bootable_" + $srcLetter + "_" + $dateStr + ".vhdx"
        
        # Calculate required space based on used data (for smart copy with dynamic VHDX)
        # Used space + boot partition (~550MB) + overhead
        $usedSpace = $srcVol.Size - $srcVol.SizeRemaining
        $requiredSpace = [uint64](($usedSpace + 600MB) * 1.1)  # 110% of used space + boot
        
        # Find other drives with sufficient space
        $otherDrives = [System.Collections.ArrayList]::new()
        foreach ($v in $allVolumes) {
            if ($v.DriveLetter -and ([string]$v.DriveLetter) -ne $srcLetter -and $v.DriveType -eq 'Fixed' -and $v.SizeRemaining -gt $requiredSpace) {
                $null = $otherDrives.Add($v)
            }
        }
        if ($otherDrives.Count -gt 0) {
            $bestDrive = ($otherDrives | Sort-Object SizeRemaining -Descending)[0]
            $defaultDest = ([string]$bestDrive.DriveLetter) + ":\VMs\Bootable_" + $srcLetter + "_" + $dateStr + ".vhdx"
        }
        
        Write-Host ""
        Write-Host "  Destination VHDX path"
        Write-Host ("  [Default: " + $defaultDest + "]")
        Write-Host "  : " -NoNewline
        $destPath = Read-Host
        if ([string]::IsNullOrWhiteSpace($destPath)) { $destPath = $defaultDest }
        if (-not $destPath.ToLower().EndsWith('.vhdx')) { $destPath = $destPath + '.vhdx' }
        
        # Options menu
        $exitOpts = $false
        while (-not $exitOpts) {
            Show-Banner
            
            $label = $srcVol.FileSystemLabel
            if (-not $label) { $label = "Local Disk" }
            $usedGB = [math]::Round(($srcVol.Size - $srcVol.SizeRemaining) / 1GB, 2)
            $totalGB = [math]::Round($srcVol.Size / 1GB, 2)
            Write-Host ("  Source: " + $srcLetter + ": (" + $label + ") - " + $usedGB + " GB used / " + $totalGB + " GB total") -ForegroundColor White
            Write-Host ("  Destination: " + $destPath) -ForegroundColor White
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor White
            Write-Host ("    [1] Boot Mode:  " + $bootMode) -ForegroundColor Yellow
            $copyText = "Smart (allocated blocks only)"
            if ($fullCopy) { $copyText = "Full (entire volume)" }
            Write-Host ("    [2] Copy Mode:  " + $copyText) -ForegroundColor Yellow
            $vhdxText = "Dynamic (grows as needed)"
            if ($fixedVhdx) { $vhdxText = "Fixed (pre-allocated)" }
            Write-Host ("    [3] VHDX Type:  " + $vhdxText) -ForegroundColor Yellow
            Write-Host ("    [4] Block Size: " + $blockSize + " MB") -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Path" -ForegroundColor Cyan
            Write-Host "    [B] Back to volume selection" -ForegroundColor DarkYellow
            Write-Host "    [Q] Quit" -ForegroundColor Red
            Write-Host ""
            
            Write-Host "  Choice: " -ForegroundColor White -NoNewline
            $choice = (Read-Host).Trim().ToUpper()
            
            switch ($choice) {
                '1' {
                    if ($bootMode -eq 'UEFI') { $bootMode = 'BIOS' }
                    else { $bootMode = 'UEFI' }
                }
                '2' { $fullCopy = -not $fullCopy }
                '3' { $fixedVhdx = -not $fixedVhdx }
                '4' {
                    Write-Host ("  Block size in MB (1-64) [" + $blockSize + "]: ") -NoNewline
                    $bs = Read-Host
                    $bsNum = 0
                    if (-not [string]::IsNullOrWhiteSpace($bs) -and [int]::TryParse($bs.Trim(), [ref]$bsNum) -and $bsNum -ge 1 -and $bsNum -le 64) {
                        $blockSize = $bsNum
                    }
                }
                'C' {
                    Write-Host ("  New path [" + $destPath + "]: ") -NoNewline
                    $np = Read-Host
                    if (-not [string]::IsNullOrWhiteSpace($np)) {
                        $destPath = $np.Trim()
                        if (-not $destPath.ToLower().EndsWith('.vhdx')) { $destPath = $destPath + '.vhdx' }
                    }
                }
                'B' { $exitOpts = $true }
                'Q' { Write-Host ""; Write-Host "  Goodbye!" -ForegroundColor Cyan; return }
                '0' { Write-Host ""; Write-Host "  Goodbye!" -ForegroundColor Cyan; return }
                'S' {
                    if (Test-Path $destPath) {
                        Write-Host "  File already exists. Overwrite? (y/N): " -ForegroundColor Yellow -NoNewline
                        $ow = (Read-Host).Trim().ToLower()
                        if ($ow -ne 'y' -and $ow -ne 'yes') { continue }
                        Remove-Item $destPath -Force
                    }
                    
                    Write-Host ""
                    Write-Host "  Ready to clone:" -ForegroundColor Cyan
                    Write-Host ("    Source:     " + $srcLetter + ":") -ForegroundColor White
                    Write-Host ("    Target:     " + $destPath) -ForegroundColor White
                    Write-Host ("    Boot Mode:  " + $bootMode) -ForegroundColor White
                    $estSize = [math]::Round((($srcVol.Size - $srcVol.SizeRemaining) + 600MB) / 1GB, 2)
                    if ($fixedVhdx -or $fullCopy) {
                        $estSize = [math]::Round(($srcVol.Size + 600MB) / 1GB, 2)
                    }
                    Write-Host ("    Est. Size:  ~" + $estSize + " GB") -ForegroundColor White
                    Write-Host ""
                    Write-Host "  Start clone? (Y/n): " -ForegroundColor Green -NoNewline
                    $confirm = (Read-Host).Trim().ToLower()
                    if ($confirm -eq 'n' -or $confirm -eq 'no') { continue }
                    
                    Write-Host ""
                    try {
                        New-BootableVolumeClone -SourceVolume $srcLetter -DestinationVHDX $destPath -BootMode $bootMode -FullCopy:$fullCopy -FixedSizeVHDX:$fixedVhdx -BlockSizeMB $blockSize
                    }
                    catch {
                        Write-Host ""
                        Write-Host ("  Operation failed: " + $_.Exception.Message) -ForegroundColor Red
                    }
                    
                    Write-Host ""
                    Wait-ForKeyPress
                    
                    Write-Host "  Clone another volume? (y/N): " -NoNewline
                    $another = (Read-Host).Trim().ToLower()
                    if ($another -ne 'y' -and $another -ne 'yes') {
                        Write-Host ""
                        Write-Host "  Goodbye!" -ForegroundColor Cyan
                        return
                    }
                    $exitOpts = $true
                }
                default {
                    # Ignore invalid input
                }
            }
        }
    }
}

# ============================================================
# ENTRY POINT
# ============================================================

if ($PSCmdlet.ParameterSetName -eq 'Interactive' -or (-not $SourceVolume -and -not $DestinationVHDX)) {
    Start-InteractiveMode
}
else {
    if (-not $SourceVolume -or -not $DestinationVHDX) {
        throw "Both -SourceVolume and -DestinationVHDX are required in command-line mode"
    }
    New-BootableVolumeClone -SourceVolume $SourceVolume -DestinationVHDX $DestinationVHDX -BootMode $BootMode -FullCopy:$FullCopy -FixedSizeVHDX:$FixedSizeVHDX -SkipBootFix:$SkipBootFix -BlockSizeMB $BlockSizeMB
}
