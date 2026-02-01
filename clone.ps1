#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a live Windows volume to a bootable VHDX file.
.DESCRIPTION
    Creates a VSS snapshot of a running Windows volume and copies it to a bootable
    VHDX virtual disk. The resulting VHDX can be used in Hyper-V or for Native VHD Boot.
.PARAMETER SourceVolume
    Drive letter of the Windows volume to clone (e.g., "C:" or "C")
.PARAMETER DestinationVHDX
    Path for the output VHDX file
.PARAMETER BootMode
    Boot mode: "UEFI" (default) or "BIOS"
.PARAMETER FullCopy
    Copy all sectors including free space (slower but safer)
.PARAMETER FixedSizeVHDX
    Create a fixed-size VHDX instead of dynamic
.PARAMETER BlockSizeMB
    I/O block size in megabytes (default: 4)
.PARAMETER SkipBootFix
    Skip boot configuration (creates non-bootable clone)
.EXAMPLE
    .\Clone-BootableVolume.ps1
    Runs in interactive menu mode
.EXAMPLE
    .\Clone-BootableVolume.ps1 -SourceVolume C: -DestinationVHDX D:\VMs\Clone.vhdx
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

try {
    if ($null -ne [Console]::OutputEncoding) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
}
catch { }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires Administrator privileges. Please run as Administrator."
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
    param([string]$Message = "Press Enter to continue...")
    Write-Host ("  " + $Message) -ForegroundColor Gray
    $null = Read-Host
}

function Get-AvailableDriveLetter {
    $usedLetters = [System.Collections.ArrayList]::new()
    
    Get-Volume | ForEach-Object {
        if ($_.DriveLetter) {
            $null = $usedLetters.Add([string]$_.DriveLetter)
        }
    }
    
    Get-CimInstance Win32_MappedLogicalDisk -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.DeviceID -and $_.DeviceID.Length -gt 0) {
            $null = $usedLetters.Add([string]$_.DeviceID[0])
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
    public const uint FILE_BEGIN = 0;

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
# VHDX PARAMETER BUFFER FUNCTIONS
# ============================================================

function New-VhdxParameterBuffer {
    param(
        [Parameter(Mandatory)][Guid]$UniqueId,
        [Parameter(Mandatory)][uint64]$MaximumSize
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
    
    $bufferSize = 56
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
    
    # Zero the buffer
    for ($i = 0; $i -lt $bufferSize; $i++) {
        [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, [byte]0)
    }
    
    # Version = 1
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 1)
    
    # UniqueId at offset 4
    $guidBytes = $UniqueId.ToByteArray()
    [System.Runtime.InteropServices.Marshal]::Copy($guidBytes, 0, [IntPtr]::Add($ptr, 4), 16)
    
    # MaximumSize at offset 24
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, 24, [long]$MaximumSize)
    
    # BlockSizeInBytes at offset 32 = 0 (use default)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 32, 0)
    
    # SectorSizeInBytes at offset 36 = 512
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 36, 512)
    
    return $ptr
}

function Remove-VhdxParameterBuffer {
    param([IntPtr]$Ptr)
    if ($Ptr -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Ptr)
    }
}

# ============================================================
# VSS SNAPSHOT FUNCTIONS
# ============================================================

function New-VssSnapshot {
    param([Parameter(Mandatory)][string]$Volume)
    
    if (-not $Volume.EndsWith("\")) {
        $Volume = $Volume + "\"
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
            3  = 'Volume not found'
            4  = 'Volume not supported'
            5  = 'Unsupported context'
            6  = 'Insufficient storage'
            7  = 'Volume in use'
            8  = 'Max shadow copies reached'
            9  = 'Operation in progress'
            10 = 'Provider vetoed'
            11 = 'Provider not registered'
            12 = 'Provider failure'
        }
        $msg = $errorMessages[[int]$result.ReturnValue]
        if (-not $msg) { $msg = "Unknown error" }
        throw ("Failed to create shadow copy. Error " + $result.ReturnValue + ": " + $msg)
    }
    
    $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
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
    param([Parameter(Mandatory)][string]$ShadowId)
    
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    
    $shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) {
        Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue
    }
}

# ============================================================
# VIRTUAL DISK FUNCTIONS
# ============================================================

function New-RawVHDX {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][uint64]$SizeBytes,
        [switch]$FixedSize
    )
    
    $typeStr = "Dynamic"
    if ($FixedSize) { $typeStr = "Fixed" }
    
    Write-Host ("Creating " + $typeStr + " VHDX: " + $Path + " (" + (Format-ByteSize $SizeBytes) + ")...") -ForegroundColor Cyan
    
    # Ensure directory exists
    $parentDir = Split-Path -Path $Path -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        $null = New-Item -Path $parentDir -ItemType Directory -Force
    }
    
    # Remove existing file
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Force
    }
    
    # Try Hyper-V cmdlet first (most reliable)
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
            
            # Open the created VHDX to get a handle
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
                throw ("OpenVirtualDisk failed: " + $win32Err.Message)
            }
            
            return $handle
        }
        catch {
            Write-Host ("  Hyper-V method failed: " + $_) -ForegroundColor Yellow
            Write-Host "  Trying VirtDisk API..." -ForegroundColor Yellow
            
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # Method 2: Manual P/Invoke with VirtDisk API
    Write-Host "  Using VirtDisk API..." -ForegroundColor DarkGray
    
    # Align size to MB boundary
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    
    $storageType = New-Object -TypeName VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $uniqueId = [Guid]::NewGuid()
    $paramsPtr = New-VhdxParameterBuffer -UniqueId $uniqueId -MaximumSize $SizeBytes
    
    try {
        $flags = [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_NONE
        if ($FixedSize) {
            $flags = [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION
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
            throw ("CreateVirtualDisk failed: " + $win32Err.Message + " (Error: " + $result + ")")
        }
        
        return $handle
    }
    finally {
        Remove-VhdxParameterBuffer -Ptr $paramsPtr
    }
}

function Mount-RawVHDX {
    param([Parameter(Mandatory)][IntPtr]$Handle)
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object -TypeName VirtDiskApi+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = 1
    
    $result = [VirtDiskApi]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
        0,
        [ref]$attachParams,
        [IntPtr]::Zero
    )
    
    if ($result -ne 0) {
        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
        throw ("AttachVirtualDisk failed: " + $win32Err.Message)
    }
    
    $pathSizeBytes = 520
    $pathBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pathSizeBytes)
    
    try {
        $result = [VirtDiskApi]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSizeBytes, $pathBuffer)
        if ($result -ne 0) {
            $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $result
            throw ("GetVirtualDiskPhysicalPath failed: " + $win32Err.Message)
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
# DISK INITIALIZATION FUNCTIONS
# ============================================================

function Initialize-BootableVHDX {
    param(
        [Parameter(Mandatory)][string]$PhysicalPath,
        [Parameter(Mandatory)][ValidateSet('UEFI', 'BIOS')][string]$BootMode,
        [Parameter(Mandatory)][uint64]$WindowsPartitionSize
    )
    
    Write-Host ("Initializing disk structure for " + $BootMode + " boot...") -ForegroundColor Cyan
    
    # Extract disk number from physical path
    $diskNumber = -1
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') {
        $diskNumber = [int]$Matches[1]
    }
    else {
        throw ("Could not determine disk number from path: " + $PhysicalPath)
    }
    
    # Wait for disk to be available
    $disk = $null
    for ($retry = 0; $retry -lt 30; $retry++) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
        if ($disk) { break }
    }
    
    if (-not $disk) {
        throw ("Could not find disk " + $diskNumber + " after waiting")
    }
    
    Write-Host ("  Disk " + $diskNumber + " found: " + (Format-ByteSize $disk.Size)) -ForegroundColor DarkGray
    
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
            DiskNumber       = $diskNumber
            EspPartition     = $espPartition
            WindowsPartition = $winPartition
            BootMode         = 'UEFI'
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
            DiskNumber       = $diskNumber
            SystemPartition  = $sysPartition
            WindowsPartition = $winPartition
            BootMode         = 'BIOS'
        }
    }
}

function Install-BootFiles {
    param(
        [Parameter(Mandatory)][hashtable]$DiskInfo,
        [Parameter(Mandatory)][string]$WindowsDriveLetter
    )
    
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $windowsPath = $WindowsDriveLetter + ":\Windows"
    if (-not (Test-Path -LiteralPath $windowsPath)) {
        throw ("Windows directory not found at " + $windowsPath)
    }
    
    # Get an available drive letter for the boot partition
    $bootLetter = Get-AvailableDriveLetter
    if (-not $bootLetter) {
        throw "No available drive letters for boot partition"
    }
    
    # Determine which partition is the boot partition
    $bootPartition = $null
    $firmware = $null
    
    if ($DiskInfo.BootMode -eq 'UEFI') {
        $bootPartition = $DiskInfo.EspPartition
        $firmware = 'UEFI'
    }
    else {
        $bootPartition = $DiskInfo.SystemPartition
        $firmware = 'BIOS'
    }
    
    Write-Host ("  Assigning drive letter " + $bootLetter + " to boot partition...") -ForegroundColor DarkGray
    $bootPartition | Set-Partition -NewDriveLetter $bootLetter
    Start-Sleep -Seconds 2
    
    try {
        Write-Host ("  Running bcdboot for " + $firmware + "...") -ForegroundColor DarkGray
        $bootDrive = $bootLetter + ":"
        $bcdbootOutput = & bcdboot.exe $windowsPath /s $bootDrive /f $firmware 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw ("bcdboot failed (exit code " + $LASTEXITCODE + "): " + $bcdbootOutput)
        }
        Write-Host "  Boot files installed successfully" -ForegroundColor Green
    }
    finally {
        # Remove the drive letter
        Write-Host "  Removing boot partition drive letter..." -ForegroundColor DarkGray
        $accessPath = $bootLetter + ":\"
        try {
            $bootPartition | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue
        }
        catch { }
    }
}

# ============================================================
# NTFS VOLUME DATA FUNCTIONS
# ============================================================

function Get-NtfsVolumeData {
    param([Parameter(Mandatory)][string]$DriveLetter)
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = "\\.\" + $DriveLetter + ":"
    
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
        throw ("Failed to open volume: " + (New-Object System.ComponentModel.Win32Exception $err).Message)
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
                throw ("FSCTL_GET_NTFS_VOLUME_DATA failed: " + (New-Object System.ComponentModel.Win32Exception $err).Message)
            }
            
            $volumeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $buffer,
                [type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER]
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
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [Parameter(Mandatory)][long]$TotalClusters
    )
    
    Write-Host "Reading volume allocation bitmap..." -ForegroundColor Cyan
    
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $volumePath = "\\.\" + $DriveLetter + ":"
    
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
        throw ("Failed to open volume: " + (New-Object System.ComponentModel.Win32Exception $err).Message)
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
                    # ERROR_MORE_DATA (234) is expected and OK
                    if ($err -ne 234) {
                        throw ("FSCTL_GET_VOLUME_BITMAP failed: error " + $err)
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
                Write-Progress -Activity "Reading Bitmap" -Status ("$pct" + "% complete") -PercentComplete $pct
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
                    EndCluster   = $cluster - 1
                    ClusterCount = $cluster - $currentStart
                })
                $currentStart = -1
            }
        }
        
        if ($cluster % $progressInterval -eq 0) {
            $pct = Get-ClampedPercent -Current $cluster -Total $TotalClusters
            Write-Progress -Activity "Analyzing Bitmap" -Status ("$pct" + "% complete") -PercentComplete $pct
        }
    }
    
    # Handle last range
    if ($currentStart -ne -1) {
        $null = $ranges.Add([PSCustomObject]@{
            StartCluster = $currentStart
            EndCluster   = $TotalClusters - 1
            ClusterCount = $TotalClusters - $currentStart
        })
    }
    Write-Progress -Activity "Analyzing Bitmap" -Completed
    
    # Merge nearby ranges
    Write-Host ("Merging adjacent ranges (gap threshold: " + $MinRunClusters + " clusters)...") -ForegroundColor Cyan
    $mergedRanges = [System.Collections.ArrayList]::new()
    $prev = $null
    
    foreach ($range in $ranges) {
        if ($null -eq $prev) {
            $prev = $range
            continue
        }
        
        $gap = $range.StartCluster - $prev.EndCluster - 1
        if ($gap -le $MinRunClusters) {
            # Merge
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
    if ($prev) {
        $null = $mergedRanges.Add($prev)
    }
    
    $totalBytes = [long]$TotalClusters * $BytesPerCluster
    $allocatedBytes = [long]$allocatedClusters * $BytesPerCluster
    $savingsPercent = 0
    if ($totalBytes -gt 0) {
        $savingsPercent = [math]::Round((1 - ($allocatedBytes / $totalBytes)) * 100, 1)
    }
    
    Write-Host ("  Total:     " + (Format-ByteSize $totalBytes)) -ForegroundColor DarkGray
    Write-Host ("  Allocated: " + (Format-ByteSize $allocatedBytes)) -ForegroundColor DarkGray
    Write-Host ("  Ranges:    " + $mergedRanges.Count) -ForegroundColor DarkGray
    Write-Host ("  Savings:   " + $savingsPercent + "% (free space skipped)") -ForegroundColor Green
    
    return @{
        Ranges            = $mergedRanges
        AllocatedClusters = $allocatedClusters
        AllocatedBytes    = $allocatedBytes
    }
}

# ============================================================
# RAW DISK I/O FUNCTIONS
# ============================================================

function Open-RawDisk {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Read', 'Write', 'ReadWrite')][string]$Access
    )
    
    $accessFlags = [NativeDiskApi]::GENERIC_READ
    if ($Access -eq 'Write') {
        $accessFlags = [NativeDiskApi]::GENERIC_WRITE
    }
    elseif ($Access -eq 'ReadWrite') {
        $accessFlags = [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE
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
        throw ("Failed to open " + $Path + ": " + (New-Object System.ComponentModel.Win32Exception $err).Message)
    }
    
    return $handle
}

# ============================================================
# BLOCK COPY FUNCTIONS
# ============================================================

function Copy-VolumeToPartition {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$DiskPath,
        [Parameter(Mandatory)][long]$PartitionOffset,
        [Parameter(Mandatory)][uint64]$TotalBytes,
        [int]$BlockSize = 4194304
    )
    
    Write-Host ("Copying " + (Format-ByteSize $TotalBytes) + " to partition (full copy)...") -ForegroundColor Cyan
    
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
            
            # Read
            $bytesRead = [uint32]0
            $readSuccess = [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $alignedBytes, [ref]$bytesRead, [IntPtr]::Zero)
            if (-not $readSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw ("Read failed at offset " + $totalCopied + " (Error: " + $err + ")")
            }
            if ($bytesRead -eq 0) { break }
            
            # Seek
            $destOffset = $PartitionOffset + $totalCopied
            $newPos = [long]0
            $seekSuccess = [NativeDiskApi]::SetFilePointerEx($destHandle, $destOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
            if (-not $seekSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw ("Seek failed at offset " + $destOffset + " (Error: " + $err + ")")
            }
            
            # Write
            $toWrite = [math]::Min($bytesRead, $remainingBytes)
            $alignedWrite = [uint32]([math]::Ceiling($toWrite / 4096) * 4096)
            
            $bytesWritten = [uint32]0
            $writeSuccess = [NativeDiskApi]::WriteFile($destHandle, $buffer, $alignedWrite, [ref]$bytesWritten, [IntPtr]::Zero)
            if (-not $writeSuccess) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw ("Write failed at offset " + $destOffset + " (Error: " + $err + ")")
            }
            
            $totalCopied += $toWrite
            
            # Progress
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
                $status = $pct.ToString() + "% - " + [math]::Round($speed, 1).ToString() + " MB/s - ETA: " + [math]::Round($eta, 1).ToString() + " min"
                Write-Progress -Activity "Copying Data" -Status $status -PercentComplete $pct
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
        Write-Host ("Copied " + (Format-ByteSize $totalCopied) + " in " + [math]::Round($stopwatch.Elapsed.TotalMinutes, 1).ToString() + " min (" + [math]::Round($avgSpeed, 1).ToString() + " MB/s)") -ForegroundColor Green
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
    
    Write-Host ("Copying " + (Format-ByteSize $AllocatedBytes) + " of allocated data (smart copy)...") -ForegroundColor Cyan
    Write-Host ("  Block size: " + ($BlockSize / 1MB).ToString() + " MB") -ForegroundColor DarkGray
    
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
                
                # Seek source
                $newPos = [long]0
                $seekSuccess = [NativeDiskApi]::SetFilePointerEx($sourceHandle, $sourceByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
                if (-not $seekSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw ("Source seek failed at offset " + $sourceByteOffset + " (Error: " + $err + ")")
                }
                
                # Read
                $bytesRead = [uint32]0
                $readSuccess = [NativeDiskApi]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
                if (-not $readSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw ("Read failed at cluster " + $clusterOffset + " (Error: " + $err + ")")
                }
                
                # Seek destination
                $destByteOffset = $PartitionOffset + $sourceByteOffset
                $seekSuccess = [NativeDiskApi]::SetFilePointerEx($destHandle, $destByteOffset, [ref]$newPos, [NativeDiskApi]::FILE_BEGIN)
                if (-not $seekSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw ("Dest seek failed at offset " + $destByteOffset + " (Error: " + $err + ")")
                }
                
                # Write
                $bytesWritten = [uint32]0
                $writeSuccess = [NativeDiskApi]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
                if (-not $writeSuccess) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw ("Write failed at cluster " + $clusterOffset + " (Error: " + $err + ")")
                }
                
                $totalCopied += $bytesRead
                $clusterOffset += $clustersToRead
                $clustersRemaining -= $clustersToRead
                
                # Progress
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
                    $status = $pct.ToString() + "% - " + [math]::Round($speed, 1).ToString() + " MB/s - ETA: " + [math]::Round($eta, 1).ToString() + " min"
                    Write-Progress -Activity "Copying Allocated Data" -Status $status -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying Allocated Data" -Completed
        
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        $avgSpeed = 0
        if ($elapsed -gt 0) {
            $avgSpeed = $totalCopied / $elapsed / 1MB
        }
        Write-Host ("Copied " + (Format-ByteSize $totalCopied) + " in " + [math]::Round($stopwatch.Elapsed.TotalMinutes, 1).ToString() + " min (" + [math]::Round($avgSpeed, 1).ToString() + " MB/s)") -ForegroundColor Green
    }
    finally {
        if ($sourceHandle -and -not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if ($destHandle -and -not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

# ============================================================
# MAIN CLONE FUNCTION
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
        # Parse source volume
        $driveLetter = $SourceVolume.TrimEnd(':', '\').ToUpper()
        $partition = Get-Partition -DriveLetter $driveLetter -ErrorAction Stop
        $partitionSize = $partition.Size
        $volume = Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
        
        # Check filesystem
        if ($volume.FileSystemType -ne 'NTFS' -and -not $FullCopy) {
            Write-Warning ("Volume is " + $volume.FileSystemType + ", not NTFS. Forcing full copy mode.")
            $FullCopy = $true
        }
        
        # Calculate VHDX size
        $bootPartitionSize = 300MB
        if ($BootMode -ne 'UEFI') { $bootPartitionSize = 550MB }
        $vhdxSize = [uint64]($partitionSize + $bootPartitionSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        # Display summary
        Write-Host ""
        Write-Host ("=" * 65) -ForegroundColor Yellow
        Write-Host "                    BOOTABLE VOLUME CLONE" -ForegroundColor Yellow
        Write-Host ("=" * 65) -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("  Source:         " + $driveLetter + ":") -ForegroundColor White
        Write-Host ("  Destination:    " + $DestinationVHDX) -ForegroundColor White
        Write-Host ("  Partition Size: " + (Format-ByteSize $partitionSize)) -ForegroundColor White
        Write-Host ("  VHDX Size:      " + (Format-ByteSize $vhdxSize)) -ForegroundColor White
        Write-Host ("  Boot Mode:      " + $BootMode) -ForegroundColor White
        $copyModeText = "Smart (skip free space)"
        if ($FullCopy) { $copyModeText = "Full (all sectors)" }
        Write-Host ("  Copy Mode:      " + $copyModeText) -ForegroundColor White
        $vhdxTypeText = "Dynamic"
        if ($FixedSizeVHDX) { $vhdxTypeText = "Fixed" }
        Write-Host ("  VHDX Type:      " + $vhdxTypeText) -ForegroundColor White
        Write-Host ""
        
        # Get NTFS data if doing smart copy
        $volumeData = $null
        if (-not $FullCopy) {
            $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
            $usedBytes = ($volumeData.TotalClusters - $volumeData.FreeClusters) * $volumeData.BytesPerCluster
            $freeBytes = $volumeData.FreeClusters * $volumeData.BytesPerCluster
            Write-Host ("  Used space:     " + (Format-ByteSize $usedBytes)) -ForegroundColor DarkGray
            Write-Host ("  Free space:     " + (Format-ByteSize $freeBytes) + " (will be skipped)") -ForegroundColor DarkGray
            Write-Host ""
        }
        
        # Create VSS snapshot
        $volPath = $driveLetter + ":\"
        $snapshot = New-VssSnapshot -Volume $volPath
        Write-Host ("Snapshot created: " + $snapshot.DeviceObject) -ForegroundColor Green
        Write-Host ""
        
        # Create VHDX
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        # Attach VHDX
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle
        Write-Host ("VHDX attached at: " + $physicalPath) -ForegroundColor Green
        Write-Host ""
        
        Start-Sleep -Seconds 3
        
        # Initialize disk with boot partitions
        $diskInfo = Initialize-BootableVHDX -PhysicalPath $physicalPath -BootMode $BootMode -WindowsPartitionSize $partitionSize
        
        Start-Sleep -Seconds 2
        
        # Get Windows partition info
        $winPartition = $diskInfo.WindowsPartition
        $winPartitionOffset = $winPartition.Offset
        $diskPath = "\\.\PhysicalDrive" + $diskInfo.DiskNumber
        
        Write-Host ""
        Write-Host ("Windows partition offset: " + $winPartitionOffset + " bytes") -ForegroundColor DarkGray
        Write-Host ("Windows partition size: " + (Format-ByteSize $winPartition.Size)) -ForegroundColor DarkGray
        Write-Host ""
        
        $blockSizeBytes = $BlockSizeMB * 1MB
        
        # Copy data
        if ($FullCopy) {
            Copy-VolumeToPartition `
                -SourcePath $snapshot.DeviceObject `
                -DiskPath $diskPath `
                -PartitionOffset $winPartitionOffset `
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
            
            Copy-AllocatedBlocksToPartition `
                -SourcePath $snapshot.DeviceObject `
                -DiskPath $diskPath `
                -PartitionOffset $winPartitionOffset `
                -Ranges $allocation.Ranges `
                -BytesPerCluster $volumeData.BytesPerCluster `
                -AllocatedBytes $allocation.AllocatedBytes `
                -BlockSize $blockSizeBytes
        }
        
        # Install boot files
        if (-not $SkipBootFix) {
            $windowsDriveLetter = Get-AvailableDriveLetter
            if (-not $windowsDriveLetter) {
                throw "No available drive letters for Windows partition"
            }
            
            Write-Host ""
            Write-Host ("Assigning drive letter " + $windowsDriveLetter + " to Windows partition...") -ForegroundColor Cyan
            $winPartition | Set-Partition -NewDriveLetter $windowsDriveLetter
            Start-Sleep -Seconds 2
            
            Install-BootFiles -DiskInfo $diskInfo -WindowsDriveLetter $windowsDriveLetter
            
            Write-Host "Removing Windows partition drive letter..." -ForegroundColor Cyan
            $accessPath = $windowsDriveLetter + ":\"
            try {
                $winPartition | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue
            }
            catch { }
            $windowsDriveLetter = $null
        }
        
        # Done
        Write-Host ""
        Write-Host ("=" * 65) -ForegroundColor Green
        Write-Host "                  BOOTABLE CLONE COMPLETE" -ForegroundColor Green
        Write-Host ("=" * 65) -ForegroundColor Green
        Write-Host ""
        Write-Host ("  VHDX File: " + $DestinationVHDX) -ForegroundColor White
        
        $vhdxFile = Get-Item -LiteralPath $DestinationVHDX
        Write-Host ("  File Size: " + (Format-ByteSize $vhdxFile.Length)) -ForegroundColor White
        Write-Host ""
        Write-Host "  Usage:" -ForegroundColor Cyan
        Write-Host "    Hyper-V:     Create a new VM and attach this VHDX as the primary disk" -ForegroundColor Gray
        Write-Host "    Native Boot: Use bcdedit to add a boot entry (requires Pro/Enterprise)" -ForegroundColor Gray
        Write-Host ""
        
        return $DestinationVHDX
    }
    catch {
        Write-Host ""
        Write-Host ("Clone failed: " + $_) -ForegroundColor Red
        Write-Host ""
        
        # Cleanup drive letters
        if ($windowsDriveLetter -and $diskInfo -and $diskInfo.WindowsPartition) {
            $accessPath = $windowsDriveLetter + ":\"
            try {
                $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue
            }
            catch { }
        }
        
        # Cleanup VHDX
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
# INTERACTIVE MENU FUNCTIONS
# ============================================================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "              BOOTABLE VOLUME CLONE UTILITY" -ForegroundColor Yellow
    Write-Host "        Clone a running Windows volume to bootable VHDX" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-VolumeList {
    $vols = @(Get-Volume | Where-Object {
        $_.DriveLetter -and
        $_.DriveType -eq 'Fixed' -and
        $_.Size -gt 0
    } | Sort-Object DriveLetter)
    
    return $vols
}

function Show-VolumeMenu {
    param([array]$Volumes)
    
    Write-Host "  Available Volumes:" -ForegroundColor White
    Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    
    for ($i = 0; $i -lt $Volumes.Count; $i++) {
        $vol = $Volumes[$i]
        $num = $i + 1
        $sizeGB = [math]::Round($vol.Size / 1GB, 2)
        $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 2)
        $usedPct = 0
        if ($vol.Size -gt 0) {
            $usedPct = [int][math]::Round((($vol.Size - $vol.SizeRemaining) / $vol.Size) * 100)
        }
        
        $label = $vol.FileSystemLabel
        if (-not $label) { $label = "Local Disk" }
        
        # Progress bar
        $barLen = 20
        $filledLen = [int][math]::Min($barLen, [math]::Max(0, [math]::Round(($usedPct / 100) * $barLen)))
        $emptyLen = $barLen - $filledLen
        
        $filled = ""
        $empty = ""
        if ($filledLen -gt 0) { $filled = [string]::new([char]0x2588, $filledLen) }
        if ($emptyLen -gt 0) { $empty = [string]::new([char]0x2591, $emptyLen) }
        $bar = "[" + $filled + $empty + "]"
        
        Write-Host ("    [" + $num + "] ") -ForegroundColor Yellow -NoNewline
        Write-Host ([string]$vol.DriveLetter + ":") -ForegroundColor White -NoNewline
        Write-Host (" " + $label) -ForegroundColor Gray
        Write-Host ("        " + $bar + " ") -ForegroundColor DarkCyan -NoNewline
        Write-Host ($usedGB.ToString() + " GB / " + $sizeGB.ToString() + " GB ") -ForegroundColor Gray -NoNewline
        Write-Host ("(" + $vol.FileSystemType + ")") -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host "    [0] " -ForegroundColor Red -NoNewline
    Write-Host "Exit" -ForegroundColor Gray
    Write-Host ""
}

function Start-InteractiveMode {
    # Default options
    $optBootMode = 'UEFI'
    $optFullCopy = $false
    $optFixedSizeVHDX = $false
    $optBlockSizeMB = 4
    
    while ($true) {
        Show-Banner
        
        # Get volumes
        $volumes = Get-VolumeList
        
        if ($volumes.Count -eq 0) {
            Write-Host "  No suitable volumes found!" -ForegroundColor Red
            Wait-ForKeyPress
            return
        }
        
        Show-VolumeMenu -Volumes $volumes
        
        # Get volume selection
        Write-Host ("  Select volume to clone (0-" + $volumes.Count + "): ") -ForegroundColor White -NoNewline
        $selInput = Read-Host
        
        # Parse selection
        $selNum = -1
        $parseOk = [int]::TryParse($selInput.Trim(), [ref]$selNum)
        
        if (-not $parseOk -or $selNum -lt 0 -or $selNum -gt $volumes.Count) {
            Write-Host ("  Invalid selection. Please enter a number from 0 to " + $volumes.Count + ".") -ForegroundColor Red
            Start-Sleep -Seconds 2
            continue
        }
        
        if ($selNum -eq 0) {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            return
        }
        
        $volIndex = $selNum - 1
        $selectedVolume = [string]$volumes[$volIndex].DriveLetter
        $volumeInfo = $volumes[$volIndex]
        
        # Build default destination path
        $dateStr = Get-Date -Format 'yyyyMMdd_HHmmss'
        $defaultName = "Bootable_" + $selectedVolume + "_" + $dateStr + ".vhdx"
        
        # Find a destination drive with enough space
        $destDrives = @(Get-Volume | Where-Object {
            $_.DriveLetter -and
            ([string]$_.DriveLetter) -ne $selectedVolume -and
            $_.DriveType -eq 'Fixed' -and
            $_.SizeRemaining -gt ($volumeInfo.Size + 1GB)
        } | Sort-Object SizeRemaining -Descending)
        
        $defaultPath = $selectedVolume + ":\VMs\" + $defaultName
        if ($destDrives.Count -gt 0) {
            $defaultPath = ([string]$destDrives[0].DriveLetter) + ":\VMs\" + $defaultName
        }
        
        # Get destination path
        Write-Host ""
        Write-Host "  Destination VHDX path" -ForegroundColor White
        Write-Host ("  Default: " + $defaultPath) -ForegroundColor DarkGray
        Write-Host "  (Press Enter to use default): " -ForegroundColor White -NoNewline
        $destInput = Read-Host
        
        $destinationPath = $defaultPath
        if (-not [string]::IsNullOrWhiteSpace($destInput)) {
            $destinationPath = $destInput.Trim()
        }
        
        if (-not $destinationPath.ToLower().EndsWith('.vhdx')) {
            $destinationPath = $destinationPath + '.vhdx'
        }
        
        # Options menu
        $exitOptions = $false
        while (-not $exitOptions) {
            Show-Banner
            
            $volumeLabel = $volumeInfo.FileSystemLabel
            if (-not $volumeLabel) { $volumeLabel = "Local Disk" }
            
            Write-Host ("  Source: " + $selectedVolume + ": (" + $volumeLabel + ")") -ForegroundColor White
            Write-Host ("  Destination: " + $destinationPath) -ForegroundColor White
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor White
            Write-Host "  ----------------------------------------------------------" -ForegroundColor DarkGray
            Write-Host ""
            
            $bootColor = "White"
            if ($optBootMode -eq 'UEFI') { $bootColor = "Green" }
            Write-Host "    [1] Boot Mode:     " -ForegroundColor Yellow -NoNewline
            Write-Host $optBootMode -ForegroundColor $bootColor
            
            $copyText = "Smart (skip free space)"
            $copyColor = "Green"
            if ($optFullCopy) {
                $copyText = "Full (all sectors)"
                $copyColor = "White"
            }
            Write-Host "    [2] Copy Mode:     " -ForegroundColor Yellow -NoNewline
            Write-Host $copyText -ForegroundColor $copyColor
            
            $vhdxText = "Dynamic"
            $vhdxColor = "Green"
            if ($optFixedSizeVHDX) {
                $vhdxText = "Fixed"
                $vhdxColor = "White"
            }
            Write-Host "    [3] VHDX Type:     " -ForegroundColor Yellow -NoNewline
            Write-Host $vhdxText -ForegroundColor $vhdxColor
            
            Write-Host ("    [4] Block Size:    " + $optBlockSizeMB + " MB") -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Destination Path" -ForegroundColor Cyan
            Write-Host "    [B] Back to Volume Selection" -ForegroundColor DarkYellow
            Write-Host "    [Q] Quit" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Enter choice: " -ForegroundColor White -NoNewline
            
            $choiceInput = Read-Host
            $choice = $choiceInput.Trim().ToUpper()
            
            switch ($choice) {
                '1' {
                    if ($optBootMode -eq 'UEFI') { $optBootMode = 'BIOS' }
                    else { $optBootMode = 'UEFI' }
                }
                '2' {
                    $optFullCopy = -not $optFullCopy
                }
                '3' {
                    $optFixedSizeVHDX = -not $optFixedSizeVHDX
                }
                '4' {
                    Write-Host ""
                    Write-Host ("  Enter block size in MB (1-64) [" + $optBlockSizeMB + "]: ") -ForegroundColor White -NoNewline
                    $bsInput = Read-Host
                    
                    $bsNum = 0
                    if ([int]::TryParse($bsInput.Trim(), [ref]$bsNum)) {
                        if ($bsNum -ge 1 -and $bsNum -le 64) {
                            $optBlockSizeMB = $bsNum
                        }
                        else {
                            Write-Host ("  Value must be between 1 and 64. Keeping: " + $optBlockSizeMB + " MB") -ForegroundColor Yellow
                            Start-Sleep -Seconds 1
                        }
                    }
                }
                'C' {
                    Write-Host ""
                    Write-Host ("  Enter new destination path [" + $destinationPath + "]: ") -ForegroundColor White -NoNewline
                    $newPath = Read-Host
                    
                    if (-not [string]::IsNullOrWhiteSpace($newPath)) {
                        $destinationPath = $newPath.Trim()
                        if (-not $destinationPath.ToLower().EndsWith('.vhdx')) {
                            $destinationPath = $destinationPath + '.vhdx'
                        }
                    }
                }
                'B' {
                    $exitOptions = $true
                }
                'Q' {
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return
                }
                '0' {
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return
                }
                'S' {
                    # Check if destination exists
                    if (Test-Path -LiteralPath $destinationPath) {
                        Write-Host ""
                        Write-Host "  Destination file exists. Overwrite? (y/N): " -ForegroundColor Yellow -NoNewline
                        $overwriteInput = Read-Host
                        
                        if ($overwriteInput.Trim().ToLower() -ne 'y') {
                            continue
                        }
                        Remove-Item -LiteralPath $destinationPath -Force
                    }
                    
                    # Confirm
                    Write-Host ""
                    Write-Host "  Start bootable clone? (Y/n): " -ForegroundColor White -NoNewline
                    $confirmInput = Read-Host
                    
                    if ($confirmInput.Trim().ToLower() -eq 'n') {
                        continue
                    }
                    
                    # Do the clone
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
                        Write-Host ("  " + ("=" * 60)) -ForegroundColor Red
                        Write-Host ("  Clone failed: " + $_) -ForegroundColor Red
                        Write-Host ("  " + ("=" * 60)) -ForegroundColor Red
                    }
                    
                    Write-Host ""
                    Wait-ForKeyPress
                    
                    # Ask to clone another
                    Write-Host ""
                    Write-Host "  Clone another volume? (y/N): " -ForegroundColor White -NoNewline
                    $anotherInput = Read-Host
                    
                    if ($anotherInput.Trim().ToLower() -ne 'y') {
                        Write-Host ""
                        Write-Host "  Goodbye!" -ForegroundColor Cyan
                        return
                    }
                    
                    $exitOptions = $true
                }
                default {
                    # Invalid input, just redraw
                }
            }
        }
    }
}

# ============================================================
# ENTRY POINT
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
