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

try {
    if ($null -ne [Console]::OutputEncoding) {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    }
}
catch { 
    Write-Verbose "Could not set console encoding"
}

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

# ============================================================
# P/Invoke Definitions
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
    
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 1;
    
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
catch { }

if (-not $typesLoaded) {
    Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop
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
        
        $barLength = 20
        $filledLength = [math]::Min($barLength, [math]::Max(0, [math]::Round(($usedPct / 100) * $barLength)))
        $emptyLength = $barLength - $filledLength
        
        $filledBar = if ($filledLength -gt 0) { [string]::new([char]0x2588, $filledLength) } else { "" }
        $emptyBar = if ($emptyLength -gt 0) { [string]::new([char]0x2591, $emptyLength) } else { "" }
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
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,
        
        [Parameter(Mandatory)]
        [int]$Min,
        
        [Parameter(Mandatory)]
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
        [Parameter(Mandatory)]
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
        [Parameter(Mandatory)]
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

# ============================================================
# VSS Functions
# ============================================================

function New-VssSnapshot {
    param(
        [Parameter(Mandatory)]
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
    param(
        [Parameter(Mandatory)]
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
# Virtual Disk Functions
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
    param(
        [Parameter(Mandatory)]
        [IntPtr]$Handle,
        
        [switch]$WithDriveLetter
    )
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object -TypeName VirtDisk+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = 1
    
    $flags = if ($WithDriveLetter) { 
        [VirtDisk]::ATTACH_VIRTUAL_DISK_FLAG_NONE 
    } 
    else { 
        [VirtDisk]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER 
    }
    
    $result = [VirtDisk]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        $flags,
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
        
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pathBuffer)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pathBuffer)
    }
}

function Dismount-RawVHDX {
    param(
        [Parameter(Mandatory)]
        [IntPtr]$Handle
    )
    
    if ($Handle -eq [IntPtr]::Zero) { 
        return 
    }
    
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    $null = [VirtDisk]::DetachVirtualDisk($Handle, 0, 0)
    $null = [VirtDisk]::CloseHandle($Handle)
}

# ============================================================
# Disk Initialization and Partitioning
# ============================================================

function Initialize-BootableVHDX {
    param(
        [Parameter(Mandatory)]
        [string]$PhysicalPath,
        
        [Parameter(Mandatory)]
        [ValidateSet('UEFI', 'BIOS')]
        [string]$BootMode,
        
        [Parameter(Mandatory)]
        [uint64]$WindowsPartitionSize
    )
    
    Write-Host "Initializing disk structure for $BootMode boot..." -ForegroundColor Cyan
    
    # Get disk number from physical path
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') {
        $diskNumber = [int]$Matches[1]
    }
    else {
        throw "Could not determine disk number from path: $PhysicalPath"
    }
    
    # Wait for disk to be ready
    $retries = 20
    $disk = $null
    while ($retries -gt 0 -and -not $disk) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNumber -ErrorAction SilentlyContinue
        $retries--
    }
    
    if (-not $disk) {
        throw "Could not find disk $diskNumber"
    }
    
    Write-Host "  Disk $diskNumber found: $([math]::Round($disk.Size/1GB, 2)) GB" -ForegroundColor DarkGray
    
    # Initialize disk
    if ($BootMode -eq 'UEFI') {
        # GPT for UEFI
        Write-Host "  Initializing as GPT..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop
        
        Start-Sleep -Seconds 2
        
        # Create EFI System Partition (ESP) - 260 MB
        Write-Host "  Creating EFI System Partition (260 MB)..." -ForegroundColor DarkGray
        $espPartition = New-Partition -DiskNumber $diskNumber -Size 260MB -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        Format-Volume -Partition $espPartition -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false | Out-Null
        
        # Create Microsoft Reserved Partition (MSR) - 16 MB
        Write-Host "  Creating Microsoft Reserved Partition (16 MB)..." -ForegroundColor DarkGray
        $null = New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
        
        # Create Windows partition (Basic Data)
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
        # MBR for BIOS
        Write-Host "  Initializing as MBR..." -ForegroundColor DarkGray
        Initialize-Disk -Number $diskNumber -PartitionStyle MBR -ErrorAction Stop
        
        Start-Sleep -Seconds 2
        
        # Create System Reserved partition - 500 MB
        Write-Host "  Creating System Reserved partition (500 MB)..." -ForegroundColor DarkGray
        $sysPartition = New-Partition -DiskNumber $diskNumber -Size 500MB -IsActive
        Format-Volume -Partition $sysPartition -FileSystem NTFS -NewFileSystemLabel "System Reserved" -Confirm:$false | Out-Null
        
        # Create Windows partition
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
        [Parameter(Mandatory)]
        [hashtable]$DiskInfo,
        
        [Parameter(Mandatory)]
        [string]$WindowsDriveLetter
    )
    
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $windowsPath = "${WindowsDriveLetter}:\Windows"
    
    if (-not (Test-Path -LiteralPath $windowsPath)) {
        throw "Windows directory not found at $windowsPath"
    }
    
    if ($DiskInfo.BootMode -eq 'UEFI') {
        # Assign temporary drive letter to ESP
        $availableLetters = @([char[]]('S'..'Z') | Where-Object { -not (Test-Path -LiteralPath "$($_):") })
        
        if ((Get-SafeCount $availableLetters) -eq 0) { 
            throw "No available drive letters for ESP" 
        }
        
        $espLetter = $availableLetters[0]
        
        Write-Host "  Assigning drive letter $espLetter to ESP..." -ForegroundColor DarkGray
        $DiskInfo.EspPartition | Set-Partition -NewDriveLetter $espLetter
        
        Start-Sleep -Seconds 2
        
        try {
            # Use bcdboot to install UEFI boot files
            Write-Host "  Running bcdboot for UEFI..." -ForegroundColor DarkGray
            $bcdbootArgs = "`"$windowsPath`" /s ${espLetter}: /f UEFI"
            
            $processInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = "bcdboot.exe"
            $processInfo.Arguments = $bcdbootArgs
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            
            $process = New-Object -TypeName System.Diagnostics.Process
            $process.StartInfo = $processInfo
            $null = $process.Start()
            $process.WaitForExit()
            
            if ($process.ExitCode -ne 0) {
                $stderr = $process.StandardError.ReadToEnd()
                throw "bcdboot failed with exit code $($process.ExitCode): $stderr"
            }
            
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            # Remove drive letter from ESP
            Write-Host "  Removing ESP drive letter..." -ForegroundColor DarkGray
            try {
                $DiskInfo.EspPartition | Remove-PartitionAccessPath -AccessPath "${espLetter}:\" -ErrorAction SilentlyContinue
            }
            catch { }
        }
    }
    else {
        # MBR/BIOS boot
        $availableLetters = @([char[]]('S'..'Z') | Where-Object { -not (Test-Path -LiteralPath "$($_):") })
        
        if ((Get-SafeCount $availableLetters) -eq 0) { 
            throw "No available drive letters for System partition" 
        }
        
        $sysLetter = $availableLetters[0]
        
        Write-Host "  Assigning drive letter $sysLetter to System partition..." -ForegroundColor DarkGray
        $DiskInfo.SystemPartition | Set-Partition -NewDriveLetter $sysLetter
        
        Start-Sleep -Seconds 2
        
        try {
            # Use bcdboot to install BIOS boot files
            Write-Host "  Running bcdboot for BIOS..." -ForegroundColor DarkGray
            $bcdbootArgs = "`"$windowsPath`" /s ${sysLetter}: /f BIOS"
            
            $processInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = "bcdboot.exe"
            $processInfo.Arguments = $bcdbootArgs
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true
            
            $process = New-Object -TypeName System.Diagnostics.Process
            $process.StartInfo = $processInfo
            $null = $process.Start()
            $process.WaitForExit()
            
            if ($process.ExitCode -ne 0) {
                $stderr = $process.StandardError.ReadToEnd()
                throw "bcdboot failed with exit code $($process.ExitCode): $stderr"
            }
            
            Write-Host "  Boot files installed successfully" -ForegroundColor Green
        }
        finally {
            Write-Host "  Removing System partition drive letter..." -ForegroundColor DarkGray
            try {
                $DiskInfo.SystemPartition | Remove-PartitionAccessPath -AccessPath "${sysLetter}:\" -ErrorAction SilentlyContinue
            }
            catch { }
        }
    }
}

# ============================================================
# Volume Bitmap Functions
# ============================================================

function Get-NtfsVolumeData {
    param(
        [Parameter(Mandatory)]
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
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter,
        
        [Parameter(Mandatory)]
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
        $inputBufferSize = 8
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
                    # ERROR_MORE_DATA (234) is expected
                    if ($err -ne 234) {
                        $win32Err = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $err
                        throw "FSCTL_GET_VOLUME_BITMAP failed: $($win32Err.Message)"
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
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bitmap,
        
        [Parameter(Mandatory)]
        [long]$TotalClusters,
        
        [Parameter(Mandatory)]
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
    
    # Merge nearby ranges
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
    
    Write-Host "  Total: $([math]::Round($totalBytes/1GB, 2)) GB" -ForegroundColor DarkGray
    Write-Host "  Allocated: $([math]::Round($allocatedBytes/1GB, 2)) GB" -ForegroundColor DarkGray
    Write-Host "  Ranges: $(Get-SafeCount $mergedRanges)" -ForegroundColor DarkGray
    Write-Host "  Space savings: $savingsPercent%" -ForegroundColor Green
    
    return @{
        Ranges            = $mergedRanges
        AllocatedClusters = $allocatedClusters
        AllocatedBytes    = $allocatedBytes
    }
}

# ============================================================
# Raw Disk I/O
# ============================================================

function Open-RawDisk {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
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
# Block Copy Functions
# ============================================================

function Copy-VolumeToPartition {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        
        [Parameter(Mandatory)]
        [string]$DiskPath,
        
        [Parameter(Mandatory)]
        [long]$PartitionOffset,
        
        [Parameter(Mandatory)]
        [uint64]$TotalBytes,
        
        [int]$BlockSize = 4194304
    )
    
    Write-Host "Copying $([math]::Round($TotalBytes/1GB, 2)) GB to partition..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DiskPath -Access Write
    
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
            
            # Seek to partition offset + current position
            $destOffset = $PartitionOffset + $totalCopied
            $newPos = [long]0
            $success = [NativeDisk]::SetFilePointerEx($destHandle, $destOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Seek failed at offset $destOffset. Error: $err"
            }
            
            $bytesWritten = [uint32]0
            $success = [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Write failed at offset $destOffset. Error: $err"
            }
            
            $totalCopied += $bytesRead
            
            $pct = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($pct -gt $lastPct) {
                $elapsed = $stopwatch.Elapsed.TotalSeconds
                $speed = if ($elapsed -gt 0) { $totalCopied / $elapsed / 1MB } else { 0 }
                $remaining = if ($speed -gt 0) { ($TotalBytes - $totalCopied) / 1MB / $speed / 60 } else { 0 }
                
                Write-Progress -Activity "Copying Data" `
                    -Status "$pct% - $([math]::Round($speed, 1)) MB/s - ETA: $([math]::Round($remaining, 1)) min" `
                    -PercentComplete $pct
                $lastPct = $pct
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying Data" -Completed
        
        $avgSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if (-not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if (-not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

function Copy-AllocatedBlocksToPartition {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        
        [Parameter(Mandatory)]
        [string]$DiskPath,
        
        [Parameter(Mandatory)]
        [long]$PartitionOffset,
        
        [Parameter(Mandatory)]
        [System.Collections.ArrayList]$Ranges,
        
        [Parameter(Mandatory)]
        [uint32]$BytesPerCluster,
        
        [Parameter(Mandatory)]
        [long]$AllocatedBytes,
        
        [int]$BlockSize = 4194304
    )
    
    if ($BlockSize % $BytesPerCluster -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $BytesPerCluster) * $BytesPerCluster)
    }
    
    $clustersPerBlock = [long]($BlockSize / $BytesPerCluster)
    
    Write-Host "Copying $([math]::Round($AllocatedBytes/1GB, 2)) GB of allocated data..." -ForegroundColor Cyan
    Write-Host "  Block size: $($BlockSize / 1MB) MB" -ForegroundColor DarkGray
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DiskPath -Access Write
    
    try {
        $buffer = New-Object -TypeName byte[] -ArgumentList $BlockSize
        $totalCopied = [long]0
        $stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
        $stopwatch.Start()
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
                $success = [NativeDisk]::SetFilePointerEx($sourceHandle, $sourceByteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Source seek failed at offset $sourceByteOffset. Error: $err"
                }
                
                # Read
                $bytesRead = [uint32]0
                $success = [NativeDisk]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Read failed at cluster $clusterOffset. Error: $err"
                }
                
                # Seek destination (partition offset + cluster offset)
                $destByteOffset = $PartitionOffset + $sourceByteOffset
                $success = [NativeDisk]::SetFilePointerEx($destHandle, $destByteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Destination seek failed at offset $destByteOffset. Error: $err"
                }
                
                # Write
                $bytesWritten = [uint32]0
                $success = [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Write failed at cluster $clusterOffset. Error: $err"
                }
                
                $totalCopied += $bytesRead
                $clusterOffset += $clustersToRead
                $clustersRemaining -= $clustersToRead
                
                $pct = [math]::Floor(($totalCopied / $AllocatedBytes) * 100)
                if ($pct -gt $lastPct) {
                    $elapsed = $stopwatch.Elapsed.TotalSeconds
                    $speed = if ($elapsed -gt 0) { $totalCopied / $elapsed / 1MB } else { 0 }
                    $remaining = if ($speed -gt 0) { ($AllocatedBytes - $totalCopied) / 1MB / $speed / 60 } else { 0 }
                    
                    Write-Progress -Activity "Copying Allocated Blocks" `
                        -Status "$pct% - $([math]::Round($speed, 1)) MB/s - ETA: $([math]::Round($remaining, 1)) min" `
                        -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Copying Allocated Blocks" -Completed
        
        $avgSpeed = if ($stopwatch.Elapsed.TotalSeconds -gt 0) { $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) min ($([math]::Round($avgSpeed, 1)) MB/s)" -ForegroundColor Green
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
        [Parameter(Mandatory)]
        [string]$SourceVolume,
        
        [Parameter(Mandatory)]
        [string]$DestinationVHDX,
        
        [ValidateSet('UEFI', 'BIOS')]
        [string]$BootMode = 'UEFI',
        
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
            Write-Warning "Volume is $($volume.FileSystemType), not NTFS. Forcing full copy mode."
            $FullCopy = $true
        }
        
        # Calculate VHDX size
        $bootPartitionSize = if ($BootMode -eq 'UEFI') { 300MB } else { 550MB }
        $vhdxSize = [uint64]($partitionSize + $bootPartitionSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        Write-Host ""
        Write-Host "=== Bootable Volume Clone ===" -ForegroundColor Yellow
        Write-Host "Source: ${driveLetter}:" -ForegroundColor White
        Write-Host "Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "Partition Size: $([math]::Round($partitionSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "VHDX Size: $([math]::Round($vhdxSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "Boot Mode: $BootMode" -ForegroundColor White
        Write-Host "Copy Mode: $(if ($FullCopy) { 'Full' } else { 'Smart (skip free space)' })" -ForegroundColor White
        Write-Host ""
        
        # Get NTFS data if doing smart copy
        $volumeData = $null
        if (-not $FullCopy) {
            $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
            $usedBytes = ($volumeData.TotalClusters - $volumeData.FreeClusters) * $volumeData.BytesPerCluster
            Write-Host "Cluster size: $($volumeData.BytesPerCluster) bytes" -ForegroundColor DarkGray
            Write-Host "Used space: $([math]::Round($usedBytes / 1GB, 2)) GB" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        # Create VSS Snapshot
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        # Create VHDX
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        # Attach VHDX
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle -WithDriveLetter
        Write-Host "VHDX attached at: $physicalPath" -ForegroundColor Green
        
        Start-Sleep -Seconds 3
        
        # Initialize disk with boot partitions
        $diskInfo = Initialize-BootableVHDX -PhysicalPath $physicalPath -BootMode $BootMode -WindowsPartitionSize $partitionSize
        
        Start-Sleep -Seconds 2
        
        # Get Windows partition info
        $winPartition = $diskInfo.WindowsPartition
        $winPartitionOffset = $winPartition.Offset
        $diskPath = "\\.\PhysicalDrive$($diskInfo.DiskNumber)"
        
        Write-Host ""
        Write-Host "Copying data to Windows partition..." -ForegroundColor Cyan
        Write-Host "  Partition offset: $winPartitionOffset bytes" -ForegroundColor DarkGray
        Write-Host "  Partition size: $([math]::Round($winPartition.Size/1GB, 2)) GB" -ForegroundColor DarkGray
        Write-Host ""
        
        $blockSizeBytes = $BlockSizeMB * 1MB
        
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
            # Assign drive letter to Windows partition
            $availableLetters = @([char[]]('W'..'Z' + 'N'..'V') | Where-Object { -not (Test-Path -LiteralPath "$($_):") })
            
            if ((Get-SafeCount $availableLetters) -eq 0) { 
                throw "No available drive letters for Windows partition" 
            }
            
            $windowsDriveLetter = $availableLetters[0]
            
            Write-Host ""
            Write-Host "Assigning drive letter $windowsDriveLetter to Windows partition..." -ForegroundColor Cyan
            $winPartition | Set-Partition -NewDriveLetter $windowsDriveLetter
            
            Start-Sleep -Seconds 2
            
            # Install boot files
            Install-BootFiles -DiskInfo $diskInfo -WindowsDriveLetter $windowsDriveLetter
            
            # Remove drive letter
            Write-Host "Removing Windows partition drive letter..." -ForegroundColor Cyan
            try {
                $winPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue
            }
            catch { }
            $windowsDriveLetter = $null
        }
        
        Write-Host ""
        Write-Host "=== Bootable Clone Complete ===" -ForegroundColor Yellow
        Write-Host "VHDX saved to: $DestinationVHDX" -ForegroundColor Green
        
        $vhdxFile = Get-Item -LiteralPath $DestinationVHDX
        Write-Host "VHDX file size: $([math]::Round($vhdxFile.Length/1GB, 2)) GB" -ForegroundColor Cyan
        
        Write-Host ""
        Write-Host "Usage:" -ForegroundColor White
        Write-Host "  Hyper-V: Create a new VM and attach this VHDX as the primary disk" -ForegroundColor Gray
        Write-Host "  Native Boot: Use bcdedit to add a boot entry (requires Pro/Enterprise)" -ForegroundColor Gray
        
        return $DestinationVHDX
    }
    catch {
        Write-Error "Clone failed: $_"
        
        # Cleanup drive letters
        if ($windowsDriveLetter -and $diskInfo) {
            try {
                $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath "${windowsDriveLetter}:\" -ErrorAction SilentlyContinue
            }
            catch { }
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
            Write-Host "  Press any key to exit..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            return
        }
        
        Show-VolumeMenu -Volumes $volumes
        
        $selection = Read-MenuSelection -Prompt "Select volume to clone" -Min 0 -Max $volumeCount
        
        if ($selection -eq 0) {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            return
        }
        
        $selectedVolume = $volumes[$selection - 1].DriveLetter
        $volumeInfo = $volumes[$selection - 1]
        
        # Build default destination path
        $defaultName = "Bootable_${selectedVolume}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        
        $destDrives = @(Get-Volume | Where-Object {
            $_.DriveLetter -and
            $_.DriveLetter -ne $selectedVolume -and
            $_.DriveType -eq 'Fixed' -and
            $_.SizeRemaining -gt ($volumeInfo.Size + 1GB)
        } | Sort-Object SizeRemaining -Descending)
        
        $defaultPath = if ((Get-SafeCount $destDrives) -gt 0) {
            "$($destDrives[0].DriveLetter):\VMs\$defaultName"
        }
        else {
            "${selectedVolume}:\VMs\$defaultName"
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
            
            Write-Host "    [1] Boot Mode:     " -ForegroundColor Yellow -NoNewline
            if ($optBootMode -eq 'UEFI') {
                Write-Host "UEFI (GPT)" -ForegroundColor Green
            }
            else {
                Write-Host "BIOS (MBR)" -ForegroundColor White
            }
            
            Write-Host "    [2] Copy Mode:     " -ForegroundColor Yellow -NoNewline
            if ($optFullCopy) {
                Write-Host "Full (all sectors)" -ForegroundColor White
            }
            else {
                Write-Host "Smart (skip free space)" -ForegroundColor Green
            }
            
            Write-Host "    [3] VHDX Type:     " -ForegroundColor Yellow -NoNewline
            if ($optFixedSizeVHDX) {
                Write-Host "Fixed (pre-allocated)" -ForegroundColor White
            }
            else {
                Write-Host "Dynamic (grows as needed)" -ForegroundColor Green
            }
            
            Write-Host "    [4] Block Size:    " -ForegroundColor Yellow -NoNewline
            Write-Host "$optBlockSizeMB MB" -ForegroundColor White
            
            Write-Host ""
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Destination Path" -ForegroundColor Cyan
            Write-Host "    [B] Back to Volume Selection" -ForegroundColor DarkYellow
            Write-Host "    [0] Exit" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Enter choice: " -ForegroundColor White -NoNewline
            
            $userChoice = Read-Host
            
            switch ($userChoice.ToUpper()) {
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
                    Write-Host "  Block size in MB (1-64) [$optBlockSizeMB]: " -ForegroundColor White -NoNewline
                    $sizeInput = Read-Host
                    if ($sizeInput -match '^\d+$') {
                        $sizeNum = [int]$sizeInput
                        if ($sizeNum -ge 1 -and $sizeNum -le 64) {
                            $optBlockSizeMB = $sizeNum
                        }
                    }
                }
                "C" {
                    Write-Host ""
                    $destinationPath = Read-PathInput -Prompt "New destination path" -Default $destinationPath -RequiredExtension ".vhdx"
                }
                "B" {
                    continue volumeLoop
                }
                "S" {
                    # Check if destination exists
                    if (Test-Path -LiteralPath $destinationPath) {
                        Write-Host ""
                        if (-not (Read-YesNo -Prompt "Destination file exists. Overwrite?" -Default $false)) {
                            continue optionsLoop
                        }
                        Remove-Item -LiteralPath $destinationPath -Force
                    }
                    
                    Write-Host ""
                    if (Read-YesNo -Prompt "Start bootable clone operation?" -Default $true) {
                        Write-Host ""
                        
                        try {
                            New-BootableVolumeClone `
                                -SourceVolume $selectedVolume `
                                -DestinationVHDX $destinationPath `
                                -BootMode $optBootMode `
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
                        if (-not (Read-YesNo -Prompt "Clone another volume?" -Default $false)) {
                            Write-Host ""
                            Write-Host "  Goodbye!" -ForegroundColor Cyan
                            return
                        }
                        continue volumeLoop
                    }
                }
                "0" {
                    Write-Host ""
                    Write-Host "  Goodbye!" -ForegroundColor Cyan
                    return
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
elseif (-not $SourceVolume -and -not $DestinationVHDX) {
    $runInteractive = $true
}

if ($runInteractive) {
    Start-InteractiveMode
}
else {
    if (-not $SourceVolume) {
        throw "SourceVolume is required in command-line mode. Run without parameters for interactive mode."
    }
    if (-not $DestinationVHDX) {
        throw "DestinationVHDX is required in command-line mode. Run without parameters for interactive mode."
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
