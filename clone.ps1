#Requires -RunAsAdministrator
#Requires -Version 5.1

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
try { $null = [VirtDiskApi].Name; $null = [NativeDiskApi].Name; $typesLoaded = $true } catch { }
if (-not $typesLoaded) { Add-Type -TypeDefinition $nativeCodeDefinition -Language CSharp -ErrorAction Stop }

# ============================================================
# VHDX PARAMETER BUFFER
# ============================================================

function New-VhdxParameterBuffer {
    param([Guid]$UniqueId, [uint64]$MaximumSize)
    
    $bufferSize = 56
    $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
    
    for ($i = 0; $i -lt $bufferSize; $i++) {
        [System.Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, [byte]0)
    }
    
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 1)
    $guidBytes = $UniqueId.ToByteArray()
    [System.Runtime.InteropServices.Marshal]::Copy($guidBytes, 0, [IntPtr]::Add($ptr, 4), 16)
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ptr, 24, [long]$MaximumSize)
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
        throw ("Failed to create shadow copy. Error: " + $result.ReturnValue)
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
    param([string]$Path, [uint64]$SizeBytes, [switch]$FixedSize)
    
    $typeStr = "Dynamic"
    if ($FixedSize) { $typeStr = "Fixed" }
    Write-Host ("Creating " + $typeStr + " VHDX: " + $Path + " (" + (Format-ByteSize $SizeBytes) + ")...") -ForegroundColor Cyan
    
    $parentDir = Split-Path $Path -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        $null = New-Item $parentDir -ItemType Directory -Force
    }
    if (Test-Path $Path) { Remove-Item $Path -Force }
    
    # Try Hyper-V cmdlet first
    $hyperVOK = $false
    try { $null = Get-Command New-VHD -ErrorAction Stop; $hyperVOK = $true } catch { }
    
    if ($hyperVOK) {
        Write-Host "  Using Hyper-V cmdlet..." -ForegroundColor DarkGray
        try {
            if ($FixedSize) { $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Fixed }
            else { $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic }
            
            $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
            $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
            $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
            $op = New-Object VirtDiskApi+OPEN_VIRTUAL_DISK_PARAMETERS
            $op.Version = 1
            $handle = [IntPtr]::Zero
            $r = [VirtDiskApi]::OpenVirtualDisk([ref]$st, $Path, [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL, 0, [ref]$op, [ref]$handle)
            if ($r -ne 0) { throw ("OpenVirtualDisk failed: " + $r) }
            return $handle
        }
        catch {
            Write-Host ("  Hyper-V failed: " + $_) -ForegroundColor Yellow
            if (Test-Path $Path) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }
        }
    }
    
    Write-Host "  Using VirtDisk API..." -ForegroundColor DarkGray
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    
    $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $paramsPtr = New-VhdxParameterBuffer -UniqueId ([Guid]::NewGuid()) -MaximumSize $SizeBytes
    try {
        $flags = 0
        if ($FixedSize) { $flags = [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION }
        $handle = [IntPtr]::Zero
        $r = [VirtDiskApi]::CreateVirtualDisk([ref]$st, $Path, [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL, [IntPtr]::Zero, $flags, 0, $paramsPtr, [IntPtr]::Zero, [ref]$handle)
        if ($r -ne 0) { throw ("CreateVirtualDisk failed: " + (New-Object ComponentModel.Win32Exception $r).Message) }
        return $handle
    }
    finally { Remove-VhdxParameterBuffer $paramsPtr }
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
        if ($r -ne 0) { throw ("GetVirtualDiskPhysicalPath failed: " + $r) }
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
    if (-not $disk) { throw ("Disk " + $diskNum + " not found") }
    
    Write-Host ("  Disk " + $diskNum + ": " + (Format-ByteSize $disk.Size)) -ForegroundColor DarkGray
    
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
    if (-not $bootLetter) { throw "No available drive letters" }
    
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
        if ($LASTEXITCODE -ne 0) { throw ("bcdboot failed: " + $output) }
        Write-Host "  Boot files installed" -ForegroundColor Green
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
    if ($handle.IsInvalid) { throw "Failed to open volume" }
    
    try {
        $bufSize = [Runtime.InteropServices.Marshal]::SizeOf([type][NativeDiskApi+NTFS_VOLUME_DATA_BUFFER])
        $buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufSize)
        try {
            $ret = [uint32]0
            if (-not [NativeDiskApi]::DeviceIoControl($handle, [NativeDiskApi]::FSCTL_GET_NTFS_VOLUME_DATA, [IntPtr]::Zero, 0, $buf, $bufSize, [ref]$ret, [IntPtr]::Zero)) {
                throw "FSCTL_GET_NTFS_VOLUME_DATA failed"
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
    if ($handle.IsInvalid) { throw "Failed to open volume" }
    
    try {
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $bitmap = New-Object byte[] $bitmapBytes
        
        $lcn = [long]0
        $chunkSize = 1048576
        $outBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $inBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        $offset = 0
        
        try {
            while ($lcn -lt $TotalClusters) {
                [Runtime.InteropServices.Marshal]::WriteInt64($inBuf, 0, $lcn)
                $ret = [uint32]0
                $null = [NativeDiskApi]::DeviceIoControl($handle, [NativeDiskApi]::FSCTL_GET_VOLUME_BITMAP, $inBuf, 8, $outBuf, $chunkSize, [ref]$ret, [IntPtr]::Zero)
                
                $dataBytes = [int]($ret - 16)
                if ($dataBytes -gt 0) {
                    $copyLen = [math]::Min($dataBytes, $bitmap.Length - $offset)
                    if ($copyLen -gt 0) {
                        [Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($outBuf, 16), $bitmap, $offset, $copyLen)
                        $offset += $copyLen
                    }
                }
                
                $read = [long]$dataBytes * 8
                if ($read -le 0) { break }
                $lcn += $read
                
                Write-Progress -Activity "Reading Bitmap" -PercentComplete (Get-ClampedPercent $lcn $TotalClusters)
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
    
    Write-Host "Analyzing bitmap..." -ForegroundColor Cyan
    $ranges = [Collections.ArrayList]::new()
    $start = [long]-1
    $allocated = [long]0
    $interval = [math]::Max(1, [int]($TotalClusters / 100))
    
    for ($c = [long]0; $c -lt $TotalClusters; $c++) {
        $isAlloc = ($Bitmap[[int][math]::Floor($c / 8)] -band (1 -shl ($c % 8))) -ne 0
        if ($isAlloc) {
            if ($start -eq -1) { $start = $c }
            $allocated++
        }
        elseif ($start -ne -1) {
            $null = $ranges.Add([PSCustomObject]@{ Start = $start; End = $c - 1; Count = $c - $start })
            $start = -1
        }
        if ($c % $interval -eq 0) { Write-Progress -Activity "Analyzing" -PercentComplete (Get-ClampedPercent $c $TotalClusters) }
    }
    if ($start -ne -1) { $null = $ranges.Add([PSCustomObject]@{ Start = $start; End = $TotalClusters - 1; Count = $TotalClusters - $start }) }
    Write-Progress -Activity "Analyzing" -Completed
    
    Write-Host "Merging ranges..." -ForegroundColor Cyan
    $merged = [Collections.ArrayList]::new()
    $prev = $null
    foreach ($r in $ranges) {
        if ($null -eq $prev) { $prev = $r; continue }
        if (($r.Start - $prev.End - 1) -le 256) {
            $prev = [PSCustomObject]@{ Start = $prev.Start; End = $r.End; Count = $r.End - $prev.Start + 1 }
        }
        else {
            $null = $merged.Add($prev)
            $prev = $r
        }
    }
    if ($prev) { $null = $merged.Add($prev) }
    
    $allocBytes = [long]$allocated * $BytesPerCluster
    Write-Host ("  Allocated: " + (Format-ByteSize $allocBytes) + " in " + $merged.Count + " ranges") -ForegroundColor DarkGray
    return @{ Ranges = $merged; AllocatedBytes = $allocBytes }
}

# ============================================================
# RAW I/O FUNCTIONS
# ============================================================

function Open-RawDisk {
    param([string]$Path, [string]$Access)
    
    $flags = [NativeDiskApi]::GENERIC_READ
    if ($Access -eq 'Write') { $flags = [NativeDiskApi]::GENERIC_WRITE }
    elseif ($Access -eq 'ReadWrite') { $flags = [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE }
    
    $handle = [NativeDiskApi]::CreateFile($Path, $flags, 3, [IntPtr]::Zero, 3, ([NativeDiskApi]::FILE_FLAG_NO_BUFFERING -bor [NativeDiskApi]::FILE_FLAG_WRITE_THROUGH), [IntPtr]::Zero)
    if ($handle.IsInvalid) { throw ("Failed to open " + $Path) }
    return $handle
}

function Copy-FullVolume {
    param([string]$Source, [string]$DiskPath, [long]$Offset, [uint64]$Total, [int]$BlockSize)
    
    Write-Host ("Copying " + (Format-ByteSize $Total) + " (full copy)...") -ForegroundColor Cyan
    $srcH = Open-RawDisk $Source 'Read'
    $dstH = Open-RawDisk $DiskPath 'Write'
    
    try {
        $buf = New-Object byte[] $BlockSize
        $copied = [uint64]0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        while ($copied -lt $Total) {
            $remaining = $Total - $copied
            $toRead = [math]::Min([uint64]$BlockSize, $remaining)
            $aligned = [uint32]([math]::Ceiling($toRead / 4096) * 4096)
            
            $read = [uint32]0
            if (-not [NativeDiskApi]::ReadFile($srcH, $buf, $aligned, [ref]$read, [IntPtr]::Zero)) { throw "Read failed" }
            if ($read -eq 0) { break }
            
            $pos = [long]0
            if (-not [NativeDiskApi]::SetFilePointerEx($dstH, ($Offset + $copied), [ref]$pos, 0)) { throw "Seek failed" }
            
            $toWrite = [math]::Min($read, $remaining)
            $alignedW = [uint32]([math]::Ceiling($toWrite / 4096) * 4096)
            $written = [uint32]0
            if (-not [NativeDiskApi]::WriteFile($dstH, $buf, $alignedW, [ref]$written, [IntPtr]::Zero)) { throw "Write failed" }
            
            $copied += $toWrite
            $pct = Get-ClampedPercent $copied $Total
            if ($pct -gt $lastPct) {
                $speed = 0
                if ($sw.Elapsed.TotalSeconds -gt 0) { $speed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
                Write-Progress -Activity "Copying" -Status ($pct.ToString() + "% - " + [math]::Round($speed,1).ToString() + " MB/s") -PercentComplete $pct
                $lastPct = $pct
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = 0
        if ($sw.Elapsed.TotalSeconds -gt 0) { $avgSpeed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
        Write-Host ("Copied " + (Format-ByteSize $copied) + " in " + [math]::Round($sw.Elapsed.TotalMinutes,1).ToString() + " min (" + [math]::Round($avgSpeed,1).ToString() + " MB/s)") -ForegroundColor Green
    }
    finally {
        if ($srcH -and -not $srcH.IsClosed) { $srcH.Close() }
        if ($dstH -and -not $dstH.IsClosed) { $dstH.Close() }
    }
}

function Copy-AllocatedBlocks {
    param([string]$Source, [string]$DiskPath, [long]$Offset, $Ranges, [uint32]$ClusterSize, [long]$AllocBytes, [int]$BlockSize)
    
    if ($BlockSize % $ClusterSize -ne 0) { $BlockSize = [int]([math]::Ceiling($BlockSize / $ClusterSize) * $ClusterSize) }
    $clustersPerBlock = [long]($BlockSize / $ClusterSize)
    
    Write-Host ("Copying " + (Format-ByteSize $AllocBytes) + " allocated data...") -ForegroundColor Cyan
    $srcH = Open-RawDisk $Source 'Read'
    $dstH = Open-RawDisk $DiskPath 'Write'
    
    try {
        $buf = New-Object byte[] $BlockSize
        $copied = [long]0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        foreach ($r in $Ranges) {
            $cluster = [long]$r.Start
            $remaining = [long]$r.Count
            
            while ($remaining -gt 0) {
                $toRead = [math]::Min($clustersPerBlock, $remaining)
                $bytes = [uint32]($toRead * $ClusterSize)
                $srcOffset = [long]$cluster * $ClusterSize
                
                $pos = [long]0
                $null = [NativeDiskApi]::SetFilePointerEx($srcH, $srcOffset, [ref]$pos, 0)
                
                $read = [uint32]0
                if (-not [NativeDiskApi]::ReadFile($srcH, $buf, $bytes, [ref]$read, [IntPtr]::Zero)) { throw "Read failed" }
                
                $null = [NativeDiskApi]::SetFilePointerEx($dstH, ($Offset + $srcOffset), [ref]$pos, 0)
                
                $written = [uint32]0
                if (-not [NativeDiskApi]::WriteFile($dstH, $buf, $read, [ref]$written, [IntPtr]::Zero)) { throw "Write failed" }
                
                $copied += $read
                $cluster += $toRead
                $remaining -= $toRead
                
                $pct = Get-ClampedPercent $copied $AllocBytes
                if ($pct -gt $lastPct) {
                    $speed = 0
                    if ($sw.Elapsed.TotalSeconds -gt 0) { $speed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
                    Write-Progress -Activity "Copying" -Status ($pct.ToString() + "% - " + [math]::Round($speed,1).ToString() + " MB/s") -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = 0
        if ($sw.Elapsed.TotalSeconds -gt 0) { $avgSpeed = $copied / $sw.Elapsed.TotalSeconds / 1MB }
        Write-Host ("Copied " + (Format-ByteSize $copied) + " in " + [math]::Round($sw.Elapsed.TotalMinutes,1).ToString() + " min (" + [math]::Round($avgSpeed,1).ToString() + " MB/s)") -ForegroundColor Green
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
    
    try {
        $letter = $SourceVolume.TrimEnd(':', '\').ToUpper()
        $partition = Get-Partition -DriveLetter $letter
        $volume = Get-Volume -DriveLetter $letter
        
        if ($volume.FileSystemType -ne 'NTFS' -and -not $FullCopy) {
            Write-Warning "Non-NTFS volume, forcing full copy"
            $FullCopy = $true
        }
        
        $bootSize = 300MB
        if ($BootMode -ne 'UEFI') { $bootSize = 550MB }
        $vhdxSize = [uint64]($partition.Size + $bootSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host "BOOTABLE VOLUME CLONE" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Yellow
        Write-Host ""
        Write-Host ("  Source:      " + $letter + ":") -ForegroundColor White
        Write-Host ("  Destination: " + $DestinationVHDX) -ForegroundColor White
        Write-Host ("  Size:        " + (Format-ByteSize $partition.Size) + " -> " + (Format-ByteSize $vhdxSize) + " VHDX") -ForegroundColor White
        Write-Host ("  Boot Mode:   " + $BootMode) -ForegroundColor White
        $copyModeText = "Smart"
        if ($FullCopy) { $copyModeText = "Full" }
        Write-Host ("  Copy Mode:   " + $copyModeText) -ForegroundColor White
        Write-Host ""
        
        $volData = $null
        if (-not $FullCopy) {
            $volData = Get-NtfsVolumeData $letter
            $used = ($volData.TotalClusters - $volData.FreeClusters) * $volData.BytesPerCluster
            Write-Host ("  Used:        " + (Format-ByteSize $used)) -ForegroundColor DarkGray
            Write-Host ""
        }
        
        $volPath = $letter + ":\"
        $snapshot = New-VssSnapshot $volPath
        Write-Host ("Snapshot: " + $snapshot.DeviceObject) -ForegroundColor Green
        
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        $physPath = Mount-RawVHDX $vhdHandle
        Write-Host ("Attached: " + $physPath) -ForegroundColor Green
        Write-Host ""
        
        Start-Sleep -Seconds 3
        $diskInfo = Initialize-BootableVHDX $physPath $BootMode
        Start-Sleep -Seconds 2
        
        $winPart = $diskInfo.WindowsPartition
        $diskPath = "\\.\PhysicalDrive" + $diskInfo.DiskNumber
        $blockBytes = $BlockSizeMB * 1MB
        
        Write-Host ""
        Write-Host ("Partition offset: " + $winPart.Offset) -ForegroundColor DarkGray
        
        if ($FullCopy) {
            Copy-FullVolume $snapshot.DeviceObject $diskPath $winPart.Offset $partition.Size $blockBytes
        }
        else {
            $bitmap = Get-VolumeBitmap $letter $volData.TotalClusters
            $alloc = Get-AllocatedRanges $bitmap $volData.TotalClusters $volData.BytesPerCluster
            Copy-AllocatedBlocks $snapshot.DeviceObject $diskPath $winPart.Offset $alloc.Ranges $volData.BytesPerCluster $alloc.AllocatedBytes $blockBytes
        }
        
        if (-not $SkipBootFix) {
            $winLetter = Get-AvailableDriveLetter
            if (-not $winLetter) { throw "No drive letters available" }
            
            Write-Host ""
            Write-Host ("Assigning " + $winLetter + " to Windows partition...") -ForegroundColor Cyan
            $winPart | Set-Partition -NewDriveLetter $winLetter
            Start-Sleep -Seconds 2
            
            Install-BootFiles $diskInfo $winLetter
            
            Write-Host "Removing drive letter..." -ForegroundColor Cyan
            $accessPath = $winLetter + ":\"
            try { $winPart | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue } catch { }
            $winLetter = $null
        }
        
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host "CLONE COMPLETE" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Green
        Write-Host ""
        Write-Host ("  File: " + $DestinationVHDX) -ForegroundColor White
        $fileSize = (Get-Item $DestinationVHDX).Length
        Write-Host ("  Size: " + (Format-ByteSize $fileSize)) -ForegroundColor White
        Write-Host ""
        
        return $DestinationVHDX
    }
    catch {
        Write-Host ""
        Write-Host ("Clone failed: " + $_) -ForegroundColor Red
        
        if ($winLetter -and $diskInfo) {
            $accessPath = $winLetter + ":\"
            try { $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath $accessPath -ErrorAction SilentlyContinue } catch { }
        }
        if ($vhdHandle -ne [IntPtr]::Zero) {
            try { Dismount-RawVHDX $vhdHandle } catch { }
            $vhdHandle = [IntPtr]::Zero
        }
        if (Test-Path $DestinationVHDX -ErrorAction SilentlyContinue) {
            Write-Host "Cleaning up..." -ForegroundColor Yellow
            Remove-Item $DestinationVHDX -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    finally {
        if ($vhdHandle -ne [IntPtr]::Zero) { Dismount-RawVHDX $vhdHandle }
        if ($snapshot) { Remove-VssSnapshot $snapshot.Id }
    }
}

# ============================================================
# INTERACTIVE MODE
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
            Write-Host ("    [" + $num + "] " + $v.DriveLetter + ": " + $label + " - " + $used + "/" + $total + " GB (" + $v.FileSystemType + ")") -ForegroundColor Yellow
        }
        Write-Host "    [0] Exit" -ForegroundColor Red
        Write-Host ""
        
        Write-Host ("  Select volume (0-" + $volumeCount + "): ") -ForegroundColor White -NoNewline
        $input1 = Read-Host
        
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
        
        # Default destination
        $dateStr = Get-Date -Format 'yyyyMMdd_HHmmss'
        $defaultDest = $srcLetter + ":\VMs\Bootable_" + $srcLetter + "_" + $dateStr + ".vhdx"
        
        # Find other drives with space
        $otherDrives = [System.Collections.ArrayList]::new()
        foreach ($v in $allVolumes) {
            if ($v.DriveLetter -and ([string]$v.DriveLetter) -ne $srcLetter -and $v.DriveType -eq 'Fixed' -and $v.SizeRemaining -gt ($srcVol.Size + 1GB)) {
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
            Write-Host ("  Source: " + $srcLetter + ": (" + $label + ")") -ForegroundColor White
            Write-Host ("  Destination: " + $destPath) -ForegroundColor White
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor White
            Write-Host ("    [1] Boot Mode:  " + $bootMode) -ForegroundColor Yellow
            $copyText = "Smart"
            if ($fullCopy) { $copyText = "Full" }
            Write-Host ("    [2] Copy Mode:  " + $copyText) -ForegroundColor Yellow
            $vhdxText = "Dynamic"
            if ($fixedVhdx) { $vhdxText = "Fixed" }
            Write-Host ("    [3] VHDX Type:  " + $vhdxText) -ForegroundColor Yellow
            Write-Host ("    [4] Block Size: " + $blockSize + "MB") -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Path" -ForegroundColor Cyan
            Write-Host "    [B] Back" -ForegroundColor DarkYellow
            Write-Host "    [Q] Quit" -ForegroundColor Red
            Write-Host ""
            
            Write-Host "  Choice: " -ForegroundColor White -NoNewline
            $choice = (Read-Host).Trim().ToUpper()
            
            switch ($choice) {
                '1' { if ($bootMode -eq 'UEFI') { $bootMode = 'BIOS' } else { $bootMode = 'UEFI' } }
                '2' { $fullCopy = -not $fullCopy }
                '3' { $fixedVhdx = -not $fixedVhdx }
                '4' {
                    Write-Host ("  Block size (1-64) [" + $blockSize + "]: ") -NoNewline
                    $bs = Read-Host
                    $bsNum = 0
                    if ([int]::TryParse($bs.Trim(), [ref]$bsNum) -and $bsNum -ge 1 -and $bsNum -le 64) { $blockSize = $bsNum }
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
                        Write-Host "  File exists. Overwrite? (y/N): " -NoNewline
                        if ((Read-Host).Trim().ToLower() -ne 'y') { continue }
                        Remove-Item $destPath -Force
                    }
                    
                    Write-Host "  Start clone? (Y/n): " -NoNewline
                    $confirm = (Read-Host).Trim().ToLower()
                    if ($confirm -eq 'n') { continue }
                    
                    Write-Host ""
                    try {
                        New-BootableVolumeClone -SourceVolume $srcLetter -DestinationVHDX $destPath -BootMode $bootMode -FullCopy:$fullCopy -FixedSizeVHDX:$fixedVhdx -BlockSizeMB $blockSize
                        Write-Host "  Success!" -ForegroundColor Green
                    }
                    catch {
                        Write-Host ("  Failed: " + $_) -ForegroundColor Red
                    }
                    
                    Wait-ForKeyPress
                    
                    Write-Host "  Clone another? (y/N): " -NoNewline
                    if ((Read-Host).Trim().ToLower() -ne 'y') {
                        Write-Host ""; Write-Host "  Goodbye!" -ForegroundColor Cyan
                        return
                    }
                    $exitOpts = $true
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
        throw "SourceVolume and DestinationVHDX are required"
    }
    New-BootableVolumeClone -SourceVolume $SourceVolume -DestinationVHDX $DestinationVHDX -BootMode $BootMode -FullCopy:$FullCopy -FixedSizeVHDX:$FixedSizeVHDX -SkipBootFix:$SkipBootFix -BlockSizeMB $BlockSizeMB
}
