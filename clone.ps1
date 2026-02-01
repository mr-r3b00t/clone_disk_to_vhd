#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Clone a live Windows volume to a bootable VHDX file.
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

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script requires Administrator privileges."
}

#region Helper Functions

function Get-ClampedPercent([double]$Current, [double]$Total) {
    if ($Total -le 0) { return 0 }
    return [int][math]::Min(100, [math]::Max(0, [math]::Floor(($Current / $Total) * 100)))
}

function Wait-KeyPress {
    Write-Host "  Press Enter to continue..." -ForegroundColor Gray
    $null = Read-Host
}

function Get-AvailableDriveLetter {
    $used = @()
    Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object { $used += $_.DriveLetter }
    Get-CimInstance Win32_MappedLogicalDisk -ErrorAction SilentlyContinue | ForEach-Object { 
        if ($_.DeviceID) { $used += $_.DeviceID[0] }
    }
    
    foreach ($l in 'S','T','U','V','W','X','Y','Z') {
        if ($l -cnotin $used -and -not (Test-Path "${l}:\")) {
            return $l
        }
    }
    return $null
}

#endregion

#region P/Invoke

$nativeCode = @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VirtDiskApi {
    public const uint VIRTUAL_DISK_ACCESS_ALL = 0x003f0000;
    public const uint CREATE_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION = 1;
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NONE = 0;
    public const uint ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 1;
    public const uint OPEN_VIRTUAL_DISK_FLAG_NONE = 0;
    public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
    public static readonly Guid VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT = new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");

    [StructLayout(LayoutKind.Sequential)]
    public struct VIRTUAL_STORAGE_TYPE { public int DeviceId; public Guid VendorId; }

    [StructLayout(LayoutKind.Sequential)]
    public struct ATTACH_VIRTUAL_DISK_PARAMETERS { public int Version; public int Reserved; }

    [StructLayout(LayoutKind.Sequential)]
    public struct OPEN_VIRTUAL_DISK_PARAMETERS { public int Version; public int RWDepth; }

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateVirtualDisk(ref VIRTUAL_STORAGE_TYPE VirtualStorageType, string Path, uint VirtualDiskAccessMask, IntPtr SecurityDescriptor, uint Flags, uint ProviderSpecificFlags, IntPtr Parameters, IntPtr Overlapped, out IntPtr Handle);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int OpenVirtualDisk(ref VIRTUAL_STORAGE_TYPE VirtualStorageType, string Path, uint VirtualDiskAccessMask, uint Flags, ref OPEN_VIRTUAL_DISK_PARAMETERS Parameters, out IntPtr Handle);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int AttachVirtualDisk(IntPtr VirtualDiskHandle, IntPtr SecurityDescriptor, uint Flags, uint ProviderSpecificFlags, ref ATTACH_VIRTUAL_DISK_PARAMETERS Parameters, IntPtr Overlapped);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DetachVirtualDisk(IntPtr VirtualDiskHandle, uint Flags, uint ProviderSpecificFlags);

    [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int GetVirtualDiskPhysicalPath(IntPtr VirtualDiskHandle, ref int DiskPathSizeInBytes, IntPtr DiskPath);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

public static class NativeDiskApi {
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
    public struct NTFS_VOLUME_DATA_BUFFER {
        public long VolumeSerialNumber, NumberSectors, TotalClusters, FreeClusters, TotalReserved;
        public uint BytesPerSector, BytesPerCluster, BytesPerFileRecordSegment, ClustersPerFileRecordSegment;
        public long MftValidDataLength, MftStartLcn, Mft2StartLcn, MftZoneStart, MftZoneEnd;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(SafeFileHandle hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(SafeFileHandle hFile, long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);
}
'@

try { $null = [VirtDiskApi].Name } catch { Add-Type -TypeDefinition $nativeCode -Language CSharp }

#endregion

#region VHDX Parameters

function New-VhdxParamsBuffer([Guid]$UniqueId, [uint64]$MaxSize) {
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal(56)
    for ($i = 0; $i -lt 56; $i++) { [Runtime.InteropServices.Marshal]::WriteByte($ptr, $i, 0) }
    [Runtime.InteropServices.Marshal]::WriteInt32($ptr, 0, 1)
    [Runtime.InteropServices.Marshal]::Copy($UniqueId.ToByteArray(), 0, [IntPtr]::Add($ptr, 4), 16)
    [Runtime.InteropServices.Marshal]::WriteInt64($ptr, 24, [long]$MaxSize)
    [Runtime.InteropServices.Marshal]::WriteInt32($ptr, 36, 512)
    return $ptr
}

#endregion

#region VSS Functions

function New-VssSnapshot([string]$Volume) {
    if (-not $Volume.EndsWith('\')) { $Volume += '\' }
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{ Volume = $Volume; Context = 'ClientAccessible' }
    if ($result.ReturnValue -ne 0) { throw "Failed to create shadow copy. Error: $($result.ReturnValue)" }
    
    $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
    if (-not $shadow) { throw "Shadow copy created but could not be retrieved." }
    
    return @{ Id = $result.ShadowID; DeviceObject = $shadow.DeviceObject; VolumeName = $Volume }
}

function Remove-VssSnapshot([string]$ShadowId) {
    Write-Host "Removing VSS snapshot..." -ForegroundColor Cyan
    $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) { Remove-CimInstance -InputObject $shadow -ErrorAction SilentlyContinue }
}

#endregion

#region Virtual Disk Functions

function New-RawVHDX([string]$Path, [uint64]$SizeBytes, [switch]$FixedSize) {
    $typeStr = if ($FixedSize) { "Fixed" } else { "Dynamic" }
    Write-Host "Creating $typeStr VHDX: $Path ($([math]::Round($SizeBytes/1GB, 2)) GB)..." -ForegroundColor Cyan
    
    $parentDir = Split-Path $Path -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) { $null = New-Item $parentDir -ItemType Directory -Force }
    if (Test-Path $Path) { Remove-Item $Path -Force }
    
    # Try Hyper-V cmdlet first
    try {
        $null = Get-Command New-VHD -ErrorAction Stop
        Write-Host "  Using Hyper-V cmdlet..." -ForegroundColor DarkGray
        if ($FixedSize) { $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Fixed }
        else { $null = New-VHD -Path $Path -SizeBytes $SizeBytes -Dynamic }
        
        $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
        $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
        $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
        $op = New-Object VirtDiskApi+OPEN_VIRTUAL_DISK_PARAMETERS
        $op.Version = 1
        $handle = [IntPtr]::Zero
        $r = [VirtDiskApi]::OpenVirtualDisk([ref]$st, $Path, [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL, 0, [ref]$op, [ref]$handle)
        if ($r -ne 0) { throw "OpenVirtualDisk failed: $r" }
        return $handle
    }
    catch {
        Write-Host "  Hyper-V unavailable, using VirtDisk API..." -ForegroundColor DarkGray
        if (Test-Path $Path) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }
    }
    
    $SizeBytes = [uint64]([math]::Ceiling($SizeBytes / 1MB) * 1MB)
    $st = New-Object VirtDiskApi+VIRTUAL_STORAGE_TYPE
    $st.DeviceId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $st.VendorId = [VirtDiskApi]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $paramsPtr = New-VhdxParamsBuffer -UniqueId ([Guid]::NewGuid()) -MaxSize $SizeBytes
    try {
        $flags = if ($FixedSize) { [VirtDiskApi]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION } else { 0 }
        $handle = [IntPtr]::Zero
        $r = [VirtDiskApi]::CreateVirtualDisk([ref]$st, $Path, [VirtDiskApi]::VIRTUAL_DISK_ACCESS_ALL, [IntPtr]::Zero, $flags, 0, $paramsPtr, [IntPtr]::Zero, [ref]$handle)
        if ($r -ne 0) { throw "CreateVirtualDisk failed: $(New-Object ComponentModel.Win32Exception $r)" }
        return $handle
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($paramsPtr) }
}

function Mount-RawVHDX([IntPtr]$Handle) {
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    $ap = New-Object VirtDiskApi+ATTACH_VIRTUAL_DISK_PARAMETERS
    $ap.Version = 1
    $r = [VirtDiskApi]::AttachVirtualDisk($Handle, [IntPtr]::Zero, [VirtDiskApi]::ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, 0, [ref]$ap, [IntPtr]::Zero)
    if ($r -ne 0) { throw "AttachVirtualDisk failed: $(New-Object ComponentModel.Win32Exception $r)" }
    
    $pathSize = 520
    $pathBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal($pathSize)
    try {
        $r = [VirtDiskApi]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSize, $pathBuf)
        if ($r -ne 0) { throw "GetVirtualDiskPhysicalPath failed: $r" }
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($pathBuf)
    }
    finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($pathBuf) }
}

function Dismount-RawVHDX([IntPtr]$Handle) {
    if ($Handle -eq [IntPtr]::Zero) { return }
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    $null = [VirtDiskApi]::DetachVirtualDisk($Handle, 0, 0)
    $null = [VirtDiskApi]::CloseHandle($Handle)
}

#endregion

#region Disk Initialization

function Initialize-BootableVHDX([string]$PhysicalPath, [string]$BootMode) {
    Write-Host "Initializing disk for $BootMode boot..." -ForegroundColor Cyan
    
    if ($PhysicalPath -match 'PhysicalDrive(\d+)') { $diskNum = [int]$Matches[1] }
    else { throw "Could not parse disk number from: $PhysicalPath" }
    
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        $disk = Get-Disk -Number $diskNum -ErrorAction SilentlyContinue
        if ($disk) { break }
    }
    if (-not $disk) { throw "Disk $diskNum not found" }
    
    Write-Host "  Disk $diskNum: $([math]::Round($disk.Size/1GB,2)) GB" -ForegroundColor DarkGray
    
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

function Install-BootFiles([hashtable]$DiskInfo, [string]$WinLetter) {
    Write-Host "Installing boot files..." -ForegroundColor Cyan
    
    $winPath = "${WinLetter}:\Windows"
    if (-not (Test-Path $winPath)) { throw "Windows not found at $winPath" }
    
    $bootLetter = Get-AvailableDriveLetter
    if (-not $bootLetter) { throw "No available drive letters" }
    
    $bootPartition = if ($DiskInfo.BootMode -eq 'UEFI') { $DiskInfo.EspPartition } else { $DiskInfo.SystemPartition }
    $firmware = if ($DiskInfo.BootMode -eq 'UEFI') { 'UEFI' } else { 'BIOS' }
    
    Write-Host "  Assigning $bootLetter to boot partition..." -ForegroundColor DarkGray
    $bootPartition | Set-Partition -NewDriveLetter $bootLetter
    Start-Sleep -Seconds 2
    
    try {
        Write-Host "  Running bcdboot /f $firmware..." -ForegroundColor DarkGray
        $output = & bcdboot.exe "$winPath" /s "${bootLetter}:" /f $firmware 2>&1
        if ($LASTEXITCODE -ne 0) { throw "bcdboot failed: $output" }
        Write-Host "  Boot files installed" -ForegroundColor Green
    }
    finally {
        try { $bootPartition | Remove-PartitionAccessPath -AccessPath "${bootLetter}:\" -ErrorAction SilentlyContinue } catch { }
    }
}

#endregion

#region NTFS Bitmap Functions

function Get-NtfsVolumeData([string]$DriveLetter) {
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $handle = [NativeDiskApi]::CreateFile("\\.\${DriveLetter}:", [NativeDiskApi]::GENERIC_READ, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
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
            return @{ TotalClusters = $data.TotalClusters; FreeClusters = $data.FreeClusters; BytesPerCluster = $data.BytesPerCluster; BytesPerSector = $data.BytesPerSector }
        }
        finally { [Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    }
    finally { $handle.Close() }
}

function Get-VolumeBitmap([string]$DriveLetter, [long]$TotalClusters) {
    Write-Host "Reading allocation bitmap..." -ForegroundColor Cyan
    $DriveLetter = $DriveLetter.TrimEnd(':', '\')
    $handle = [NativeDiskApi]::CreateFile("\\.\${DriveLetter}:", [NativeDiskApi]::GENERIC_READ, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
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

function Get-AllocatedRanges([byte[]]$Bitmap, [long]$TotalClusters, [uint32]$BytesPerCluster) {
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
    
    # Merge nearby ranges
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
    Write-Host "  Allocated: $([math]::Round($allocBytes/1GB,2)) GB in $($merged.Count) ranges" -ForegroundColor DarkGray
    return @{ Ranges = $merged; AllocatedBytes = $allocBytes }
}

#endregion

#region Raw I/O

function Open-RawDisk([string]$Path, [string]$Access) {
    $flags = switch ($Access) {
        'Read' { [NativeDiskApi]::GENERIC_READ }
        'Write' { [NativeDiskApi]::GENERIC_WRITE }
        default { [NativeDiskApi]::GENERIC_READ -bor [NativeDiskApi]::GENERIC_WRITE }
    }
    $handle = [NativeDiskApi]::CreateFile($Path, $flags, 3, [IntPtr]::Zero, 3, ([NativeDiskApi]::FILE_FLAG_NO_BUFFERING -bor [NativeDiskApi]::FILE_FLAG_WRITE_THROUGH), [IntPtr]::Zero)
    if ($handle.IsInvalid) { throw "Failed to open $Path" }
    return $handle
}

function Copy-DataToPartition([string]$Source, [string]$DiskPath, [long]$Offset, [uint64]$Total, [int]$BlockSize) {
    Write-Host "Copying $([math]::Round($Total/1GB,2)) GB..." -ForegroundColor Cyan
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
            if (-not [NativeDiskApi]::ReadFile($srcH, $buf, $aligned, [ref]$read, [IntPtr]::Zero)) { throw "Read failed at $copied" }
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
                $speed = if ($sw.Elapsed.TotalSeconds -gt 0) { $copied / $sw.Elapsed.TotalSeconds / 1MB } else { 0 }
                Write-Progress -Activity "Copying" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                $lastPct = $pct
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = if ($sw.Elapsed.TotalSeconds -gt 0) { $copied / $sw.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $([math]::Round($copied/1GB,2)) GB in $([math]::Round($sw.Elapsed.TotalMinutes,1)) min ($([math]::Round($avgSpeed,1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if ($srcH -and -not $srcH.IsClosed) { $srcH.Close() }
        if ($dstH -and -not $dstH.IsClosed) { $dstH.Close() }
    }
}

function Copy-AllocatedData([string]$Source, [string]$DiskPath, [long]$Offset, $Ranges, [uint32]$ClusterSize, [long]$AllocBytes, [int]$BlockSize) {
    if ($BlockSize % $ClusterSize -ne 0) { $BlockSize = [int]([math]::Ceiling($BlockSize / $ClusterSize) * $ClusterSize) }
    $clustersPerBlock = [long]($BlockSize / $ClusterSize)
    
    Write-Host "Copying $([math]::Round($AllocBytes/1GB,2)) GB allocated data..." -ForegroundColor Cyan
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
                    $speed = if ($sw.Elapsed.TotalSeconds -gt 0) { $copied / $sw.Elapsed.TotalSeconds / 1MB } else { 0 }
                    Write-Progress -Activity "Copying" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                    $lastPct = $pct
                }
            }
        }
        $sw.Stop()
        Write-Progress -Activity "Copying" -Completed
        $avgSpeed = if ($sw.Elapsed.TotalSeconds -gt 0) { $copied / $sw.Elapsed.TotalSeconds / 1MB } else { 0 }
        Write-Host "Copied $([math]::Round($copied/1GB,2)) GB in $([math]::Round($sw.Elapsed.TotalMinutes,1)) min ($([math]::Round($avgSpeed,1)) MB/s)" -ForegroundColor Green
    }
    finally {
        if ($srcH -and -not $srcH.IsClosed) { $srcH.Close() }
        if ($dstH -and -not $dstH.IsClosed) { $dstH.Close() }
    }
}

#endregion

#region Main Clone Function

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
        
        $bootSize = if ($BootMode -eq 'UEFI') { 300MB } else { 550MB }
        $vhdxSize = [uint64]($partition.Size + $bootSize + 100MB)
        $vhdxSize = [uint64]([math]::Ceiling($vhdxSize / 1MB) * 1MB)
        
        Write-Host "`n$('='*60)" -ForegroundColor Yellow
        Write-Host "BOOTABLE VOLUME CLONE" -ForegroundColor Yellow
        Write-Host "$('='*60)`n" -ForegroundColor Yellow
        Write-Host "  Source:      ${letter}:" -ForegroundColor White
        Write-Host "  Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "  Size:        $([math]::Round($partition.Size/1GB,2)) GB -> $([math]::Round($vhdxSize/1GB,2)) GB VHDX" -ForegroundColor White
        Write-Host "  Boot Mode:   $BootMode" -ForegroundColor White
        Write-Host "  Copy Mode:   $(if ($FullCopy) {'Full'} else {'Smart'})`n" -ForegroundColor White
        
        $volData = $null
        if (-not $FullCopy) {
            $volData = Get-NtfsVolumeData $letter
            $used = ($volData.TotalClusters - $volData.FreeClusters) * $volData.BytesPerCluster
            Write-Host "  Used:        $([math]::Round($used/1GB,2)) GB`n" -ForegroundColor DarkGray
        }
        
        $snapshot = New-VssSnapshot "${letter}:\"
        Write-Host "Snapshot: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        $physPath = Mount-RawVHDX $vhdHandle
        Write-Host "Attached: $physPath`n" -ForegroundColor Green
        
        Start-Sleep -Seconds 3
        $diskInfo = Initialize-BootableVHDX $physPath $BootMode
        Start-Sleep -Seconds 2
        
        $winPart = $diskInfo.WindowsPartition
        $diskPath = "\\.\PhysicalDrive$($diskInfo.DiskNumber)"
        $blockBytes = $BlockSizeMB * 1MB
        
        Write-Host "`nPartition offset: $($winPart.Offset) bytes" -ForegroundColor DarkGray
        
        if ($FullCopy) {
            Copy-DataToPartition $snapshot.DeviceObject $diskPath $winPart.Offset $partition.Size $blockBytes
        }
        else {
            $bitmap = Get-VolumeBitmap $letter $volData.TotalClusters
            $alloc = Get-AllocatedRanges $bitmap $volData.TotalClusters $volData.BytesPerCluster
            Copy-AllocatedData $snapshot.DeviceObject $diskPath $winPart.Offset $alloc.Ranges $volData.BytesPerCluster $alloc.AllocatedBytes $blockBytes
        }
        
        if (-not $SkipBootFix) {
            $winLetter = Get-AvailableDriveLetter
            if (-not $winLetter) { throw "No drive letters available" }
            
            Write-Host "`nAssigning $winLetter to Windows partition..." -ForegroundColor Cyan
            $winPart | Set-Partition -NewDriveLetter $winLetter
            Start-Sleep -Seconds 2
            
            Install-BootFiles $diskInfo $winLetter
            
            Write-Host "Removing drive letter..." -ForegroundColor Cyan
            try { $winPart | Remove-PartitionAccessPath -AccessPath "${winLetter}:\" -ErrorAction SilentlyContinue } catch { }
            $winLetter = $null
        }
        
        Write-Host "`n$('='*60)" -ForegroundColor Green
        Write-Host "CLONE COMPLETE" -ForegroundColor Green
        Write-Host "$('='*60)`n" -ForegroundColor Green
        Write-Host "  File: $DestinationVHDX" -ForegroundColor White
        Write-Host "  Size: $([math]::Round((Get-Item $DestinationVHDX).Length/1GB,2)) GB`n" -ForegroundColor White
        
        return $DestinationVHDX
    }
    catch {
        Write-Host "`nClone failed: $_" -ForegroundColor Red
        
        if ($winLetter -and $diskInfo) {
            try { $diskInfo.WindowsPartition | Remove-PartitionAccessPath -AccessPath "${winLetter}:\" -ErrorAction SilentlyContinue } catch { }
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

#endregion

#region Interactive Mode

function Show-Banner {
    Clear-Host
    Write-Host "`n  ╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║           BOOTABLE VOLUME CLONE UTILITY                    ║" -ForegroundColor Cyan
    Write-Host "  ║     Clone running Windows to bootable VHDX                 ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

function Start-InteractiveMode {
    $bootMode = 'UEFI'
    $fullCopy = $false
    $fixedVhdx = $false
    $blockSize = 4
    
    while ($true) {
        Show-Banner
        
        $volumes = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' -and $_.Size -gt 0 } | Sort-Object DriveLetter)
        if ($volumes.Count -eq 0) {
            Write-Host "  No volumes found!" -ForegroundColor Red
            Wait-KeyPress
            return
        }
        
        Write-Host "  Available Volumes:`n" -ForegroundColor White
        for ($i = 0; $i -lt $volumes.Count; $i++) {
            $v = $volumes[$i]
            $used = [math]::Round(($v.Size - $v.SizeRemaining) / 1GB, 1)
            $total = [math]::Round($v.Size / 1GB, 1)
            $label = if ($v.FileSystemLabel) { $v.FileSystemLabel } else { "Local Disk" }
            Write-Host "    [$($i+1)] $($v.DriveLetter): $label - $used/$total GB ($($v.FileSystemType))" -ForegroundColor Yellow
        }
        Write-Host "    [0] Exit`n" -ForegroundColor Red
        
        Write-Host "  Select volume (0-$($volumes.Count)): " -ForegroundColor White -NoNewline
        $input = Read-Host
        
        $sel = 0
        if (-not [int]::TryParse($input, [ref]$sel) -or $sel -lt 0 -or $sel -gt $volumes.Count) {
            Write-Host "  Invalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }
        if ($sel -eq 0) { Write-Host "`n  Goodbye!" -ForegroundColor Cyan; return }
        
        $srcVol = $volumes[$sel - 1]
        $srcLetter = $srcVol.DriveLetter
        
        # Default destination
        $defaultDest = "${srcLetter}:\VMs\Bootable_${srcLetter}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        $otherDrives = @(Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne $srcLetter -and $_.DriveType -eq 'Fixed' -and $_.SizeRemaining -gt ($srcVol.Size + 1GB) } | Sort-Object SizeRemaining -Descending)
        if ($otherDrives.Count -gt 0) {
            $defaultDest = "$($otherDrives[0].DriveLetter):\VMs\Bootable_${srcLetter}_$(Get-Date -Format 'yyyyMMdd_HHmmss').vhdx"
        }
        
        Write-Host "`n  Destination VHDX path"
        Write-Host "  [Default: $defaultDest]"
        Write-Host "  : " -NoNewline
        $destPath = Read-Host
        if ([string]::IsNullOrWhiteSpace($destPath)) { $destPath = $defaultDest }
        if (-not $destPath.ToLower().EndsWith('.vhdx')) { $destPath += '.vhdx' }
        
        # Options menu
        while ($true) {
            Show-Banner
            Write-Host "  Source: ${srcLetter}: ($($srcVol.FileSystemLabel))" -ForegroundColor White
            Write-Host "  Destination: $destPath`n" -ForegroundColor White
            
            Write-Host "  Options:" -ForegroundColor White
            Write-Host "    [1] Boot Mode:  $bootMode" -ForegroundColor Yellow
            Write-Host "    [2] Copy Mode:  $(if($fullCopy){'Full'}else{'Smart'})" -ForegroundColor Yellow
            Write-Host "    [3] VHDX Type:  $(if($fixedVhdx){'Fixed'}else{'Dynamic'})" -ForegroundColor Yellow
            Write-Host "    [4] Block Size: ${blockSize}MB`n" -ForegroundColor Yellow
            Write-Host "    [S] Start Clone" -ForegroundColor Green
            Write-Host "    [C] Change Path" -ForegroundColor Cyan
            Write-Host "    [B] Back" -ForegroundColor DarkYellow
            Write-Host "    [Q] Quit`n" -ForegroundColor Red
            
            Write-Host "  Choice: " -ForegroundColor White -NoNewline
            $choice = (Read-Host).Trim().ToUpper()
            
            switch ($choice) {
                '1' { $bootMode = if ($bootMode -eq 'UEFI') { 'BIOS' } else { 'UEFI' } }
                '2' { $fullCopy = -not $fullCopy }
                '3' { $fixedVhdx = -not $fixedVhdx }
                '4' {
                    Write-Host "  Block size (1-64) [$blockSize]: " -NoNewline
                    $bs = Read-Host
                    $bsNum = 0
                    if ([int]::TryParse($bs, [ref]$bsNum) -and $bsNum -ge 1 -and $bsNum -le 64) { $blockSize = $bsNum }
                }
                'C' {
                    Write-Host "  New path [$destPath]: " -NoNewline
                    $np = Read-Host
                    if (-not [string]::IsNullOrWhiteSpace($np)) {
                        $destPath = $np
                        if (-not $destPath.ToLower().EndsWith('.vhdx')) { $destPath += '.vhdx' }
                    }
                }
                'B' { break }
                'Q' { Write-Host "`n  Goodbye!" -ForegroundColor Cyan; return }
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
                        Write-Host "  Failed: $_" -ForegroundColor Red
                    }
                    
                    Wait-KeyPress
                    
                    Write-Host "  Clone another? (y/N): " -NoNewline
                    if ((Read-Host).Trim().ToLower() -ne 'y') {
                        Write-Host "`n  Goodbye!" -ForegroundColor Cyan
                        return
                    }
                    break
                }
            }
            
            if ($choice -eq 'B') { break }
        }
    }
}

#endregion

#region Entry Point

if ($PSCmdlet.ParameterSetName -eq 'Interactive' -or (-not $SourceVolume -and -not $DestinationVHDX)) {
    Start-InteractiveMode
}
else {
    if (-not $SourceVolume -or -not $DestinationVHDX) {
        throw "SourceVolume and DestinationVHDX are required"
    }
    New-BootableVolumeClone -SourceVolume $SourceVolume -DestinationVHDX $DestinationVHDX -BootMode $BootMode -FullCopy:$FullCopy -FixedSizeVHDX:$FixedSizeVHDX -SkipBootFix:$SkipBootFix -BlockSizeMB $BlockSizeMB
}

#endregion
