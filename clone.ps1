#Requires -RunAsAdministrator

# ============================================================
# Part 1: P/Invoke Definitions (with CreateFile for raw I/O)
# ============================================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VirtDisk
{
    public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
    public const int CREATE_VIRTUAL_DISK_VERSION_2 = 2;
    public const int OPEN_VIRTUAL_DISK_VERSION_2 = 2;
    public const int ATTACH_VIRTUAL_DISK_VERSION_1 = 1;
    
    public const uint VIRTUAL_DISK_ACCESS_ALL = 0x003f0000;
    public const uint VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x00020000;
    
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
    public struct OPEN_VIRTUAL_DISK_PARAMETERS
    {
        public int Version;
        public bool GetInfoOnly;
        public bool ReadOnly;
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
        [Out] System.Text.StringBuilder DiskPath);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}

public static class NativeDisk
{
    // CreateFile constants
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
    public const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    
    // IOCTL codes
    public const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C;
    public const uint FSCTL_LOCK_VOLUME = 0x00090018;
    public const uint FSCTL_UNLOCK_VOLUME = 0x0009001C;
    public const uint FSCTL_DISMOUNT_VOLUME = 0x00090020;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct GET_LENGTH_INFORMATION
    {
        public long Length;
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
        out GET_LENGTH_INFORMATION lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
    
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
"@

# ============================================================
# Part 2: VSS Functions using CIM (modern replacement for WMI)
# ============================================================

function New-VssSnapshot {
    param(
        [Parameter(Mandatory)]
        [string]$Volume  # e.g., "C:\"
    )
    
    # Normalize volume path
    if (-not $Volume.EndsWith("\")) { $Volume += "\" }
    
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    # Use CIM to create shadow copy (modern replacement for WMI)
    $shadowClass = Get-CimClass -ClassName Win32_ShadowCopy
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume = $Volume
        Context = "ClientAccessible"
    }
    
    if ($result.ReturnValue -ne 0) {
        throw "Failed to create shadow copy. Error code: $($result.ReturnValue)"
    }
    
    # Get the shadow copy object
    $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | 
        Where-Object { $_.ID -eq $result.ShadowID }
    
    return @{
        Id = $result.ShadowID
        DeviceObject = $shadowCopy.DeviceObject
        VolumeName = $Volume
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
        Remove-CimInstance -InputObject $shadow
    }
}

# ============================================================
# Part 3: Virtual Disk Functions
# ============================================================

function New-RawVHDX {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter(Mandatory)]
        [uint64]$SizeBytes
    )
    
    Write-Host "Creating VHDX: $Path ($([math]::Round($SizeBytes/1GB, 2)) GB)..." -ForegroundColor Cyan
    
    $storageType = New-Object VirtDisk+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $params = New-Object VirtDisk+CREATE_VIRTUAL_DISK_PARAMETERS
    $params.Version = [VirtDisk]::CREATE_VIRTUAL_DISK_VERSION_2
    $params.MaximumSize = $SizeBytes
    $params.BlockSizeInBytes = 0      # Default block size
    $params.SectorSizeInBytes = 512   # Logical sector size
    $params.PhysicalSectorSizeInBytes = 4096  # Physical sector size for 4Kn drives
    $params.UniqueId = [Guid]::NewGuid()
    
    $handle = [IntPtr]::Zero
    $result = [VirtDisk]::CreateVirtualDisk(
        [ref]$storageType,
        $Path,
        [VirtDisk]::VIRTUAL_DISK_ACCESS_ALL,
        [IntPtr]::Zero,
        0,   # CREATE_VIRTUAL_DISK_FLAG_NONE
        0,
        [ref]$params,
        [IntPtr]::Zero,
        [ref]$handle
    )
    
    if ($result -ne 0) {
        throw "CreateVirtualDisk failed with error: $result (0x$($result.ToString('X8')))"
    }
    
    return $handle
}

function Mount-RawVHDX {
    param(
        [Parameter(Mandatory)]
        [IntPtr]$Handle
    )
    
    Write-Host "Attaching VHDX..." -ForegroundColor Cyan
    
    $attachParams = New-Object VirtDisk+ATTACH_VIRTUAL_DISK_PARAMETERS
    $attachParams.Version = [VirtDisk]::ATTACH_VIRTUAL_DISK_VERSION_1
    
    # ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 1
    # ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = 4 (optional, survives handle close)
    $result = [VirtDisk]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        1,   # NO_DRIVE_LETTER - we want raw access
        0,
        [ref]$attachParams,
        [IntPtr]::Zero
    )
    
    if ($result -ne 0) {
        throw "AttachVirtualDisk failed with error: $result (0x$($result.ToString('X8')))"
    }
    
    # Get the physical path (e.g., \\.\PhysicalDrive2)
    $pathSize = 520
    $pathBuilder = New-Object System.Text.StringBuilder -ArgumentList $pathSize
    $result = [VirtDisk]::GetVirtualDiskPhysicalPath($Handle, [ref]$pathSize, $pathBuilder)
    
    if ($result -ne 0) {
        throw "GetVirtualDiskPhysicalPath failed with error: $result"
    }
    
    return $pathBuilder.ToString()
}

function Dismount-RawVHDX {
    param(
        [Parameter(Mandatory)]
        [IntPtr]$Handle
    )
    
    Write-Host "Detaching VHDX..." -ForegroundColor Cyan
    $result = [VirtDisk]::DetachVirtualDisk($Handle, 0, 0)
    if ($result -ne 0) {
        Write-Warning "DetachVirtualDisk returned: $result"
    }
    [VirtDisk]::CloseHandle($Handle) | Out-Null
}

# ============================================================
# Part 4: Raw Disk I/O Functions
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
    
    # Use unbuffered I/O for raw disk access
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
        throw "Failed to open $Path. Error: $err"
    }
    
    return $handle
}

function Get-DiskLength {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.SafeHandles.SafeFileHandle]$Handle
    )
    
    $lengthInfo = New-Object NativeDisk+GET_LENGTH_INFORMATION
    $bytesReturned = 0
    
    $success = [NativeDisk]::DeviceIoControl(
        $Handle,
        [NativeDisk]::IOCTL_DISK_GET_LENGTH_INFO,
        [IntPtr]::Zero,
        0,
        [ref]$lengthInfo,
        [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($lengthInfo),
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    
    if (-not $success) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to get disk length. Error: $err"
    }
    
    return $lengthInfo.Length
}

# ============================================================
# Part 5: Block Copy Function (Fixed)
# ============================================================

function Copy-VolumeBlocks {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,      # VSS device path (NO trailing backslash!)
        
        [Parameter(Mandatory)]
        [string]$DestinationPath, # Physical disk path
        
        [Parameter(Mandatory)]
        [uint64]$TotalBytes,
        
        [int]$BlockSize = 4MB     # Must be multiple of sector size (4KB for modern disks)
    )
    
    # Ensure block size is aligned to 4K sectors
    if ($BlockSize % 4096 -ne 0) {
        $BlockSize = [math]::Ceiling($BlockSize / 4096) * 4096
        Write-Warning "Block size adjusted to $BlockSize for sector alignment"
    }
    
    Write-Host "Copying $([math]::Round($TotalBytes/1GB, 2)) GB in $($BlockSize/1MB) MB blocks..." -ForegroundColor Cyan
    
    $sourceHandle = $null
    $destHandle = $null
    
    try {
        # Open source (VSS snapshot) for reading
        $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
        Write-Host "  Opened source: $SourcePath" -ForegroundColor DarkGray
        
        # Open destination (VHD physical disk) for writing
        $destHandle = Open-RawDisk -Path $DestinationPath -Access Write
        Write-Host "  Opened destination: $DestinationPath" -ForegroundColor DarkGray
        
        # Allocate aligned buffer
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [uint64]0
        $lastProgressPercent = -1
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        while ($totalCopied -lt $TotalBytes) {
            $bytesToRead = [Math]::Min($BlockSize, $TotalBytes - $totalCopied)
            
            # Round up to sector size for unbuffered I/O
            $alignedBytesToRead = [uint32]([math]::Ceiling($bytesToRead / 4096) * 4096)
            
            # Read from source
            $bytesRead = [uint32]0
            $success = [NativeDisk]::ReadFile($sourceHandle, $buffer, $alignedBytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
            
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Read failed at offset $totalCopied. Error: $err"
            }
            
            if ($bytesRead -eq 0) { 
                Write-Warning "Unexpected end of source at offset $totalCopied"
                break 
            }
            
            # Write to destination
            $bytesWritten = [uint32]0
            $success = [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)
            
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Write failed at offset $totalCopied. Error: $err"
            }
            
            $totalCopied += $bytesRead
            
            # Progress reporting (update every 1%)
            $progressPercent = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($progressPercent -gt $lastProgressPercent) {
                $elapsed = $stopwatch.Elapsed.TotalSeconds
                $speed = if ($elapsed -gt 0) { $totalCopied / $elapsed / 1MB } else { 0 }
                $remaining = if ($speed -gt 0) { ($TotalBytes - $totalCopied) / 1MB / $speed } else { 0 }
                
                Write-Progress -Activity "Cloning Volume" `
                    -Status "$progressPercent% Complete - $([math]::Round($speed, 1)) MB/s - ETA: $([math]::Round($remaining/60, 1)) min" `
                    -PercentComplete $progressPercent
                $lastProgressPercent = $progressPercent
            }
        }
        
        $stopwatch.Stop()
        Write-Progress -Activity "Cloning Volume" -Completed
        
        $avgSpeed = $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB in $([math]::Round($stopwatch.Elapsed.TotalMinutes, 1)) minutes ($([math]::Round($avgSpeed, 1)) MB/s avg)" -ForegroundColor Green
    }
    finally {
        if ($sourceHandle -and -not $sourceHandle.IsClosed) {
            $sourceHandle.Close()
        }
        if ($destHandle -and -not $destHandle.IsClosed) {
            $destHandle.Close()
        }
    }
}

# ============================================================
# Part 6: Main Clone Function
# ============================================================

function New-LiveVolumeClone {
    param(
        [Parameter(Mandatory)]
        [string]$SourceVolume,    # e.g., "C:"
        
        [Parameter(Mandatory)]
        [string]$DestinationVHDX, # e.g., "D:\Backup\Clone.vhdx"
        
        [int]$BlockSizeMB = 4     # Block size in MB (default 4MB)
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    
    try {
        # Normalize source volume
        $driveLetter = $SourceVolume.TrimEnd(':', '\')
        
        # Get partition info for accurate size
        $partition = Get-Partition -DriveLetter $driveLetter
        $partitionSize = $partition.Size
        
        Write-Host "`n=== Starting Live Volume Clone ===" -ForegroundColor Yellow
        Write-Host "Source: ${driveLetter}:" -ForegroundColor White
        Write-Host "Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "Partition Size: $([math]::Round($partitionSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "Block Size: $BlockSizeMB MB`n" -ForegroundColor White
        
        # Step 1: Create VSS Snapshot
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        # Step 2: Create VHDX (slightly larger to account for alignment)
        $vhdxSize = [math]::Ceiling($partitionSize / 1MB) * 1MB
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize
        
        # Step 3: Attach VHDX and get physical path
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle
        Write-Host "VHDX attached at: $physicalPath" -ForegroundColor Green
        
        # Wait for disk to be ready
        Start-Sleep -Seconds 3
        
        # Step 4: Copy blocks from snapshot to VHDX
        # NOTE: No trailing backslash on VSS device path for raw access!
        Copy-VolumeBlocks `
            -SourcePath $snapshot.DeviceObject `
            -DestinationPath $physicalPath `
            -TotalBytes $partitionSize `
            -BlockSize ($BlockSizeMB * 1MB)
        
        Write-Host "`n=== Clone Complete ===" -ForegroundColor Yellow
        Write-Host "VHDX saved to: $DestinationVHDX" -ForegroundColor Green
        Write-Host "You can mount this VHDX in Disk Management or Hyper-V" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Clone failed: $_"
        
        # Clean up partial VHDX on failure
        if (Test-Path $DestinationVHDX) {
            Write-Host "Cleaning up partial VHDX..." -ForegroundColor Yellow
            # Need to dismount first if attached
            if ($vhdHandle -ne [IntPtr]::Zero) {
                try { Dismount-RawVHDX -Handle $vhdHandle } catch { }
                $vhdHandle = [IntPtr]::Zero
            }
            Remove-Item $DestinationVHDX -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    finally {
        # Cleanup
        if ($vhdHandle -ne [IntPtr]::Zero) {
            Dismount-RawVHDX -Handle $vhdHandle
        }
        
        if ($snapshot) {
            Remove-VssSnapshot -ShadowId $snapshot.Id
        }
    }
}

# ============================================================
# Usage
# ============================================================

# Clone the C: drive to a VHDX file
# New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\SystemClone.vhdx" -BlockSizeMB 4
