#Requires -RunAsAdministrator

# ============================================================
# Part 1: P/Invoke Definitions
# ============================================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VirtDisk
{
    public const int VIRTUAL_STORAGE_TYPE_DEVICE_VHDX = 3;
    public const int CREATE_VIRTUAL_DISK_VERSION_2 = 2;
    public const int ATTACH_VIRTUAL_DISK_VERSION_1 = 1;
    
    public const uint VIRTUAL_DISK_ACCESS_ALL = 0x003f0000;
    
    // Flag for dynamic/sparse VHDX
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
        [Out] System.Text.StringBuilder DiskPath);
    
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
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    
    // FSCTL codes
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
        // Buffer follows - we handle this separately
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
    public static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        ref STARTING_LCN_INPUT_BUFFER lpInBuffer,
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
# Part 2: VSS Functions
# ============================================================

function New-VssSnapshot {
    param(
        [Parameter(Mandatory)]
        [string]$Volume
    )
    
    if (-not $Volume.EndsWith("\")) { $Volume += "\" }
    
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
        Volume = $Volume
        Context = "ClientAccessible"
    }
    
    if ($result.ReturnValue -ne 0) {
        throw "Failed to create shadow copy. Error code: $($result.ReturnValue)"
    }
    
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
        [uint64]$SizeBytes,
        
        [switch]$FixedSize
    )
    
    $typeStr = if ($FixedSize) { "Fixed" } else { "Dynamic" }
    Write-Host "Creating $typeStr VHDX: $Path ($([math]::Round($SizeBytes/1GB, 2)) GB)..." -ForegroundColor Cyan
    
    $storageType = New-Object VirtDisk+VIRTUAL_STORAGE_TYPE
    $storageType.DeviceId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_DEVICE_VHDX
    $storageType.VendorId = [VirtDisk]::VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT
    
    $params = New-Object VirtDisk+CREATE_VIRTUAL_DISK_PARAMETERS
    $params.Version = 2
    $params.MaximumSize = $SizeBytes
    $params.BlockSizeInBytes = 0
    $params.SectorSizeInBytes = 512
    $params.PhysicalSectorSizeInBytes = 4096
    $params.UniqueId = [Guid]::NewGuid()
    
    $flags = if ($FixedSize) { 
        [VirtDisk]::CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION 
    } else { 
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
    $attachParams.Version = 1
    
    $result = [VirtDisk]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        1,   # NO_DRIVE_LETTER
        0,
        [ref]$attachParams,
        [IntPtr]::Zero
    )
    
    if ($result -ne 0) {
        throw "AttachVirtualDisk failed with error: $result (0x$($result.ToString('X8')))"
    }
    
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
    [VirtDisk]::DetachVirtualDisk($Handle, 0, 0) | Out-Null
    [VirtDisk]::CloseHandle($Handle) | Out-Null
}

# ============================================================
# Part 4: Volume Bitmap Functions (Skip Free Space)
# ============================================================

function Get-NtfsVolumeData {
    param(
        [Parameter(Mandatory)]
        [string]$DriveLetter
    )
    
    $volumePath = "\\.\${DriveLetter}:"
    
    $handle = [NativeDisk]::CreateFile(
        $volumePath,
        [NativeDisk]::GENERIC_READ,
        [NativeDisk]::FILE_SHARE_READ -bor [NativeDisk]::FILE_SHARE_WRITE,
        [IntPtr]::Zero,
        [NativeDisk]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume $volumePath. Error: $err"
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
                $bufferSize,
                [ref]$bytesReturned,
                [IntPtr]::Zero
            )
            
            if (-not $success) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "FSCTL_GET_NTFS_VOLUME_DATA failed. Error: $err"
            }
            
            $volumeData = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $buffer, 
                [type][NativeDisk+NTFS_VOLUME_DATA_BUFFER]
            )
            
            return @{
                TotalClusters = $volumeData.TotalClusters
                FreeClusters = $volumeData.FreeClusters
                BytesPerCluster = $volumeData.BytesPerCluster
                BytesPerSector = $volumeData.BytesPerSector
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
    
    $volumePath = "\\.\${DriveLetter}:"
    
    $handle = [NativeDisk]::CreateFile(
        $volumePath,
        [NativeDisk]::GENERIC_READ,
        [NativeDisk]::FILE_SHARE_READ -bor [NativeDisk]::FILE_SHARE_WRITE,
        [IntPtr]::Zero,
        [NativeDisk]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )
    
    if ($handle.IsInvalid) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Failed to open volume. Error: $err"
    }
    
    try {
        # Calculate bitmap size (1 bit per cluster, round up to bytes)
        $bitmapBytes = [long][math]::Ceiling($TotalClusters / 8.0)
        $fullBitmap = New-Object byte[] $bitmapBytes
        
        $startingLcn = [long]0
        $headerSize = 16  # Size of StartingLcn (8) + BitmapSize (8)
        $chunkSize = 1MB  # Read bitmap in chunks
        $outputBuffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($chunkSize)
        $bitmapOffset = 0
        
        try {
            while ($startingLcn -lt $TotalClusters) {
                $inputBuffer = New-Object NativeDisk+STARTING_LCN_INPUT_BUFFER
                $inputBuffer.StartingLcn = $startingLcn
                
                $bytesReturned = [uint32]0
                $success = [NativeDisk]::DeviceIoControl(
                    $handle,
                    [NativeDisk]::FSCTL_GET_VOLUME_BITMAP,
                    [ref]$inputBuffer,
                    [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($inputBuffer),
                    $outputBuffer,
                    [uint32]$chunkSize,
                    [ref]$bytesReturned,
                    [IntPtr]::Zero
                )
                
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    # ERROR_MORE_DATA (234) is expected - we're reading in chunks
                    if ($err -ne 234) {
                        throw "FSCTL_GET_VOLUME_BITMAP failed. Error: $err"
                    }
                }
                
                # Parse header
                $returnedStartLcn = [System.Runtime.InteropServices.Marshal]::ReadInt64($outputBuffer, 0)
                $bitmapSize = [System.Runtime.InteropServices.Marshal]::ReadInt64($outputBuffer, 8)
                
                # Copy bitmap data
                $dataBytes = [int]($bytesReturned - $headerSize)
                if ($dataBytes -gt 0 -and ($bitmapOffset + $dataBytes) -le $fullBitmap.Length) {
                    [System.Runtime.InteropServices.Marshal]::Copy(
                        [IntPtr]::Add($outputBuffer, $headerSize),
                        $fullBitmap,
                        $bitmapOffset,
                        $dataBytes
                    )
                    $bitmapOffset += $dataBytes
                }
                
                # Move to next chunk (each byte represents 8 clusters)
                $clustersRead = $dataBytes * 8
                $startingLcn += $clustersRead
                
                # Progress
                $pct = [math]::Min(100, [int](($startingLcn / $TotalClusters) * 100))
                Write-Progress -Activity "Reading Bitmap" -Status "$pct%" -PercentComplete $pct
            }
            
            Write-Progress -Activity "Reading Bitmap" -Completed
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outputBuffer)
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
        
        [int]$MinRunClusters = 256  # Merge runs closer than this (1MB with 4K clusters)
    )
    
    Write-Host "Analyzing allocation bitmap..." -ForegroundColor Cyan
    
    $ranges = [System.Collections.Generic.List[PSCustomObject]]::new()
    $currentStart = -1
    $allocatedClusters = [long]0
    
    for ($cluster = 0; $cluster -lt $TotalClusters; $cluster++) {
        $byteIndex = [math]::Floor($cluster / 8)
        $bitIndex = $cluster % 8
        
        $isAllocated = ($Bitmap[$byteIndex] -band (1 -shl $bitIndex)) -ne 0
        
        if ($isAllocated) {
            if ($currentStart -eq -1) {
                $currentStart = $cluster
            }
            $allocatedClusters++
        }
        else {
            if ($currentStart -ne -1) {
                $ranges.Add([PSCustomObject]@{
                    StartCluster = $currentStart
                    EndCluster = $cluster - 1
                    ClusterCount = $cluster - $currentStart
                })
                $currentStart = -1
            }
        }
        
        # Progress every 1%
        if ($cluster % [math]::Max(1, [int]($TotalClusters / 100)) -eq 0) {
            $pct = [int](($cluster / $TotalClusters) * 100)
            Write-Progress -Activity "Analyzing Bitmap" -Status "$pct%" -PercentComplete $pct
        }
    }
    
    # Handle final range
    if ($currentStart -ne -1) {
        $ranges.Add([PSCustomObject]@{
            StartCluster = $currentStart
            EndCluster = $TotalClusters - 1
            ClusterCount = $TotalClusters - $currentStart
        })
    }
    
    Write-Progress -Activity "Analyzing Bitmap" -Completed
    
    # Merge nearby ranges to reduce I/O operations
    Write-Host "Merging adjacent ranges (threshold: $MinRunClusters clusters)..." -ForegroundColor Cyan
    $mergedRanges = [System.Collections.Generic.List[PSCustomObject]]::new()
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
                EndCluster = $range.EndCluster
                ClusterCount = $range.EndCluster - $prev.StartCluster + 1
            }
        }
        else {
            $mergedRanges.Add($prev)
            $prev = $range
        }
    }
    if ($null -ne $prev) {
        $mergedRanges.Add($prev)
    }
    
    $totalBytes = $TotalClusters * $BytesPerCluster
    $allocatedBytes = $allocatedClusters * $BytesPerCluster
    $savingsPercent = [math]::Round((1 - ($allocatedBytes / $totalBytes)) * 100, 1)
    
    Write-Host "  Total clusters: $TotalClusters ($([math]::Round($totalBytes/1GB, 2)) GB)" -ForegroundColor DarkGray
    Write-Host "  Allocated clusters: $allocatedClusters ($([math]::Round($allocatedBytes/1GB, 2)) GB)" -ForegroundColor DarkGray
    Write-Host "  Ranges before merge: $($ranges.Count)" -ForegroundColor DarkGray
    Write-Host "  Ranges after merge: $($mergedRanges.Count)" -ForegroundColor DarkGray
    Write-Host "  Space savings: $savingsPercent%" -ForegroundColor Green
    
    return @{
        Ranges = $mergedRanges
        AllocatedClusters = $allocatedClusters
        AllocatedBytes = $allocatedBytes
    }
}

# ============================================================
# Part 5: Raw Disk I/O
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
        throw "Failed to open $Path. Error: $err"
    }
    
    return $handle
}

# ============================================================
# Part 6: Sparse Block Copy (Skip Free Space)
# ============================================================

function Copy-AllocatedBlocks {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[PSCustomObject]]$Ranges,
        
        [Parameter(Mandatory)]
        [uint32]$BytesPerCluster,
        
        [Parameter(Mandatory)]
        [long]$AllocatedBytes,
        
        [int]$BlockSize = 4MB
    )
    
    # Ensure block size is cluster-aligned
    if ($BlockSize % $BytesPerCluster -ne 0) {
        $BlockSize = [int]([math]::Ceiling($BlockSize / $BytesPerCluster) * $BytesPerCluster)
    }
    
    $clustersPerBlock = $BlockSize / $BytesPerCluster
    
    Write-Host "Copying $([math]::Round($AllocatedBytes/1GB, 2)) GB of allocated data..." -ForegroundColor Cyan
    Write-Host "  Block size: $($BlockSize/1MB) MB ($clustersPerBlock clusters)" -ForegroundColor DarkGray
    
    $sourceHandle = $null
    $destHandle = $null
    
    try {
        $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
        $destHandle = Open-RawDisk -Path $DestinationPath -Access Write
        
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [long]0
        $rangeIndex = 0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastProgressPercent = -1
        
        foreach ($range in $Ranges) {
            $rangeIndex++
            $clusterOffset = $range.StartCluster
            $clustersRemaining = $range.ClusterCount
            
            while ($clustersRemaining -gt 0) {
                $clustersToRead = [math]::Min($clustersPerBlock, $clustersRemaining)
                $bytesToRead = [uint32]($clustersToRead * $BytesPerCluster)
                $byteOffset = [long]$clusterOffset * $BytesPerCluster
                
                # Seek source
                $newPos = [long]0
                $success = [NativeDisk]::SetFilePointerEx($sourceHandle, $byteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Source seek failed. Error: $err"
                }
                
                # Read
                $bytesRead = [uint32]0
                $success = [NativeDisk]::ReadFile($sourceHandle, $buffer, $bytesToRead, [ref]$bytesRead, [IntPtr]::Zero)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Read failed at cluster $clusterOffset. Error: $err"
                }
                
                # Seek destination
                $success = [NativeDisk]::SetFilePointerEx($destHandle, $byteOffset, [ref]$newPos, [NativeDisk]::FILE_BEGIN)
                if (-not $success) {
                    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw "Destination seek failed. Error: $err"
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
                
                # Progress
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
        if ($sourceHandle -and -not $sourceHandle.IsClosed) { $sourceHandle.Close() }
        if ($destHandle -and -not $destHandle.IsClosed) { $destHandle.Close() }
    }
}

# ============================================================
# Part 7: Main Clone Function
# ============================================================

function New-LiveVolumeClone {
    param(
        [Parameter(Mandatory)]
        [string]$SourceVolume,
        
        [Parameter(Mandatory)]
        [string]$DestinationVHDX,
        
        [switch]$FullCopy,         # Skip free space optimization
        [switch]$FixedSizeVHDX,    # Create fixed instead of dynamic VHDX
        [int]$BlockSizeMB = 4
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    
    try {
        $driveLetter = $SourceVolume.TrimEnd(':', '\')
        $partition = Get-Partition -DriveLetter $driveLetter
        $partitionSize = $partition.Size
        
        Write-Host "`n=== Live Volume Clone (Skip Free Space) ===" -ForegroundColor Yellow
        Write-Host "Source: ${driveLetter}:" -ForegroundColor White
        Write-Host "Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "Partition Size: $([math]::Round($partitionSize/1GB, 2)) GB" -ForegroundColor White
        Write-Host "Mode: $(if ($FullCopy) { 'Full Copy' } else { 'Skip Free Space' })`n" -ForegroundColor White
        
        # Get volume information
        $volumeData = Get-NtfsVolumeData -DriveLetter $driveLetter
        Write-Host "Cluster size: $($volumeData.BytesPerCluster) bytes" -ForegroundColor DarkGray
        Write-Host "Total clusters: $($volumeData.TotalClusters)" -ForegroundColor DarkGray
        Write-Host "Free clusters: $($volumeData.FreeClusters)`n" -ForegroundColor DarkGray
        
        # Create VSS Snapshot
        $snapshot = New-VssSnapshot -Volume "${driveLetter}:\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        # Create VHDX
        $vhdxSize = [math]::Ceiling($partitionSize / 1MB) * 1MB
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $vhdxSize -FixedSize:$FixedSizeVHDX
        
        # Attach VHDX
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle
        Write-Host "VHDX attached at: $physicalPath`n" -ForegroundColor Green
        
        Start-Sleep -Seconds 3
        
        if ($FullCopy) {
            # Full sector-by-sector copy (original behavior)
            Copy-VolumeBlocksFull `
                -SourcePath $snapshot.DeviceObject `
                -DestinationPath $physicalPath `
                -TotalBytes $partitionSize `
                -BlockSize ($BlockSizeMB * 1MB)
        }
        else {
            # Skip free space - copy only allocated clusters
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
                -BlockSize ($BlockSizeMB * 1MB)
        }
        
        Write-Host "`n=== Clone Complete ===" -ForegroundColor Yellow
        Write-Host "VHDX saved to: $DestinationVHDX" -ForegroundColor Green
        
        $vhdxFile = Get-Item $DestinationVHDX
        Write-Host "VHDX file size: $([math]::Round($vhdxFile.Length/1GB, 2)) GB" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Clone failed: $_"
        
        if ($vhdHandle -ne [IntPtr]::Zero) {
            try { Dismount-RawVHDX -Handle $vhdHandle } catch { }
            $vhdHandle = [IntPtr]::Zero
        }
        
        if (Test-Path $DestinationVHDX) {
            Remove-Item $DestinationVHDX -Force -ErrorAction SilentlyContinue
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

# Full copy function (for -FullCopy switch)
function Copy-VolumeBlocksFull {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [uint64]$TotalBytes,
        [int]$BlockSize = 4MB
    )
    
    Write-Host "Performing full sector copy of $([math]::Round($TotalBytes/1GB, 2)) GB..." -ForegroundColor Cyan
    
    $sourceHandle = Open-RawDisk -Path $SourcePath -Access Read
    $destHandle = Open-RawDisk -Path $DestinationPath -Access Write
    
    try {
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = [uint64]0
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastPct = -1
        
        while ($totalCopied -lt $TotalBytes) {
            $bytesToRead = [uint32][Math]::Min($BlockSize, $TotalBytes - $totalCopied)
            $alignedBytes = [uint32]([math]::Ceiling($bytesToRead / 4096) * 4096)
            
            $bytesRead = [uint32]0
            if (-not [NativeDisk]::ReadFile($sourceHandle, $buffer, $alignedBytes, [ref]$bytesRead, [IntPtr]::Zero)) {
                throw "Read failed at offset $totalCopied. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            
            if ($bytesRead -eq 0) { break }
            
            $bytesWritten = [uint32]0
            if (-not [NativeDisk]::WriteFile($destHandle, $buffer, $bytesRead, [ref]$bytesWritten, [IntPtr]::Zero)) {
                throw "Write failed at offset $totalCopied. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
            }
            
            $totalCopied += $bytesRead
            
            $pct = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($pct -gt $lastPct) {
                $speed = $totalCopied / $stopwatch.Elapsed.TotalSeconds / 1MB
                Write-Progress -Activity "Full Clone" -Status "$pct% - $([math]::Round($speed,1)) MB/s" -PercentComplete $pct
                $lastPct = $pct
            }
        }
        
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
# Usage Examples
# ============================================================

<#
# Clone C: drive, skipping free space (default, fastest)
New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\SystemClone.vhdx"

# Clone with full sector copy (no optimization)
New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\FullClone.vhdx" -FullCopy

# Clone to a fixed-size VHDX
New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\Fixed.vhdx" -FixedSizeVHDX

# Clone with larger block size for faster I/O
New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\Fast.vhdx" -BlockSizeMB 16
#>
```

## Key Features Added

| Feature | Description |
|---------|-------------|
| **FSCTL_GET_VOLUME_BITMAP** | Reads NTFS allocation bitmap to identify used clusters |
| **FSCTL_GET_NTFS_VOLUME_DATA** | Gets cluster size and volume geometry |
| **Range merging** | Combines nearby allocated ranges to reduce seek operations |
| **Dynamic VHDX** | Default creates sparse VHDX that only stores written blocks |
| **Progress with ETA** | Shows speed and estimated time remaining |

## Example Output
```
=== Live Volume Clone (Skip Free Space) ===
Source: C:
Destination: D:\Backups\SystemClone.vhdx
Partition Size: 237.5 GB
Mode: Skip Free Space

Cluster size: 4096 bytes
Total clusters: 62256127
Free clusters: 41502845

Creating VSS snapshot for C:\...
Snapshot created: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
Creating Dynamic VHDX: D:\Backups\SystemClone.vhdx (237.5 GB)...
VHDX attached at: \\.\PhysicalDrive2

Reading volume allocation bitmap...
Analyzing allocation bitmap...
  Total clusters: 62256127 (237.5 GB)
  Allocated clusters: 20753282 (79.2 GB)
  Ranges before merge: 847291
  Ranges after merge: 12847
  Space savings: 66.7%

Copying 79.2 GB of allocated data...
  Block size: 4 MB (1024 clusters)
Copied 79.2 GB in 8.3 min (159.4 MB/s)

=== Clone Complete ===
VHDX saved to: D:\Backups\SystemClone.vhdx
VHDX file size: 79.8 GB
