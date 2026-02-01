#Requires -RunAsAdministrator

# ============================================================
# Part 1: Virtual Disk P/Invoke Definitions
# ============================================================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

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
"@

# ============================================================
# Part 2: VSS Functions using WMI/COM
# ============================================================

function New-VssSnapshot {
    param(
        [Parameter(Mandatory)]
        [string]$Volume  # e.g., "C:\"
    )
    
    # Normalize volume path
    if (-not $Volume.EndsWith("\")) { $Volume += "\" }
    
    Write-Host "Creating VSS snapshot for $Volume..." -ForegroundColor Cyan
    
    # Use WMI to create shadow copy
    $shadowClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
    $result = $shadowClass.Create($Volume, "ClientAccessible")
    
    if ($result.ReturnValue -ne 0) {
        throw "Failed to create shadow copy. Error code: $($result.ReturnValue)"
    }
    
    # Get the shadow copy object
    $shadowCopy = Get-WmiObject Win32_ShadowCopy | 
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
    $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $ShadowId }
    if ($shadow) {
        $shadow.Delete()
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
    $params.BlockSizeInBytes = 0
    $params.SectorSizeInBytes = 512
    $params.UniqueId = [Guid]::NewGuid()
    
    $handle = [IntPtr]::Zero
    $result = [VirtDisk]::CreateVirtualDisk(
        [ref]$storageType,
        $Path,
        [VirtDisk]::VIRTUAL_DISK_ACCESS_ALL,
        [IntPtr]::Zero,
        0,
        0,
        [ref]$params,
        [IntPtr]::Zero,
        [ref]$handle
    )
    
    if ($result -ne 0) {
        throw "CreateVirtualDisk failed with error: $result"
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
    
    # Flag 1 = ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER (raw access)
    $result = [VirtDisk]::AttachVirtualDisk(
        $Handle,
        [IntPtr]::Zero,
        1,  
        0,
        [ref]$attachParams,
        [IntPtr]::Zero
    )
    
    if ($result -ne 0) {
        throw "AttachVirtualDisk failed with error: $result"
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
    [VirtDisk]::DetachVirtualDisk($Handle, 0, 0) | Out-Null
    [VirtDisk]::CloseHandle($Handle) | Out-Null
}

# ============================================================
# Part 4: Block Copy Function
# ============================================================

function Copy-VolumeBlocks {
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,      # VSS device path
        
        [Parameter(Mandatory)]
        [string]$DestinationPath, # Physical disk path
        
        [Parameter(Mandatory)]
        [uint64]$TotalBytes,
        
        [int]$BlockSize = 1MB
    )
    
    Write-Host "Copying $([math]::Round($TotalBytes/1GB, 2)) GB..." -ForegroundColor Cyan
    
    # Open source (VSS snapshot) for reading
    $sourceStream = [System.IO.File]::Open(
        $SourcePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    
    # Open destination (VHD physical disk) for writing
    $destStream = [System.IO.File]::Open(
        $DestinationPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    
    try {
        $buffer = New-Object byte[] $BlockSize
        $totalCopied = 0
        $lastProgress = 0
        
        while ($totalCopied -lt $TotalBytes) {
            $bytesToRead = [Math]::Min($BlockSize, $TotalBytes - $totalCopied)
            $bytesRead = $sourceStream.Read($buffer, 0, $bytesToRead)
            
            if ($bytesRead -eq 0) { break }
            
            $destStream.Write($buffer, 0, $bytesRead)
            $totalCopied += $bytesRead
            
            # Progress reporting
            $progress = [math]::Floor(($totalCopied / $TotalBytes) * 100)
            if ($progress -gt $lastProgress) {
                Write-Progress -Activity "Cloning Volume" `
                    -Status "$progress% Complete" `
                    -PercentComplete $progress
                $lastProgress = $progress
            }
        }
        
        Write-Progress -Activity "Cloning Volume" -Completed
        Write-Host "Copied $([math]::Round($totalCopied/1GB, 2)) GB successfully." -ForegroundColor Green
    }
    finally {
        $sourceStream.Close()
        $destStream.Close()
    }
}

# ============================================================
# Part 5: Main Clone Function
# ============================================================

function New-LiveVolumeClone {
    param(
        [Parameter(Mandatory)]
        [string]$SourceVolume,    # e.g., "C:"
        
        [Parameter(Mandatory)]
        [string]$DestinationVHDX  # e.g., "D:\Backup\Clone.vhdx"
    )
    
    $vhdHandle = [IntPtr]::Zero
    $snapshot = $null
    
    try {
        # Get volume size
        $volume = Get-Volume -DriveLetter $SourceVolume.TrimEnd(':')
        $volumeSize = $volume.Size
        
        Write-Host "`n=== Starting Live Volume Clone ===" -ForegroundColor Yellow
        Write-Host "Source: $SourceVolume" -ForegroundColor White
        Write-Host "Destination: $DestinationVHDX" -ForegroundColor White
        Write-Host "Size: $([math]::Round($volumeSize/1GB, 2)) GB`n" -ForegroundColor White
        
        # Step 1: Create VSS Snapshot
        $snapshot = New-VssSnapshot -Volume "$SourceVolume\"
        Write-Host "Snapshot created: $($snapshot.DeviceObject)" -ForegroundColor Green
        
        # Step 2: Create VHDX
        $vhdHandle = New-RawVHDX -Path $DestinationVHDX -SizeBytes $volumeSize
        
        # Step 3: Attach VHDX and get physical path
        $physicalPath = Mount-RawVHDX -Handle $vhdHandle
        Write-Host "VHDX attached at: $physicalPath" -ForegroundColor Green
        
        # Small delay for disk to be ready
        Start-Sleep -Seconds 2
        
        # Step 4: Copy blocks from snapshot to VHDX
        Copy-VolumeBlocks `
            -SourcePath "$($snapshot.DeviceObject)\" `
            -DestinationPath $physicalPath `
            -TotalBytes $volumeSize
        
        Write-Host "`n=== Clone Complete ===" -ForegroundColor Yellow
        Write-Host "VHDX saved to: $DestinationVHDX" -ForegroundColor Green
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
# Usage Example
# ============================================================

# Clone the C: drive to a VHDX file
# New-LiveVolumeClone -SourceVolume "C:" -DestinationVHDX "D:\Backups\SystemClone.vhdx"
