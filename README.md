# BootableVolumeClone

Clone a live Windows volume to a bootable VHDX file — while Windows is running.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%7C%20Server-0078D6.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Live Cloning** — Clone your running Windows system without rebooting
- **Smart Copy** — Only copies allocated clusters, dramatically reducing time and file size
- **No Dependencies** — Uses native Windows APIs (virtdisk.dll), no Hyper-V module required
- **Bootable Output** — Creates fully bootable VHDX files with proper boot configuration
- **Dual Boot Mode Support** — UEFI (GPT) and BIOS (MBR) compatible
- **Interactive & Scripted** — Menu-driven interface or command-line automation
- **Progress Tracking** — Real-time speed and progress monitoring

## How It Works

```
┌─────────────────┐     ┌─────────────┐     ┌─────────────────┐
│  Source Volume  │────▶│ VSS Snapshot │────▶│  Read Bitmap    │
│    (Live C:)    │     │  (Frozen)    │     │  (Find Used)    │
└─────────────────┘     └─────────────┘     └────────┬────────┘
                                                     │
┌─────────────────┐     ┌─────────────┐     ┌────────▼────────┐
│ Bootable VHDX   │◀────│  Install    │◀────│   Smart Copy    │
│   (Ready!)      │     │  Boot Files │     │ (Allocated Only)│
└─────────────────┘     └─────────────┘     └─────────────────┘
```

1. **VSS Snapshot** — Creates a consistent point-in-time snapshot of the live volume
2. **VHDX Creation** — Creates a new VHDX using Windows virtdisk.dll API
3. **Partition Setup** — Initializes disk with proper boot partitions (ESP/MSR for UEFI, System Reserved for BIOS)
4. **Smart Copy** — Reads NTFS bitmap to identify allocated clusters and copies only used data
5. **Boot Configuration** — Runs `bcdboot` to install Windows boot files

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- Administrator privileges
- VSS service running (default on Windows)

**Not Required:**
- Hyper-V role or module
- Third-party tools
- Reboot

## Installation

Download the script directly:

```powershell
# Download to current directory
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mr-r3b00t/clone_disk_to_vhd/main/Clone.ps1" -OutFile "Clone.ps1"
```

Or clone the repository:

```bash
git clone https://github.com/mr-r3b00t/clone_disk_to_vhd.git
```

## Usage

### Interactive Mode

Simply run the script without parameters for a menu-driven experience:

```powershell
.\Clone.ps1
```

### Command Line Mode

```powershell
.\Clone.ps1 -SourceVolume "C" -DestinationVHDX "D:\Backup\MyClone.vhdx"
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SourceVolume` | String | — | Drive letter to clone (e.g., `"C"` or `"C:"`) |
| `-DestinationVHDX` | String | — | Full path for output VHDX file |
| `-BootMode` | String | `"UEFI"` | Boot mode: `"UEFI"` (GPT) or `"BIOS"` (MBR) |
| `-FullCopy` | Switch | `$false` | Copy all sectors instead of allocated only |
| `-FixedSizeVHDX` | Switch | `$false` | Create fixed-size instead of dynamic VHDX |
| `-BlockSizeMB` | Int | `4` | Copy block size in MB (1-64) |
| `-SkipBootFix` | Switch | `$false` | Skip boot file installation |

## Examples

### Basic Clone (Smart Copy, Dynamic VHDX, UEFI)

```powershell
.\Clone.ps1 -SourceVolume "C" -DestinationVHDX "E:\VMs\Windows_Clone.vhdx"
```

### Full Sector Copy

```powershell
.\Clone.ps1 -SourceVolume "C" -DestinationVHDX "E:\VMs\Full_Clone.vhdx" -FullCopy
```

### BIOS/MBR Boot Mode

```powershell
.\Clone.ps1 -SourceVolume "C" -DestinationVHDX "E:\VMs\BIOS_Clone.vhdx" -BootMode "BIOS"
```

### Fixed-Size VHDX with Larger Block Size

```powershell
.\Clone.ps1 -SourceVolume "C" -DestinationVHDX "E:\VMs\Fixed_Clone.vhdx" -FixedSizeVHDX -BlockSizeMB 16
```

### Clone Secondary Drive (Data Only, No Boot Files)

```powershell
.\Clone.ps1 -SourceVolume "D" -DestinationVHDX "E:\VMs\Data_Clone.vhdx" -SkipBootFix
```

## Output

```
╔═══════════════════════════════════════════════════════════════════╗
║                    BOOTABLE VOLUME CLONE                          ║
╚═══════════════════════════════════════════════════════════════════╝

  Source:      C:
  Destination: D:\VMs\Clone.vhdx
  Used Space:  118.13 GB
  VHDX Size:   953.42 GB (virtual)
  Disk Needed: ~125 GB
  Boot Mode:   UEFI
  Copy Mode:   Smart (allocated blocks only)

Creating VSS snapshot for C:\...
  Snapshot created: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
Creating Dynamic VHDX: D:\VMs\Clone.vhdx (953.42 GB)...
  VHDX created successfully
Attaching VHDX...
  VHDX attached at: \\.\PhysicalDrive1
Initializing disk structure for UEFI boot...
  Allocated: 118.13 GB of 953.03 GB in 797 ranges
Copying 118.13 GB of allocated data...
Copied 118.28 GB in 1.7 min (1170.3 MB/s)
Installing boot files...
  Boot files installed successfully

╔═══════════════════════════════════════════════════════════════════╗
║                    CLONE COMPLETED SUCCESSFULLY                   ║
╚═══════════════════════════════════════════════════════════════════╝

  VHDX File: D:\VMs\Clone.vhdx
  File Size: 125.44 GB
```

## Using the Clone

### Boot in Hyper-V

1. Create a new Hyper-V VM (Generation 2 for UEFI, Generation 1 for BIOS)
2. Attach the VHDX as the primary hard drive
3. Start the VM

### Native VHD Boot

Add the VHDX to Windows boot menu:

```powershell
bcdedit /copy "{current}" /d "Windows Clone"
bcdedit /set "{NEW-GUID}" device vhd="[D:]\VMs\Clone.vhdx"
bcdedit /set "{NEW-GUID}" osdevice vhd="[D:]\VMs\Clone.vhdx"
```

### Mount for File Access

```powershell
Mount-VHD -Path "D:\VMs\Clone.vhdx"
# Access via assigned drive letter
Dismount-VHD -Path "D:\VMs\Clone.vhdx"
```

## BitLocker Considerations

| Scenario | Result |
|----------|--------|
| Cloning unlocked BitLocker volume (e.g., running C:) | ✅ Works — clone is **unencrypted** |
| Cloning locked BitLocker volume | ❌ Fails — encrypted data is unreadable |

When you clone a running BitLocker-encrypted system drive, Windows transparently decrypts the data during reading. The resulting VHDX contains **unencrypted data**.

**To secure the clone:**
- Store the VHDX on a BitLocker-encrypted drive
- Or boot the clone in a VM and enable BitLocker on it

## Smart Copy vs Full Copy

| Mode | Copies | Speed | VHDX Size | Use Case |
|------|--------|-------|-----------|----------|
| **Smart** (default) | Allocated clusters only | Fast | Smaller | Most scenarios |
| **Full** | All sectors | Slower | Larger | Non-NTFS, forensics, disk recovery |

**Example:** A 1 TB partition with 100 GB used:
- Smart Copy: ~100 GB copied, ~105 GB VHDX
- Full Copy: ~1 TB copied, ~1 TB VHDX

## Troubleshooting

### "PtrToStructure" Error

```
Exception calling "PtrToStructure" with "2" argument(s): "The specified structure 
must be blittable or have layout information."
```

**Solution:** Close PowerShell completely and open a new window. This error occurs when .NET types are cached from a previous script run with different definitions.

### "Insufficient Space" Error

The script calculates required space based on:
- **Dynamic VHDX + Smart Copy:** Used space + boot partitions + 5% overhead
- **Fixed VHDX or Full Copy:** Full partition size + boot partitions

Ensure destination drive has adequate free space.

### VSS Snapshot Fails

Common causes:
- VSS service not running: `Start-Service VSS`
- Insufficient disk space for shadow copy
- Volume not supported (some USB drives)

### Boot Files Installation Fails

If `bcdboot` fails:
1. Ensure Windows folder exists on the source volume
2. Try running with `-SkipBootFix` and manually run bcdboot afterward
3. Check that EFI System Partition was created correctly

## Technical Details

### Partition Layout

**UEFI (GPT):**
| Partition | Size | Type |
|-----------|------|------|
| EFI System | 260 MB | FAT32 |
| Microsoft Reserved | 16 MB | — |
| Windows | Remaining | NTFS (raw copy) |

**BIOS (MBR):**
| Partition | Size | Type |
|-----------|------|------|
| System Reserved | 500 MB | NTFS |
| Windows | Remaining | NTFS (raw copy) |

### APIs Used

- **virtdisk.dll** — CreateVirtualDisk, AttachVirtualDisk, DetachVirtualDisk
- **kernel32.dll** — CreateFile, DeviceIoControl, ReadFile, WriteFile
- **FSCTL_GET_NTFS_VOLUME_DATA** — Retrieve cluster size and count
- **FSCTL_GET_VOLUME_BITMAP** — Get allocation bitmap
- **Win32_ShadowCopy** — VSS snapshot management

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- Microsoft for the Windows Virtual Disk and VSS APIs
- The PowerShell community for P/Invoke patterns
