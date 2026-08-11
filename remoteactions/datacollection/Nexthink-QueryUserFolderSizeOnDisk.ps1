<#
.SYNOPSIS
    Collects folder and file size metrics for a given path and reports them to Nexthink.

.DESCRIPTION
    Resolves supported path variables, optionally waits a random delay, then computes:
    - Total directory count (recursive, excluding root directories matched by input)
    - Total file count
    - Total logical size (bytes)
    - Total size on disk (bytes, compressed-size aware)
    - Capacity of the Windows system drive

    Filesystem scans stop after an internal 300-second limit. Reparse-point directories
    are counted but not traversed, preventing junction loops and scope escapes. Any
    inaccessible directory or timeout fails the action rather than returning incomplete
    metrics as authoritative results.

.PARAMETER InputPath
    Full path or wildcard path to measure. Supports:
    - %HOMEPATH%
    - %HOMEDRIVE%
    - $env:USERPROFILE (as literal text in parameter value)

.PARAMETER MaximumDelayInSeconds
    Maximum random startup delay (0..600). Use to spread load in shared environments.

.OUTPUTS
    [UInt32] TotalDirectories
    [UInt32] TotalFiles
    [Size]   TotalSize
    [Size]   TotalSizeOnDisk
    [Size]   TotalCapacityWinDrive
    [Size]   SyncedSizeOnDisk

.NOTES
    ==========================================================================
    Organization:   synit.io
    Pwsh:           Windows PowerShell 5.1+
    Compatibility:  Designed to be backwards-compatible with Windows PowerShell 5.1.
    Dependencies:   Requires $env:NEXTHINK\RemoteActions\nxtremoteactions.dll.
    ==========================================================================
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Folder or file path to measure. Wildcards are supported.')]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [Parameter(Mandatory = $false, HelpMessage = 'Maximum random delay in seconds before collection starts. Valid range: 0..600.')]
    [ValidateRange(0, 600)]
    [int]$MaximumDelayInSeconds = 0
)

$ErrorActionPreference = 'Stop'
$exitCode = 0
$maximumScanSeconds = 300
$script:sizeOnDiskWarningCount = 0
$script:sizeOnDiskWarningsSuppressed = $false

function Add-NexthinkRemoteActionAssembly {
    if ([string]::IsNullOrWhiteSpace($env:NEXTHINK)) {
        throw 'NEXTHINK environment variable is not defined.'
    }

    $dllPath = Join-Path -Path $env:NEXTHINK -ChildPath 'RemoteActions\nxtremoteactions.dll'
    if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) {
        throw "Nexthink Remote Action DLL not found at '$dllPath'."
    }

    Add-Type -LiteralPath $dllPath
}

function Add-SizeOnDiskInteropType {
    if ($null -ne ('Nexthink.Interop.FileSizeOnDisk' -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Nexthink.Interop
{
    public static class FileSizeOnDisk
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

        public static ulong GetSize(string filePath)
        {
            uint high;
            uint low = GetCompressedFileSizeW(filePath, out high);
            int error = Marshal.GetLastWin32Error();

            if (low == 0xFFFFFFFF && error != 0)
            {
                throw new Win32Exception(error);
            }

            return ((ulong)high << 32) + low;
        }
    }
}
'@
}

function Resolve-InputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolvedPath = $Path
    $variables = @(
        @{ Token = '%HOMEDRIVE%'; Value = $env:HOMEDRIVE },
        @{ Token = '%HOMEPATH%'; Value = $env:HOMEPATH },
        @{ Token = '$env:USERPROFILE'; Value = $env:USERPROFILE }
    )

    foreach ($variable in $variables) {
        if ($resolvedPath.Contains($variable.Token)) {
            if ([string]::IsNullOrWhiteSpace($variable.Value)) {
                throw "Cannot resolve '$($variable.Token)' because its environment variable is not defined."
            }

            $resolvedPath = $resolvedPath.Replace($variable.Token, $variable.Value)
        }
    }

    return $resolvedPath
}

function Convert-ToWin32ExtendedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($Path.StartsWith('\\?\')) {
        return $Path
    }

    if ($Path.StartsWith('\\')) {
        return "\\?\UNC\$($Path.TrimStart('\\'))"
    }

    return "\\?\$Path"
}

function Convert-ToUInt32Safe {
    param(
        [Parameter(Mandatory = $true)]
        [long]$Value
    )

    if ($Value -lt 0) { return [uint32]0 }
    if ($Value -gt [uint32]::MaxValue) { return [uint32]::MaxValue }
    return [uint32]$Value
}

function Convert-ToNexthinkSize {
    param(
        [Parameter(Mandatory = $true)]
        [double]$Value
    )

    if ([double]::IsNaN($Value) -or [double]::IsInfinity($Value) -or $Value -lt 0) {
        throw "Size value '$Value' is outside the supported Nexthink range."
    }

    if ($Value -gt [float]::MaxValue) {
        return [float]::MaxValue
    }

    return [float]$Value
}

function Get-WindowsDriveCapacity {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 30
    if ($null -eq $os -or [string]::IsNullOrWhiteSpace($os.SystemDrive)) {
        throw 'Unable to determine Windows system drive.'
    }

    $systemDrive = $os.SystemDrive
    $volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -OperationTimeoutSec 30
    if ($null -eq $volume) {
        throw "Unable to query capacity for system drive '$systemDrive'."
    }

    return [double]$volume.Size
}

function Get-FileSizeOnDiskSafe {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    try {
        $extendedPath = Convert-ToWin32ExtendedPath -Path $File.FullName
        return [double][Nexthink.Interop.FileSizeOnDisk]::GetSize($extendedPath)
    } catch {
        if ($script:sizeOnDiskWarningCount -lt 10) {
            Write-Warning "Failed to query size-on-disk for '$($File.FullName)'. Falling back to logical size. $($_.Exception.Message)"
            $script:sizeOnDiskWarningCount++
        } else {
            $script:sizeOnDiskWarningsSuppressed = $true
        }

        return [double]$File.Length
    }
}

function Add-DirectoryFileSizeMetric {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [Parameter(Mandatory = $true)]
        [hashtable]$Metrics,
        [Parameter(Mandatory = $true)]
        [DateTime]$DeadlineUtc
    )

    $pendingDirectories = New-Object System.Collections.Stack
    $pendingDirectories.Push($RootPath)

    while ($pendingDirectories.Count -gt 0) {
        if ([DateTime]::UtcNow -ge $DeadlineUtc) {
            throw "Filesystem scan exceeded the internal $script:maximumScanSeconds-second limit."
        }

        $currentPath = [string]$pendingDirectories.Pop()
        $enumerator = $null
        try {
            $directory = New-Object System.IO.DirectoryInfo -ArgumentList $currentPath
            $enumerator = $directory.EnumerateFileSystemInfos().GetEnumerator()

            while ($true) {
                if ([DateTime]::UtcNow -ge $DeadlineUtc) {
                    throw "Filesystem scan exceeded the internal $script:maximumScanSeconds-second limit."
                }

                $hasNextItem = $enumerator.MoveNext()
                if (-not $hasNextItem) {
                    break
                }

                $item = $enumerator.Current
                if ($item -is [System.IO.DirectoryInfo]) {
                    $Metrics.TotalDirectories++
                    $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
                    if (-not $isReparsePoint) {
                        $pendingDirectories.Push($item.FullName)
                    }
                    continue
                }

                $Metrics.TotalFiles++
                $Metrics.TotalSize += [double]$item.Length
                $Metrics.TotalSizeOnDisk += Get-FileSizeOnDiskSafe -File $item
            }
        } catch {
            throw "Failed while scanning directory '$currentPath': $($_.Exception.Message)"
        } finally {
            if ($null -ne $enumerator) {
                $enumerator.Dispose()
            }
        }
    }
}

function Get-SizeMetric {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [DateTime]$DeadlineUtc
    )

    $result = @{
        TotalDirectories = [int64]0
        TotalFiles = [int64]0
        TotalSize = [double]0
        TotalSizeOnDisk = [double]0
    }

    Get-Item -Path $Path -Force -ErrorAction Stop | ForEach-Object {
        $root = $_
        if ($root.PSProvider.Name -ne 'FileSystem') {
            throw "Path '$($root.PSPath)' is not a filesystem path."
        }

        if ($root -is [System.IO.FileInfo]) {
            $result.TotalFiles++
            $result.TotalSize += [double]$root.Length
            $result.TotalSizeOnDisk += Get-FileSizeOnDiskSafe -File $root
        } elseif ($root -is [System.IO.DirectoryInfo]) {
            Add-DirectoryFileSizeMetric -RootPath $root.FullName -Metrics $result -DeadlineUtc $DeadlineUtc
        } else {
            throw "Path '$($root.PSPath)' is not a file or directory."
        }
    }

    return $result
}

function Get-SyncFolderRoot {
    $candidates = New-Object System.Collections.Generic.List[string]

    foreach ($value in @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer)) {
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            $candidates.Add($value)
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE) -and (Test-Path -LiteralPath $env:USERPROFILE -PathType Container)) {
        Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dir = $_
            if ($dir.Name -like 'OneDrive*' -or $dir.Name -like 'Nextcloud*' -or $dir.Name -like 'Google Drive*' -or $dir.Name -like 'GoogleDrive*') {
                $candidates.Add($dir.FullName)
            }
        }

        $explicitNextcloud = Join-Path -Path $env:USERPROFILE -ChildPath 'Nextcloud'
        $candidates.Add($explicitNextcloud)
    }

    $existing = New-Object System.Collections.Generic.List[string]
    $pathMap = @{}

    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $candidate -PathType Container -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $full = (Get-Item -LiteralPath $candidate -Force -ErrorAction Stop).FullName.TrimEnd('\')
        } catch {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($full)) {
            continue
        }

        $key = $full.ToLowerInvariant()
        if (-not $pathMap.ContainsKey($key)) {
            $pathMap[$key] = $full
        }
    }

    $allRoots = @($pathMap.Values | Sort-Object)
    foreach ($root in $allRoots) {
        $rootWithSlash = "$($root.TrimEnd('\'))\"
        $isNested = $false

        foreach ($other in $allRoots) {
            if ($root -eq $other) {
                continue
            }

            $otherWithSlash = "$($other.TrimEnd('\'))\"
            if ($rootWithSlash.StartsWith($otherWithSlash, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isNested = $true
                break
            }
        }

        if (-not $isNested) {
            $existing.Add($root)
        }
    }

    return @($existing)
}

function Get-SyncedSizeOnDisk {
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$DeadlineUtc
    )

    $syncRoots = @(Get-SyncFolderRoot)
    if ($syncRoots.Count -eq 0) {
        Write-Information 'No known sync folders detected. SyncedSizeOnDisk is 0.'
        return [int64]0
    }

    Write-Information ('Detected sync folder root(s): {0}' -f ($syncRoots -join '; '))
    $syncMetrics = @{
        TotalFiles = [int64]0
        TotalSize = [double]0
        TotalSizeOnDisk = [double]0
    }

    foreach ($syncRoot in $syncRoots) {
        Add-DirectoryFileSizeMetric -RootPath $syncRoot -Metrics $syncMetrics -DeadlineUtc $DeadlineUtc
    }

    return $syncMetrics.TotalSizeOnDisk
}

try {
    Write-Information 'Loading Nexthink remote actions assembly.'
    Add-NexthinkRemoteActionAssembly
    Add-SizeOnDiskInteropType

    if ($MaximumDelayInSeconds -gt 0) {
        $delaySeconds = Get-Random -Minimum 0 -Maximum ($MaximumDelayInSeconds + 1)
        Write-Information "Applying random delay of $delaySeconds second(s)."
        Start-Sleep -Seconds $delaySeconds
    } else {
        Write-Information 'Random delay disabled.'
    }

    $scanDeadlineUtc = [DateTime]::UtcNow.AddSeconds($maximumScanSeconds)

    $resolvedInputPath = Resolve-InputPath -Path $InputPath
    Write-Information "Resolved input path: '$resolvedInputPath'."

    if (-not (Test-Path -Path $resolvedInputPath -ErrorAction SilentlyContinue)) {
        throw "InputPath '$resolvedInputPath' cannot be accessed by the current device context."
    }

    Write-Information 'Collecting folder metrics.'
    $metrics = Get-SizeMetric -Path $resolvedInputPath -DeadlineUtc $scanDeadlineUtc

    Write-Information 'Collecting synchronized folders size-on-disk.'
    $syncedSizeOnDisk = Get-SyncedSizeOnDisk -DeadlineUtc $scanDeadlineUtc

    if ($script:sizeOnDiskWarningsSuppressed) {
        Write-Warning 'Additional size-on-disk fallback warnings were suppressed.'
    }

    Write-Information 'Collecting Windows drive capacity.'
    $windowsDriveCapacity = Get-WindowsDriveCapacity

    Write-Information 'Writing outputs to Nexthink.'
    [nxt]::WriteOutputUInt32('TotalDirectories', (Convert-ToUInt32Safe -Value $metrics.TotalDirectories))
    [nxt]::WriteOutputUInt32('TotalFiles', (Convert-ToUInt32Safe -Value $metrics.TotalFiles))
    [nxt]::WriteOutputSize('TotalSize', (Convert-ToNexthinkSize -Value $metrics.TotalSize))
    [nxt]::WriteOutputSize('TotalSizeOnDisk', (Convert-ToNexthinkSize -Value $metrics.TotalSizeOnDisk))
    [nxt]::WriteOutputSize('TotalCapacityWinDrive', (Convert-ToNexthinkSize -Value $windowsDriveCapacity))
    [nxt]::WriteOutputSize('SyncedSizeOnDisk', (Convert-ToNexthinkSize -Value $syncedSizeOnDisk))

    Write-Information ('Metrics collected successfully. Directories={0}; Files={1}; Size={2}; SizeOnDisk={3}; SyncedSizeOnDisk={4}; WinDriveCapacity={5}.' -f $metrics.TotalDirectories, $metrics.TotalFiles, $metrics.TotalSize, $metrics.TotalSizeOnDisk, $syncedSizeOnDisk, $windowsDriveCapacity)
} catch {
    $exitCode = 1
    Write-Error ('Failed to query user folder size on disk: {0} at line {1}.' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ErrorAction Continue
}

return $exitCode
