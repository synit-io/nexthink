<#
.SYNOPSIS
    Reports recursive folder metrics and the largest files and folders below a path.

.DESCRIPTION
    Scans a filesystem path once and reports total file, directory, and byte counts.
    It also returns the largest files and largest subfolders, including their paths.

    Folder sizes include files in all descendant folders. The queried root is excluded
    from LargestFolders because it would always be the largest folder. A reparse-point
    root is rejected. Child reparse points are counted as directories but are not
    traversed, preventing junction loops and scans outside the requested path.

    The scan stops after MaximumScanSeconds. Partial results are still written, with
    ScanComplete set to False and detailed state and affected-directory counts.
    Intentional child reparse exclusions produce CompleteWithExclusions and do not make
    ScanComplete false.

    ScanState is Complete, CompleteWithExclusions, PartialAccess, or PartialTimeout.
    SkippedDirectories combines reparse exclusions, terminal unreadable directories,
    and discovered directories pending at timeout. The three detail outputs separate
    those causes. ElapsedDuration covers traversal and result preparation before output.

    Mode controls which ranked path lists are populated. Counts and TotalSize are
    always collected because recursive folder sizing requires the same traversal.

.PARAMETER BasePath
    Filesystem directory to scan recursively.

.PARAMETER TopCount
    Number of largest files and folders to return. Valid range: 1..50.

.PARAMETER MaximumScanSeconds
    Maximum scan duration. Valid range: 30..840 seconds. Default: 300. The upper bound
    reserves 60 seconds below a 900-second Remote Action timeout for final output.

.PARAMETER Mode
    Ranked path lists to return: FilesAndFolders, Files, or Folders. The excluded
    list is returned as a single '-' entry. Default: FilesAndFolders.

.OUTPUTS
    [string]   QueriedPath
    [uint32]   TotalDirectories
    [uint32]   TotalFiles
    [size]     TotalSize
    [string[]] LargestFiles
    [string[]] LargestFolders
    [bool]     ScanComplete
    [uint32]   SkippedDirectories
    [bool]     CountValuesCapped
    [bool]     PathsTruncated
    [string]   ScanState
    [uint32]   ReparsePointsSkipped
    [uint32]   UnreadableDirectories
    [duration] ElapsedDuration
    [uint32]   DiscoveredDirectoriesPending

.EXAMPLE
    -BasePath 'C:\Users' -TopCount 10 -MaximumScanSeconds 300 -Mode 'Files'

    Returns recursive counts and sizes plus the ten largest files below C:\Users.
    LargestFolders contains '-'.

.NOTES
    ==========================================================================
    Organization:   synit.io
    Pwsh:           Windows PowerShell 5.1+
    Compatibility:  Designed to be backwards-compatible with Windows PowerShell 5.1.
    Dependencies:   Requires $env:NEXTHINK\RemoteActions\nxtremoteactions.dll.
    Output limits:  Each string/list entry is limited to 1024 UTF-8 bytes.
    ==========================================================================
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Enter the filesystem directory to scan (for example, C:\Users).')]
    [ValidateNotNullOrEmpty()]
    [string]$BasePath,

    [Parameter(Mandatory = $false, HelpMessage = 'Number of largest files and folders to return. Valid range: 1..50.')]
    [ValidateRange(1, 50)]
    [int]$TopCount = 10,

    [Parameter(Mandatory = $false, HelpMessage = 'Maximum scan duration in seconds. Valid range: 30..840.')]
    [ValidateRange(30, 3600)]
    [int]$MaximumScanSeconds = 30,

    [Parameter(Mandatory = $false, HelpMessage = 'Ranked path lists to return: FilesAndFolders, Files, or Folders.')]
    [ValidateSet('FilesAndFolders', 'Files', 'Folders')]
    [string]$Mode = 'FilesAndFolders'
)

$ErrorActionPreference = 'Stop'
$exitCode = 0
$maxOutputBytes = 1024
$maximumUInt32 = [uint64][uint32]::MaxValue

function Add-NexthinkRemoteActionAssembly {
    [CmdletBinding()]
    param ()

    if ([string]::IsNullOrWhiteSpace($env:NEXTHINK)) {
        throw 'NEXTHINK environment variable is not defined.'
    }

    $remoteActionsPath = Join-Path -Path $env:NEXTHINK -ChildPath 'RemoteActions'
    $dllPath = Join-Path -Path $remoteActionsPath -ChildPath 'nxtremoteactions.dll'
    if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) {
        throw "Nexthink Remote Action DLL not found at '$dllPath'."
    }

    Add-Type -LiteralPath $dllPath
}

function Convert-ToNexthinkUInt32 {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [long]::MaxValue)]
        [long]$Value
    )

    if ([uint64]$Value -gt $script:maximumUInt32) {
        return [uint32]::MaxValue
    }

    return [uint32]$Value
}

function Limit-Utf8String {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 1024)]
        [int]$MaxBytes = 1024
    )

    if ($null -eq $Value) {
        return ''
    }

    $encoding = [System.Text.Encoding]::UTF8
    if ($encoding.GetByteCount($Value) -le $MaxBytes) {
        return $Value
    }

    # Preserve both path root and leaf name when long paths must be shortened.
    $marker = '...'
    if ($encoding.GetByteCount($marker) -gt $MaxBytes) {
        return ''
    }

    $low = 0
    $high = $Value.Length
    $best = $marker

    while ($low -le $high) {
        $charactersToKeep = [int](($low + $high) / 2)
        $prefixLength = [int][Math]::Ceiling($charactersToKeep * 0.6)
        $suffixLength = $charactersToKeep - $prefixLength

        # Do not split a UTF-16 surrogate pair at either retained boundary.
        if (
            $prefixLength -gt 0 -and
            $prefixLength -lt $Value.Length -and
            [char]::IsHighSurrogate($Value[$prefixLength - 1]) -and
            [char]::IsLowSurrogate($Value[$prefixLength])
        ) {
            $prefixLength--
        }
        $suffixStart = $Value.Length - $suffixLength
        if (
            $suffixLength -gt 0 -and
            $suffixStart -gt 0 -and
            [char]::IsHighSurrogate($Value[$suffixStart - 1]) -and
            [char]::IsLowSurrogate($Value[$suffixStart])
        ) {
            $suffixLength--
        }

        $prefix = if ($prefixLength -gt 0) { $Value.Substring(0, $prefixLength) } else { '' }
        $suffix = if ($suffixLength -gt 0) { $Value.Substring($Value.Length - $suffixLength) } else { '' }
        $candidate = $prefix + $marker + $suffix

        if ($encoding.GetByteCount($candidate) -le $MaxBytes) {
            $best = $candidate
            $low = $charactersToKeep + 1
        } else {
            $high = $charactersToKeep - 1
        }
    }

    return $best
}

function Format-ByteSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [double]::MaxValue)]
        [double]$SizeBytes
    )

    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($SizeBytes -ge 1TB) {
        return [string]::Format($culture, '{0:0.##} TB', ($SizeBytes / 1TB))
    }
    if ($SizeBytes -ge 1GB) {
        return [string]::Format($culture, '{0:0.##} GB', ($SizeBytes / 1GB))
    }
    if ($SizeBytes -ge 1MB) {
        return [string]::Format($culture, '{0:0.##} MB', ($SizeBytes / 1MB))
    }
    if ($SizeBytes -ge 1KB) {
        return [string]::Format($culture, '{0:0.##} KB', ($SizeBytes / 1KB))
    }

    return [string]::Format($culture, '{0:0} B', $SizeBytes)
}

function Format-RankedPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [double]$SizeBytes,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $value = '{0} | {1}' -f (Format-ByteSize -SizeBytes $SizeBytes), $Path
    return Limit-Utf8String -Value $value -MaxBytes $script:maxOutputBytes
}

function Write-LimitedWarning {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($script:warningCount -ge 10) {
        $script:warningsSuppressed = $true
        return
    }

    Write-Warning $Message
    $script:warningCount++
}

function Add-TopCandidate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$Candidates,

        [Parameter(Mandatory = $true)]
        [double]$SizeBytes,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 50)]
        [int]$Limit
    )

    # Root of this bounded heap is the least useful retained candidate: smallest
    # size, then lexicographically latest path. Reject noncompetitive items before
    # allocating a candidate object.
    if ($Candidates.Count -ge $Limit) {
        $worst = $Candidates[0]
        $isBetter = (
            $SizeBytes -gt $worst.SizeBytes -or
            (
                $SizeBytes -eq $worst.SizeBytes -and
                [string]::CompareOrdinal($Path, $worst.Path) -lt 0
            )
        )
        if (-not $isBetter) {
            return
        }
    }

    $candidate = [PSCustomObject]@{
        Path = $Path
        SizeBytes = $SizeBytes
    }

    if ($Candidates.Count -lt $Limit) {
        [void]$Candidates.Add($candidate)
        $index = $Candidates.Count - 1
        while ($index -gt 0) {
            $parentIndex = [int][Math]::Floor(($index - 1) / 2)
            $current = $Candidates[$index]
            $parent = $Candidates[$parentIndex]
            $currentIsWorse = (
                $current.SizeBytes -lt $parent.SizeBytes -or
                (
                    $current.SizeBytes -eq $parent.SizeBytes -and
                    [string]::CompareOrdinal($current.Path, $parent.Path) -gt 0
                )
            )
            if (-not $currentIsWorse) {
                break
            }

            $Candidates[$index] = $parent
            $Candidates[$parentIndex] = $current
            $index = $parentIndex
        }
        return
    }

    $Candidates[0] = $candidate
    $index = 0
    while ($true) {
        $leftIndex = ($index * 2) + 1
        if ($leftIndex -ge $Candidates.Count) {
            break
        }

        $rightIndex = $leftIndex + 1
        $worseChildIndex = $leftIndex
        if ($rightIndex -lt $Candidates.Count) {
            $left = $Candidates[$leftIndex]
            $right = $Candidates[$rightIndex]
            $rightIsWorse = (
                $right.SizeBytes -lt $left.SizeBytes -or
                (
                    $right.SizeBytes -eq $left.SizeBytes -and
                    [string]::CompareOrdinal($right.Path, $left.Path) -gt 0
                )
            )
            if ($rightIsWorse) {
                $worseChildIndex = $rightIndex
            }
        }

        $current = $Candidates[$index]
        $worseChild = $Candidates[$worseChildIndex]
        $childIsWorse = (
            $worseChild.SizeBytes -lt $current.SizeBytes -or
            (
                $worseChild.SizeBytes -eq $current.SizeBytes -and
                [string]::CompareOrdinal($worseChild.Path, $current.Path) -gt 0
            )
        )
        if (-not $childIsWorse) {
            break
        }

        $Candidates[$index] = $worseChild
        $Candidates[$worseChildIndex] = $current
        $index = $worseChildIndex
    }
}

$activeFrames = $null
$scanStopwatch = $null

try {
    Write-Information 'Loading Nexthink remote actions assembly.'
    Add-NexthinkRemoteActionAssembly

    Write-Information "Resolving scan path '$BasePath'."
    $resolvedPath = Resolve-Path -LiteralPath $BasePath -ErrorAction Stop
    if ($resolvedPath.Provider.Name -ne 'FileSystem') {
        throw "Path '$BasePath' is not a filesystem path."
    }

    $rootItem = Get-Item -LiteralPath $resolvedPath.ProviderPath -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw "Path '$BasePath' is not a directory."
    }
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Path '$BasePath' is a reparse-point directory. Query its resolved non-reparse target explicitly."
    }

    $rootPath = $rootItem.FullName
    $includeFiles = ($Mode -ne 'Folders')
    $includeFolders = ($Mode -ne 'Files')
    Write-Information "Scanning '$rootPath'. Mode=$Mode; TopCount=$TopCount; MaximumScanSeconds=$MaximumScanSeconds."

    $largestFileCandidates = New-Object System.Collections.ArrayList
    $largestFolderCandidates = New-Object System.Collections.ArrayList
    $activeFrames = New-Object System.Collections.Stack
    $activeFrames.Push([PSCustomObject]@{
            Path = $rootPath
            IsRoot = $true
            State = [int]0
            Enumerator = $null
            SizeBytes = [double]0
            HadReadFailure = $false
        })

    [long]$totalFileCount = 0
    [long]$totalDirectoryCount = 0
    [double]$totalSizeBytes = 0
    [long]$reparsePointCount = 0
    [long]$terminalUnreadableDirectoryCount = 0
    [long]$activeUnreadableDirectoryCount = 0
    [long]$pendingDirectoryCount = 0
    [int]$warningCount = 0
    $warningsSuppressed = $false
    $timedOut = $false
    $scanStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $scanBudget = [TimeSpan]::FromSeconds($MaximumScanSeconds)

    # Lazy depth-first frames retain only active traversal depth. State values:
    # 0 = not opened, 1 = enumerating, 2 = ready to aggregate and release.
    while ($activeFrames.Count -gt 0) {
        if ($scanStopwatch.Elapsed -ge $scanBudget) {
            $timedOut = $true
            break
        }

        $frame = $activeFrames.Peek()
        if ($frame.State -eq 2) {
            $completedFrame = $activeFrames.Pop()
            if ($completedFrame.HadReadFailure) {
                $terminalUnreadableDirectoryCount++
            }

            if ($includeFolders) {
                if ($activeFrames.Count -gt 0) {
                    $parentFrame = $activeFrames.Peek()
                    $parentFrame.SizeBytes += $completedFrame.SizeBytes
                }
                if (
                    -not $completedFrame.IsRoot -and
                    ($completedFrame.SizeBytes -gt 0 -or -not $completedFrame.HadReadFailure)
                ) {
                    Add-TopCandidate -Candidates $largestFolderCandidates -SizeBytes $completedFrame.SizeBytes -Path $completedFrame.Path -Limit $TopCount
                }
            }
            continue
        }

        if ($frame.State -eq 0) {
            try {
                $directoryInfo = New-Object System.IO.DirectoryInfo -ArgumentList ([string]$frame.Path)
                $frame.Enumerator = $directoryInfo.EnumerateFileSystemInfos().GetEnumerator()
                $frame.State = 1
            } catch {
                $frame.HadReadFailure = $true
                $frame.State = 2
                Write-LimitedWarning -Message ("Could not enumerate directory '{0}': {1}" -f $frame.Path, $_.Exception.Message)
            }
            continue
        }

        try {
            $hasNextItem = $frame.Enumerator.MoveNext()
        } catch {
            $frame.HadReadFailure = $true
            $frame.State = 2
            Write-LimitedWarning -Message ("Could not read all items in '{0}': {1}" -f $frame.Path, $_.Exception.Message)
            try {
                $frame.Enumerator.Dispose()
            } catch {
                Write-LimitedWarning -Message ("Could not release directory enumerator for '{0}': {1}" -f $frame.Path, $_.Exception.Message)
            }
            $frame.Enumerator = $null
            continue
        }

        if (-not $hasNextItem) {
            try {
                $frame.Enumerator.Dispose()
            } catch {
                $frame.HadReadFailure = $true
                Write-LimitedWarning -Message ("Could not release directory enumerator for '{0}': {1}" -f $frame.Path, $_.Exception.Message)
            }
            $frame.Enumerator = $null
            $frame.State = 2
            continue
        }

        $item = $frame.Enumerator.Current
        if ($item -is [System.IO.DirectoryInfo]) {
            $totalDirectoryCount++
            try {
                $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            } catch {
                $terminalUnreadableDirectoryCount++
                Write-LimitedWarning -Message ("Could not inspect directory '{0}': {1}" -f $item.FullName, $_.Exception.Message)
                continue
            }

            if ($isReparsePoint) {
                $reparsePointCount++
                continue
            }

            $activeFrames.Push([PSCustomObject]@{
                    Path = $item.FullName
                    IsRoot = $false
                    State = [int]0
                    Enumerator = $null
                    SizeBytes = [double]0
                    HadReadFailure = $false
                })
            continue
        }

        try {
            [double]$fileSize = $item.Length
        } catch {
            $frame.HadReadFailure = $true
            Write-LimitedWarning -Message ("Could not read file size for '{0}': {1}" -f $item.FullName, $_.Exception.Message)
            continue
        }

        $totalFileCount++
        $totalSizeBytes += $fileSize
        if ($includeFolders) {
            $frame.SizeBytes += $fileSize
        }
        if ($includeFiles) {
            Add-TopCandidate -Candidates $largestFileCandidates -SizeBytes $fileSize -Path $item.FullName -Limit $TopCount
        }
    }

    if ($timedOut) {
        $pendingDirectoryCount = [long]$activeFrames.Count

        # Unwind active frames from child to parent so partial folder sizes retain all
        # data collected before the deadline. Open enumerators are always released.
        while ($activeFrames.Count -gt 0) {
            $partialFrame = $activeFrames.Pop()
            if ($null -ne $partialFrame.Enumerator) {
                try {
                    $partialFrame.Enumerator.Dispose()
                } catch {
                    $partialFrame.HadReadFailure = $true
                    Write-LimitedWarning -Message ("Could not release directory enumerator for '{0}': {1}" -f $partialFrame.Path, $_.Exception.Message)
                }
                $partialFrame.Enumerator = $null
            }
            if ($partialFrame.HadReadFailure) {
                $activeUnreadableDirectoryCount++
            }

            if ($includeFolders) {
                if ($activeFrames.Count -gt 0) {
                    $parentFrame = $activeFrames.Peek()
                    $parentFrame.SizeBytes += $partialFrame.SizeBytes
                }
                if (-not $partialFrame.IsRoot -and $partialFrame.SizeBytes -gt 0) {
                    Add-TopCandidate -Candidates $largestFolderCandidates -SizeBytes $partialFrame.SizeBytes -Path $partialFrame.Path -Limit $TopCount
                }
            }
        }

        Write-Warning ('Scan reached MaximumScanSeconds={0}. Returning partial results; {1} discovered directories were not fully scanned.' -f $MaximumScanSeconds, $pendingDirectoryCount)
    }

    [long]$unreadableDirectoryCount = $terminalUnreadableDirectoryCount + $activeUnreadableDirectoryCount
    [long]$affectedDirectoryCount = $reparsePointCount + $terminalUnreadableDirectoryCount + $pendingDirectoryCount
    $scanComplete = (-not $timedOut -and $unreadableDirectoryCount -eq 0)
    if ($timedOut) {
        $scanState = 'PartialTimeout'
    } elseif ($unreadableDirectoryCount -gt 0) {
        $scanState = 'PartialAccess'
    } elseif ($reparsePointCount -gt 0) {
        $scanState = 'CompleteWithExclusions'
    } else {
        $scanState = 'Complete'
    }

    if ($warningsSuppressed) {
        Write-Warning 'Additional filesystem warnings were suppressed. See ScanState and directory-detail outputs.'
    }

    $largestFileRecords = @(
        $largestFileCandidates |
            Sort-Object -Property @{ Expression = 'SizeBytes'; Descending = $true }, @{ Expression = 'Path'; Descending = $false }
    )
    $largestFolderRecords = @(
        $largestFolderCandidates |
            Sort-Object -Property @{ Expression = 'SizeBytes'; Descending = $true }, @{ Expression = 'Path'; Descending = $false }
    )
    $largestFiles = @(
        $largestFileRecords |
            ForEach-Object { Format-RankedPath -SizeBytes $_.SizeBytes -Path $_.Path }
    )
    $largestFolders = @(
        $largestFolderRecords |
            ForEach-Object { Format-RankedPath -SizeBytes $_.SizeBytes -Path $_.Path }
    )

    if ($largestFiles.Count -eq 0) {
        $largestFiles = [string[]]@('-')
    }
    if ($largestFolders.Count -eq 0) {
        $largestFolders = [string[]]@('-')
    }

    $safeRootPath = Limit-Utf8String -Value $rootPath -MaxBytes $maxOutputBytes
    $pathsTruncated = ($safeRootPath -ne $rootPath)
    foreach ($candidate in @($largestFileRecords) + @($largestFolderRecords)) {
        if ((Format-RankedPath -SizeBytes $candidate.SizeBytes -Path $candidate.Path) -ne ('{0} | {1}' -f (Format-ByteSize -SizeBytes $candidate.SizeBytes), $candidate.Path)) {
            $pathsTruncated = $true
            break
        }
    }

    $countValuesCapped = (
        [uint64]$totalDirectoryCount -gt $maximumUInt32 -or
        [uint64]$totalFileCount -gt $maximumUInt32 -or
        [uint64]$affectedDirectoryCount -gt $maximumUInt32 -or
        [uint64]$reparsePointCount -gt $maximumUInt32 -or
        [uint64]$unreadableDirectoryCount -gt $maximumUInt32 -or
        [uint64]$pendingDirectoryCount -gt $maximumUInt32
    )
    if ($countValuesCapped) {
        Write-Warning 'One or more count outputs exceeded UInt32 maximum and were capped at 4294967295.'
    }
    if ($pathsTruncated) {
        Write-Warning 'One or more output paths exceeded 1024 UTF-8 bytes and were shortened in the middle.'
    }
    if ([double]::IsNaN($totalSizeBytes) -or [double]::IsInfinity($totalSizeBytes) -or $totalSizeBytes -gt [float]::MaxValue) {
        throw 'Total folder size is outside the Nexthink size output range.'
    }

    $scanStopwatch.Stop()
    $elapsedDuration = $scanStopwatch.Elapsed

    Write-Information 'Writing fixed, size-safe outputs to Nexthink.'
    [nxt]::WriteOutputString('QueriedPath', $safeRootPath)
    [nxt]::WriteOutputUInt32('TotalDirectories', (Convert-ToNexthinkUInt32 -Value $totalDirectoryCount))
    [nxt]::WriteOutputUInt32('TotalFiles', (Convert-ToNexthinkUInt32 -Value $totalFileCount))
    [nxt]::WriteOutputSize('TotalSize', [float]$totalSizeBytes)
    [nxt]::WriteOutputStringList('LargestFiles', [string[]]$largestFiles)
    [nxt]::WriteOutputStringList('LargestFolders', [string[]]$largestFolders)
    [nxt]::WriteOutputBool('ScanComplete', [bool]$scanComplete)
    [nxt]::WriteOutputUInt32('SkippedDirectories', (Convert-ToNexthinkUInt32 -Value $affectedDirectoryCount))
    [nxt]::WriteOutputBool('CountValuesCapped', [bool]$countValuesCapped)
    [nxt]::WriteOutputBool('PathsTruncated', [bool]$pathsTruncated)
    [nxt]::WriteOutputString('ScanState', $scanState)
    [nxt]::WriteOutputUInt32('ReparsePointsSkipped', (Convert-ToNexthinkUInt32 -Value $reparsePointCount))
    [nxt]::WriteOutputUInt32('UnreadableDirectories', (Convert-ToNexthinkUInt32 -Value $unreadableDirectoryCount))
    [nxt]::WriteOutputDuration('ElapsedDuration', [TimeSpan]$elapsedDuration)
    [nxt]::WriteOutputUInt32('DiscoveredDirectoriesPending', (Convert-ToNexthinkUInt32 -Value $pendingDirectoryCount))

    Write-Information ('Folder scan complete. Mode={0}; State={1}; Directories={2}; Files={3}; SizeBytes={4}; SkippedDirectories={5}; ReparsePointsSkipped={6}; UnreadableDirectories={7}; PendingDirectories={8}; ElapsedMs={9}.' -f $Mode, $scanState, $totalDirectoryCount, $totalFileCount, $totalSizeBytes, $affectedDirectoryCount, $reparsePointCount, $unreadableDirectoryCount, $pendingDirectoryCount, [Math]::Round($elapsedDuration.TotalMilliseconds))
} catch {
    $exitCode = 1
    Write-Error ('Failed to query folder metrics: {0} at line {1}.' -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) -ErrorAction Continue
} finally {
    if ($null -ne $activeFrames) {
        while ($activeFrames.Count -gt 0) {
            $remainingFrame = $activeFrames.Pop()
            if ($null -ne $remainingFrame.Enumerator) {
                try {
                    $remainingFrame.Enumerator.Dispose()
                } catch {
                    Write-Warning ("Could not release directory enumerator for '{0}': {1}" -f $remainingFrame.Path, $_.Exception.Message)
                }
            }
        }
    }
    if ($null -ne $scanStopwatch -and $scanStopwatch.IsRunning) {
        $scanStopwatch.Stop()
    }
}

return $exitCode
