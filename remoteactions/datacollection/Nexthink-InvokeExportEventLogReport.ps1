<#
.SYNOPSIS
    Exports and groups Windows Event Logs (Critical, Error, Warning) to a Markdown or CSV file.

.DESCRIPTION
    This remote action queries all enabled event logs for Critical (1), Error (2), and
    Warning (3) level events from the specified number of past days.
    It then groups identical events (by LogName, Level, Source, and EventID)
    to provide a summary report with occurrence counts, first seen, and last seen times.
    The output can be generated either as Markdown (default) or as a CSV file.
    Markdown reports include available hardware manufacturer and model information.

.PARAMETER Days
    The number of days back to query for events. Defaults to 7.

.PARAMETER UNCPath
    UNC directory where the report is saved.

.PARAMETER OutputFormat
    The file format for the report. Valid options: md (default) or csv.

.PARAMETER UNCUsername
    Optional username used to access UNCPath. UNCPassword must also be supplied.

.PARAMETER UNCPassword
    Optional plaintext password used to access UNCPath. UNCUsername must also be supplied.
    The value is used to create a PSCredential and is never written to the report or logs.

.NOTES
    ===========================================================================
    Organization:   synit.io
    Pwsh:           Powershell 5.1+
    Compatibility:  Designed to be backwards-compatible with Windows PowerShell 5.1.
    Dependencies:   Requires the nxtremoteactions.dll assembly to be present in
                    the $env:NEXTHINK\RemoteActions directory.
    Signing:        For environments with an 'AllSigned' execution policy, this
                    script must be digitally signed to execute correctly.
    ===========================================================================
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = 'The number of days back to query for events. Defaults to 7.')]
    [ValidateRange(1, 3650)]
    [int]$Days = 7,
    [Parameter(Mandatory = $false, HelpMessage = 'The target server to store the report.')]
    [string]$UNCPath,
    [Parameter(Mandatory = $false, HelpMessage = 'Optional username used to access the UNC share.')]
    [string]$UNCUsername,
    [Parameter(Mandatory = $false, HelpMessage = 'Optional plaintext password used to access the UNC share.')]
    [string]$UNCPassword,
    [Parameter(Mandatory = $false, HelpMessage = 'The file format for the report. Valid options: Markdown (default) or Csv.')]
    [ValidateSet('md', 'csv')]
    [string]$OutputFormat = 'md'
)

# Set the script to stop on any terminating error for robust error handling.
$ErrorActionPreference = 'Stop'
$exitCode = 0
$reportStatus = $false
$temporaryDriveName = $null
$reportPath = $null
$nexthinkAssemblyLoaded = $false

function ConvertTo-MarkdownCell {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    return (([string]$Value) -replace '\|', '&#124;' -replace '(\r\n|\n\r|\r|\n)', '<br>').Trim()
}

try {
    if ([string]::IsNullOrWhiteSpace($UNCPath) -or -not $UNCPath.StartsWith('\\')) {
        throw 'UNCPath must be a valid UNC path beginning with "\\".'
    }

    $hasUNCUsername = -not [string]::IsNullOrWhiteSpace($UNCUsername)
    $hasUNCPassword = -not [string]::IsNullOrWhiteSpace($UNCPassword)
    if ($hasUNCUsername -ne $hasUNCPassword) {
        throw 'UNCUsername and UNCPassword must either both be supplied or both be omitted.'
    }

    # --- 1. Load Nexthink Assembly ---
    $dllPath = Join-Path -Path $env:NEXTHINK -ChildPath 'RemoteActions\nxtremoteactions.dll'
    if (Test-Path -Path $dllPath -PathType Leaf) {
        Add-Type -Path $dllPath
        $nexthinkAssemblyLoaded = $true
        Write-Information 'Successfully loaded nxtremoteactions.dll.'
    } else {
        throw 'Unable to load nxtremoteactions.dll'
    }

    # The full path (including filename) to save the report.
    # Defaults to "%HOSTNAME%_%DATE%_EventLog_Grouped_Report.[md|csv]" (in the export share's directory).
    $outputExtension = if ($OutputFormat -eq 'csv') { 'csv' } else { 'md' }
    $outputFileName = "$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyy_MM_dd')_EventLog_Grouped_Report.$outputExtension"
    $reportPath = Join-Path -Path $UNCPath -ChildPath $outputFileName
    $outputDirectory = $UNCPath

    if ($hasUNCUsername) {
        $securePassword = ConvertTo-SecureString -String $UNCPassword -AsPlainText -Force
        $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UNCUsername, $securePassword
        $temporaryDriveName = "NxtReport$PID"
        $null = New-PSDrive -Name $temporaryDriveName -PSProvider FileSystem -Root $UNCPath -Credential $credential -Scope Script
        $outputDirectory = "$temporaryDriveName`:\"
    }

    $outputPath = Join-Path -Path $outputDirectory -ChildPath $outputFileName

    Write-Information 'Starting event log export...'
    Write-Information "Querying events from the last $Days day(s)."
    Write-Information "Output format: $OutputFormat"
    Write-Information "Output will be saved to: $reportPath"

    # Get all enabled logs that have records
    Write-Information 'Finding all enabled event logs with records...'
    $logNames = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -and ($_.RecordCount -gt 0 -or $null -eq $_.RecordCount) } | Select-Object -ExpandProperty LogName)

    if ($logNames.Count -eq 0) {
        throw 'Could not find any enabled event logs with records.'
    }

    if (-not (Test-Path -Path $outputDirectory -PathType Container)) {
        throw 'Could not access output path share. Aborting.'
    }

    Write-Information "Found $($logNames.Count) logs to query."

    # Define the filter
    $startDate = (Get-Date).AddDays(-$Days)
    $filter = @{
        LogName = $logNames
        Level = 1, 2, 3 # Critical, Error, Warning
        StartTime = $startDate
    }

    # Query the events
    Write-Information 'Querying events. This may take a moment...'
    # Suppress errors for logs that might be inaccessible (e.g., Security log)
    $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
    $totalEvents = $events.Count
    $endDate = Get-Date
    $statusMessage = 'Events found and processed.'

    if ($events.Count -eq 0) {
        Write-Warning 'No Warning, Error, or Critical events found in the specified time frame.'
        $statusMessage = 'No Warning, Error, or Critical events found.'
        $reportRows = @(
            [PSCustomObject]@{
                Count         = 0
                FirstSeen     = $null
                LastSeen      = $null
                LogName       = 'N/A'
                Level         = 'N/A'
                Source        = 'N/A'
                EventID       = 'N/A'
                SampleMessage = $statusMessage
            }
        )
        $groupedEvents = @()
    } else {
        Write-Information "Found $($events.Count) total events. Grouping unique events..."

        # Group events by key properties to find unique issues
        $groupedEvents = @($events | Group-Object -Property LogName, LevelDisplayName, ProviderName, Id)

        Write-Information "Found $($groupedEvents.Count) unique events. Preparing report rows..."

        # Process each group of events into a common object structure
        $reportRows = $groupedEvents | Sort-Object -Property Count -Descending | ForEach-Object {
            $group = $_
            $count = $group.Count

            # Find boundaries without sorting every event in the group.
            $firstEvent = $group.Group[0]
            $lastEvent = $group.Group[0]
            foreach ($event in $group.Group) {
                if ($event.TimeCreated -lt $firstEvent.TimeCreated) {
                    $firstEvent = $event
                }
                if ($event.TimeCreated -gt $lastEvent.TimeCreated) {
                    $lastEvent = $event
                }
            }

            # Get properties from the last event in the group
            $logName = $lastEvent.LogName
            $level = $lastEvent.LevelDisplayName
            $source = $lastEvent.ProviderName
            $eventID = $lastEvent.Id

            # Use the newest event message as the group sample.
            $message = ([string]$lastEvent.Message).Trim()

            # Return a reusable object representation for either Markdown or CSV output
            [PSCustomObject]@{
                Count         = $count
                FirstSeen     = $firstEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss zzz')
                LastSeen      = $lastEvent.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss zzz')
                LogName       = $logName
                Level         = $level
                Source        = $source
                EventID       = $eventID
                SampleMessage = $message
            }
        }
    }

    # Save the report in the requested format
    Write-Information "Saving report to $reportPath..."
    switch ($OutputFormat) {
        'csv' {
            $reportRows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
        }
        'md' {
            $hardwareManufacturer = $null
            $hardwareModel = $null
            try {
                $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
                $hardwareManufacturer = $computerSystem.Manufacturer
                $hardwareModel = $computerSystem.Model
            } catch {
                Write-Warning "Could not query Win32_ComputerSystem: $($_.Exception.Message)"
            }

            try {
                $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
                $osCaption = $operatingSystem.Caption
                $osVersion = $operatingSystem.Version
                $osBuildNumber = $operatingSystem.BuildNumber
            } catch {
                Write-Warning "Could not query Win32_OperatingSystem: $($_.Exception.Message)"
                $osCaption = 'Microsoft Windows'
                $osVersion = [Environment]::OSVersion.Version.ToString()
                $osBuildNumber = [Environment]::OSVersion.Version.Build
            }

            # Markdown formatting
            $mdOutput = @(
                '# Grouped Event Log Report',
                "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
                "**Hostname:** $(ConvertTo-MarkdownCell -Value $env:COMPUTERNAME)"
            )

            if (-not [string]::IsNullOrWhiteSpace($hardwareManufacturer)) {
                $mdOutput += "**Hardware Manufacturer:** $(ConvertTo-MarkdownCell -Value $hardwareManufacturer)"
            }
            if (-not [string]::IsNullOrWhiteSpace($hardwareModel)) {
                $mdOutput += "**Hardware Model:** $(ConvertTo-MarkdownCell -Value $hardwareModel)"
            }

            $mdOutput += @(
                "**Operating System:** $(ConvertTo-MarkdownCell -Value $osCaption)",
                "**Windows Version:** $(ConvertTo-MarkdownCell -Value $osVersion)",
                "**Windows Build:** $(ConvertTo-MarkdownCell -Value $osBuildNumber)",
                "**Date Range Queried:** $($startDate.ToString('yyyy-MM-dd HH:mm')) to $($endDate.ToString('yyyy-MM-dd HH:mm'))",
                "**Total Events Found:** $totalEvents",
                "**Unique Events Found:** $($groupedEvents.Count)",
                "**Status:** $statusMessage",
                '',
                '| Count | First Seen | Last Seen | LogName | Level | Source | EventID | Sample Message |',
                '|---|---|---|---|---|---|---|---|'
            )

            $mdRows = $reportRows | ForEach-Object {
                "| $(ConvertTo-MarkdownCell -Value $_.Count) | $(ConvertTo-MarkdownCell -Value $_.FirstSeen) | $(ConvertTo-MarkdownCell -Value $_.LastSeen) | $(ConvertTo-MarkdownCell -Value $_.LogName) | $(ConvertTo-MarkdownCell -Value $_.Level) | $(ConvertTo-MarkdownCell -Value $_.Source) | $(ConvertTo-MarkdownCell -Value $_.EventID) | $(ConvertTo-MarkdownCell -Value $_.SampleMessage) |"
            }

            $mdOutput += $mdRows
            $mdOutput | Out-File -FilePath $outputPath -Encoding UTF8
        }
        default {
            throw 'Unsupported format. Aborting.'
        }
    }

    if (-not (Test-Path -Path $outputPath -PathType Leaf)) {
        throw 'Report file was not found after export.'
    }

    $reportStatus = $true
    Write-Information "Export complete. File saved to $reportPath"

    # --- 4. Write All Outputs to Nexthink ---
    [nxt]::WriteOutputBool('ReportSuccessfull', $reportStatus)
    [nxt]::WriteOutputString('ReportPath', $reportPath)
} catch {
    $exitCode = 1
    $errorMessage = "An unexpected error occurred: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)."
    Write-Error -Message $errorMessage -ErrorAction Continue

    if ($nexthinkAssemblyLoaded) {
        try {
            [nxt]::WriteOutputBool('ReportSuccessfull', $false)
            [nxt]::WriteOutputString('ReportPath', [string]$reportPath)
        } catch {
            Write-Warning "Could not write failure outputs to Nexthink: $($_.Exception.Message)"
        }
    }
} finally {
    if ($temporaryDriveName -and (Get-PSDrive -Name $temporaryDriveName -ErrorAction SilentlyContinue)) {
        Remove-PSDrive -Name $temporaryDriveName -Force -ErrorAction SilentlyContinue
    }
}

exit $exitCode
