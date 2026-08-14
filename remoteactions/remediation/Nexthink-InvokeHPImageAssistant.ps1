<#
.SYNOPSIS
Scans for or installs selected HP Image Assistant recommendations on HP devices.

.DESCRIPTION
Runs unattended with administrative privileges, normally as LocalSystem, from a
Nexthink Windows Remote Action. The action reuses or obtains a caller-selected HPIA
version from an internal HTTPS mirror, verifies the supplied SHA-256, HP Authenticode
signature, and extracted executable version, then analyzes the selected category.

Scan mode is read-only: it reports recommendation counts and BIOS-settings drift,
never installs recommendations, and never triggers a campaign. Install mode first
scans for applicable recommendations, optionally triggers one non-blocking campaign,
and installs only HPIA auto-installable (SSM-compliant) recommendations. Recognized
BIOS SoftPaqs are prepared by HPIA, validated, then re-extracted from the signed HP
SoftPaq wrapper into an owned folder. The signed HP firmware updater is run with a
bounded 45-minute wait instead of HPIA's fixed 15-minute per-SoftPaq executor wait.
On 64-bit Windows, the signed native 64-bit updater is preferred when the package
contains it. Bounded HP updater log details are included when firmware staging fails.
The exact HP `Flash already in progress` state with error `0x13` is treated as an
already-staged update requiring reboot, provided no HP firmware updater remains active.
If HPIA does not retain the downloaded CVA metadata, the action retrieves that small
file from its deterministic official HP HTTPS location with a bounded network request.
It performs a verification scan after installation unless an installer reports that
a reboot is required.
Non-auto-installable recommendations are counted but are not installed and do not by
themselves make an otherwise successful remediation fail. Per the HPIA CLI contract,
the All category excludes Accessories; select Accessories explicitly when needed.

Required environment, input, HPIA, download, extraction, filesystem, verification,
and Nexthink integration failures return exit code 1. Optional campaign failures warn
and do not block installation. Successful Scan and Install executions return exit code 0.

.PARAMETER hpia_mode
Operation to perform. Scan analyzes and reports the selected category without making
changes or displaying a campaign. Install analyzes, optionally displays the campaign,
installs selected auto-installable recommendations, and verifies convergence when no
reboot is required. Accepted values: Scan or Install.

.PARAMETER hpia_required_version
Required HPIA version in three- or four-component numeric form, for example 5.3.6 or
5.3.6.1. The action downloads hp-hpia-<version>.exe from the configured mirror and
requires the extracted HPImageAssistant.exe version to match.

.PARAMETER hpia_installer_sha256
Expected 64-character hexadecimal SHA-256 hash of the HPIA installer matching
hpia_required_version. The installer must match this hash and also have a valid HP
Authenticode signature. Letter case is ignored.

.PARAMETER hpia_tool_download_url
Base URL of the internal HPIA mirror. Must be an absolute HTTPS URL without embedded
credentials, query, or fragment. Public HP download hosts are intentionally rejected.
The action appends /hp-hpia-<version>.exe to this value.

.PARAMETER hpia_encoded_bios_password
Optional Base64 representation of binary HPQPwd password-file content. This is not a
plain-text password and must not be replaced with a Base64-encoded plain-text password.
It is decoded only in Install mode for BIOS or All and passed through the supported
password-file argument in a protected temporary file. Supply an empty string when BIOS
authentication is not needed.

.PARAMETER hpia_installation_category
HPIA recommendation category to analyze or install. Accepted values: All, Accessories,
BIOS, Drivers, Firmware, Software, or Drivers,Firmware. All excludes Accessories.

.PARAMETER show_in_progress_campaign
Controls the optional installation-in-progress campaign. Accepted text values: True
or False. The campaign is considered only in Install mode after auto-installable
recommendations are found. Scan mode and already-compliant runs never trigger it.

.PARAMETER update_in_progress_campaign_id
NQL ID (recommended) or UID of the published non-blocking campaign to trigger before
installation. Used only when show_in_progress_campaign is True and installation is
needed. An empty value or campaign delivery failure produces a warning but does not
block remediation.

.PARAMETER maximum_delay_in_seconds
Maximum random startup delay, from 0 through 600 seconds. The action waits a random
whole number of seconds between zero and this value before acquiring the HPIA mutex.
Use 0 to disable jitter.

.OUTPUTS
hpia_mode (String): Requested operation, Scan or Install.

hpia_installation_category (String): Requested HPIA category.

all_updates_applied_successfully (Boolean): True only when Install mode completes and
no selected auto-installable recommendation requires further pre-reboot work. False in
Scan mode and on failures. This does not mean non-auto-installable updates were installed.

reboot_required (Boolean): True when installation reports that a reboot is required or
the exact HP updater log confirms a previously staged flash is awaiting reboot. Otherwise
False.

list_of_updated_drivers (StringList): Deduplicated display names of auto-installable
driver recommendations handled by a successful installation attempt. Contains '-' when
no driver name is reported. Each value is limited to 1024 UTF-8 bytes.

last_successful_scan (DateTime): UTC time of the most recent successful HPIA analysis in
this execution. Uses 1970-01-01 00:00:00 UTC when no analysis completed successfully.

number_total_updates (UInt32): Total recommendations found by the initial analysis,
across BIOS, Drivers, Firmware, Software, and Accessories.

number_accessories_updates (UInt32): Accessory recommendations found by the initial
analysis.

number_bios_updates (UInt32): BIOS recommendations found by the initial analysis.

number_driver_updates (UInt32): Driver recommendations found by the initial analysis.

number_firmware_updates (UInt32): Firmware recommendations found by the initial analysis.

number_software_updates (UInt32): Software recommendations found by the initial analysis.

number_ssm_compliant_updates (UInt32): Auto-installable, SSM-compliant recommendations
found by the initial analysis.

number_non_ssm_updates (UInt32): Non-auto-installable recommendations found by the
initial analysis. These are reported but not installed unattended.

number_bios_settings_drift (UInt32): Sum of mismatched, added, and missing BIOS settings
reported in the HPIA analysis summary.

.NOTES
    ===========================================================================
    Organization:   synit.io
    Pwsh:           PowerShell 5.1
    Dependencies:   nxtremoteactions.dll; nxtcampaignaction.dll
    Exit codes:     0 = success; 1 = environment, input, download, validation, HPIA, verification, or output failure
    Signing:        Production deployment requires an approved Authenticode signature and timestamp.
    ===========================================================================
#>

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Scan')]
    [string]$hpia_mode,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:\.\d+)?$')]
    [string]$hpia_required_version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$hpia_installer_sha256,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$hpia_tool_download_url,

    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$hpia_encoded_bios_password,

    [Parameter(Mandatory = $true)]
    [ValidateSet('All', 'Accessories', 'BIOS', 'Drivers', 'Firmware', 'Software', 'Drivers,Firmware')]
    [string]$hpia_installation_category,

    [Parameter(Mandatory = $true)]
    [ValidateSet('True', 'False')]
    [string]$show_in_progress_campaign,

    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$update_in_progress_campaign_id,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 600)]
    [int]$maximum_delay_in_seconds
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\;$env:Path"

$ERROR_EXCEPTION_TYPE = @{
    Environment = '[Environment error]'
    Input       = '[Input error]'
    Internal    = '[Internal error]'
    Network     = '[Network error]'
}
Set-Variable -Name 'ERROR_EXCEPTION_TYPE' -Option ReadOnly -Scope Script -Force

$LOG_REMOTE_ACTION_NAME = 'Nexthink-InvokeInstallHPUpdates'
$REMOTE_ACTION_TIMEOUT_SEC = 7200
$FINALIZATION_RESERVE_SEC = 300
$WORKFLOW_TIMEOUT_SEC = $REMOTE_ACTION_TIMEOUT_SEC - $FINALIZATION_RESERVE_SEC
$DOWNLOAD_TIMEOUT_SEC = 300
$EXTRACTION_TIMEOUT_SEC = 300
$HPIA_SCAN_TIMEOUT_SEC = 1200
$HPIA_INSTALL_TIMEOUT_SEC = 2700
$HPIA_BIOS_PREPARE_TIMEOUT_SEC = 1200
$HPIA_BIOS_INSTALL_TIMEOUT_SEC = 2700
$HPIA_STARTUP_TIMEOUT_SEC = 180
$PROCESS_PROGRESS_INTERVAL_SEC = 60
$HPIA_DEBUG_LOG_FILE_NAME = 'HP Image Assistant.log'
$HPIA_EXTRACTION_SUCCESS_EXIT_CODES = @(0, 1168)
$SOFTPAQ_EXTRACTION_SUCCESS_EXIT_CODES = @(0, 1168)
$HPIA_MUTEX_NAME = 'Global\Nexthink-InvokeInstallHPUpdates'
$NXT_PATH = 'C:\ProgramData\NexthinkAppData'
$TEMP_FOLDER = Join-Path $NXT_PATH 'hp'
$HPIA_ROOT_FOLDER = Join-Path $TEMP_FOLDER 'hpia'
$HPIA_INSTALLER_CACHE_FOLDER = Join-Path $TEMP_FOLDER 'hpia-installer-cache'
$HPIA_INSTALLER_PATH = Join-Path $HPIA_INSTALLER_CACHE_FOLDER 'hp-hpia.exe'
$HP_IMAGE_ASSISTANT_EXE = 'HPImageAssistant.exe'
$HPIA_REQUIRED_APPLICATION_FILES = @(
    'HPImageAssistant.exe',
    'HPImageAssistant.dll',
    'HPImageAssistant.dll.config',
    'ImageCapture.exe'
)

# Assigned per execution after the mutex is acquired.
$RUN_FOLDER = $null
$HP_REPORT_FOLDER = $null
$HP_LOG_FOLDER = $null
$HP_DOWNLOAD_FOLDER = $null
$HP_EXTRACT_FOLDER = $null
$RUN_FOLDER_CLEANUP_ALLOWED = $true
$NXT_LOG_FILE = $null
$WORKFLOW_DEADLINE_UTC = $null

$DEFAULT_DATE = [datetime]::SpecifyKind([datetime]'1970-01-01T00:00:00', [DateTimeKind]::Utc)

function Invoke-Main {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $exitCode = 1
    $loggingStarted = $false
    $mutex = $null
    $mutexAcquired = $false
    $returnData = Get-HPIAReturnData -InputParameters $InputParameters
    $script:WORKFLOW_DEADLINE_UTC = [DateTime]::UtcNow.AddSeconds($WORKFLOW_TIMEOUT_SEC)

    try {
        Initialize-NxtLogging -RemoteActionName $LOG_REMOTE_ACTION_NAME
        $loggingStarted = $true

        Assert-ExecutionEnvironment
        Add-NexthinkDLL
        Assert-InputParameter -InputParameters $InputParameters

        $isInstallMode = $InputParameters.hpia_mode -eq 'Install'
        $campaignEnabled = $isInstallMode -and $InputParameters.show_in_progress_campaign -eq 'True'

        Wait-RandomTime -MaximumDelayInSeconds $InputParameters.maximum_delay_in_seconds

        $mutex = New-Object -TypeName System.Threading.Mutex -ArgumentList $false, $HPIA_MUTEX_NAME
        try {
            $mutexAcquired = $mutex.WaitOne(0, $false)
        } catch [System.Threading.AbandonedMutexException] {
            $mutexAcquired = $true
            Write-NxtLog -Message 'Recovered abandoned HPIA execution mutex.'
        }

        if (-not $mutexAcquired) {
            throw "$($ERROR_EXCEPTION_TYPE.Environment) Another HPIA Remote Action is already running."
        }

        Assert-NoExistingHPIAProcess

        Initialize-RunDirectory
        $hpiaExePath = Get-OrUpdateHPIA -InputParameters $InputParameters

        $updatesAvailable = Invoke-HPIAScan `
            -ExePath $hpiaExePath `
            -InputParameters $InputParameters `
            -ReturnData $returnData

        if ($InputParameters.hpia_mode -eq 'Scan') {
            Write-NxtLog -Message 'Scan completed. No remediation was requested.'
        } elseif ($updatesAvailable) {
            if ($campaignEnabled) {
                if ([string]::IsNullOrWhiteSpace($InputParameters.update_in_progress_campaign_id)) {
                    Write-Warning 'In-progress campaign display is enabled but no campaign ID was supplied; installation will continue without a campaign.'
                } else {
                    try {
                        Add-NexthinkCampaignDLL
                        Invoke-InProgressCampaign -CampaignId $InputParameters.update_in_progress_campaign_id
                    } catch {
                        Write-Warning "Could not display optional in-progress campaign; installation will continue: $($_.Exception.Message)"
                    }
                }
            }

            $installResult = @{
                RebootRequired           = $false
                NonAutoInstallableSkipped = $false
                InstallationAttempted     = $false
            }
            $nonBIOSCategory = Get-HPIANonBIOSInstallCategory `
                -InstallationCategory $InputParameters.hpia_installation_category
            $nonBIOSRecommendationCount = $returnData.number_ssm_compliant_updates -
            $returnData.number_auto_installable_bios_recommendations

            if (-not [string]::IsNullOrWhiteSpace($nonBIOSCategory) -and $nonBIOSRecommendationCount -gt 0) {
                $nonBIOSResult = Invoke-HPIAInstall `
                    -ExePath $hpiaExePath `
                    -InputParameters $InputParameters `
                    -InstallationCategory $nonBIOSCategory
                Merge-HPIAInstallResult -Target $installResult -Source $nonBIOSResult
            }

            if ($returnData.auto_installable_bios_softpaqs.Count -gt 0) {
                $biosResult = Invoke-HPIABIOSInstall `
                    -ExePath $hpiaExePath `
                    -InputParameters $InputParameters `
                    -SoftPaqs $returnData.auto_installable_bios_softpaqs
                Merge-HPIAInstallResult -Target $installResult -Source $biosResult
            }

            if (-not $installResult.InstallationAttempted) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA reported auto-installable recommendations, but no bounded installation phase was selected."
            }
            $returnData.reboot_required = $installResult.RebootRequired

            if ($installResult.RebootRequired) {
                Write-NxtLog -Message 'HP update installation reported reboot required; final applicability verification is deferred until after reboot.'
            } else {
                Initialize-HPIAReportFolder

                $verificationData = Get-HPIAReturnData -InputParameters $InputParameters
                $updatesRemain = Invoke-HPIAScan `
                    -ExePath $hpiaExePath `
                    -InputParameters $InputParameters `
                    -ReturnData $verificationData

                if ($updatesRemain) {
                    throw "$($ERROR_EXCEPTION_TYPE.Internal) Post-install verification found $($verificationData.number_ssm_compliant_updates) auto-installable recommendation(s) still applicable."
                }

                $returnData.month_and_year_updates_were_scanned = $verificationData.month_and_year_updates_were_scanned
                Write-NxtLog -Message 'Post-install scan verified no selected auto-installable recommendations remain.'
            }

            $returnData.all_updates_applied_successfully = $true
            if ($installResult.InstallationAttempted) {
                $returnData.updated_drivers = @($returnData.auto_installable_driver_names)
            }

            if ($installResult.NonAutoInstallableSkipped) {
                Write-Warning 'HPIA skipped at least one non-auto-installable SoftPaq; selected auto-installable recommendations were handled successfully.'
            }
        } else {
            $returnData.all_updates_applied_successfully = $true
            if ($returnData.number_non_ssm_updates -gt 0) {
                Write-NxtLog -Message "$($returnData.number_non_ssm_updates) recommendation(s) require non-automatic handling; no unattended installation attempted."
            } else {
                Write-NxtLog -Message 'No applicable updates were available.'
            }
        }

        $exitCode = 0
    } catch {
        $exitCode = 1
        $errorMessage = "Remote Action failed: $($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)."
        Write-NxtLog -Message $errorMessage
        Write-Error -Message $errorMessage -ErrorAction Continue
    } finally {
        try {
            Write-HPIALogTail
        } catch {
            Write-Warning "Could not capture HPIA log tail: $($_.Exception.Message)"
        }

        try {
            Write-EngineOutputVariable -Outputs $returnData
        } catch {
            $exitCode = 1
            $outputError = "Failed to write Nexthink outputs: $($_.Exception.Message)"
            Write-NxtLog -Message $outputError
            Write-Error -Message $outputError -ErrorAction Continue
        }

        Invoke-RunFolderCleanup

        if ($mutexAcquired -and $null -ne $mutex) {
            try {
                $mutex.ReleaseMutex()
            } catch {
                $exitCode = 1
                Write-Error -Message "Failed to release HPIA mutex: $($_.Exception.Message)" -ErrorAction Continue
            }
        }
        if ($null -ne $mutex) {
            try {
                $mutex.Dispose()
            } catch {
                $exitCode = 1
                Write-Error -Message "Failed to dispose HPIA mutex: $($_.Exception.Message)" -ErrorAction Continue
            }
        }

        if ($loggingStarted) {
            try {
                Complete-NxtLogging -Result $exitCode
            } catch {
                $exitCode = 1
                Write-Error -Message "Failed to finalize Nexthink logging: $($_.Exception.Message)" -ErrorAction Continue
            }
        }
    }

    return $exitCode
}

function Get-HPIAReturnData {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    return @{
        hpia_mode                           = $InputParameters.hpia_mode
        hpia_installation_category          = $InputParameters.hpia_installation_category
        all_updates_applied_successfully    = $false
        updated_drivers                     = @()
        reboot_required                     = $false
        month_and_year_updates_were_scanned = $DEFAULT_DATE
        number_total_updates                = 0
        number_driver_updates               = 0
        number_bios_updates                 = 0
        number_firmware_updates             = 0
        number_software_updates             = 0
        number_accessories_updates          = 0
        number_bios_settings_drift          = 0
        number_ssm_compliant_updates        = 0
        number_non_ssm_updates              = 0
        auto_installable_driver_names       = @()
        auto_installable_bios_softpaqs       = @()
        number_auto_installable_bios_recommendations = 0
    }
}

function Assert-InputParameter {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $uri = $null
    if (-not [uri]::TryCreate($InputParameters.hpia_tool_download_url, [UriKind]::Absolute, [ref]$uri)) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) HPIA download URL is not an absolute URI."
    }
    if ($uri.Scheme -ne 'https') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) HPIA download URL must use HTTPS."
    }
    if ($uri.Query -or $uri.Fragment) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) HPIA download URL must not contain a query or fragment."
    }
    if (-not [string]::IsNullOrWhiteSpace($uri.UserInfo)) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) HPIA download URL must not contain embedded credentials."
    }
    $parsedVersion = $null
    if (-not [version]::TryParse($InputParameters.hpia_required_version, [ref]$parsedVersion) -or
        $parsedVersion.Build -lt 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) HPIA version must contain three or four numeric components."
    }

    $publicHPHosts = @('hpia.hpcloud.hp.com', 'ftp.hp.com', 'ftp.ext.hp.com')
    if ($publicHPHosts -contains $uri.DnsSafeHost) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Public HP download hosts are not allowed. Configure the internal HPIA mirror."
    }

    $categories = @($InputParameters.hpia_installation_category -split ',')
    $isInstallMode = $InputParameters.hpia_mode -eq 'Install'
    if ($isInstallMode -and
        ($categories -contains 'BIOS' -or $categories -contains 'All') -and
        -not [string]::IsNullOrWhiteSpace($InputParameters.hpia_encoded_bios_password)) {
        Assert-BIOSPasswordData -EncodedData $InputParameters.hpia_encoded_bios_password
    }

}

function Assert-ExecutionEnvironment {
    if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Full Language Mode is required; current mode is '$($ExecutionContext.SessionState.LanguageMode)'."
    }

    foreach ($environmentVariableName in @('NEXTHINK', 'SystemRoot', 'ProgramData')) {
        $environmentVariableValue = [Environment]::GetEnvironmentVariable($environmentVariableName)
        if ([string]::IsNullOrWhiteSpace($environmentVariableValue)) {
            throw "$($ERROR_EXCEPTION_TYPE.Environment) Required environment variable '$environmentVariableName' is not defined."
        }
    }

    $identity = $null
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "$($ERROR_EXCEPTION_TYPE.Environment) Administrator privileges are required to install HP updates."
        }
    } finally {
        if ($null -ne $identity) {
            $identity.Dispose()
        }
    }
}

function Assert-BIOSPasswordData {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EncodedData
    )

    $decodedData = $null
    try {
        $decodedData = [Convert]::FromBase64String($EncodedData)
        if ($decodedData.Length -eq 0) {
            throw "$($ERROR_EXCEPTION_TYPE.Input) BIOS password data decoded to an empty file."
        }
    } catch [System.FormatException] {
        throw "$($ERROR_EXCEPTION_TYPE.Input) BIOS password data is not valid base64-encoded HPQPwd file content."
    } finally {
        if ($null -ne $decodedData) {
            [Array]::Clear($decodedData, 0, $decodedData.Length)
        }
    }
}

function Initialize-RunDirectory {
    if (-not (Test-Path -LiteralPath $NXT_PATH)) {
        [void](New-Item -Path $NXT_PATH -ItemType Directory -Force)
    }
    if (-not (Test-Path -LiteralPath $TEMP_FOLDER)) {
        [void](New-Item -Path $TEMP_FOLDER -ItemType Directory -Force)
    }
    Assert-DirectoryIsNotReparsePoint -Path $TEMP_FOLDER
    Protect-SecureFolderAcl -FolderPath $TEMP_FOLDER

    if (-not (Test-Path -LiteralPath $HPIA_ROOT_FOLDER)) {
        [void](New-Item -Path $HPIA_ROOT_FOLDER -ItemType Directory -Force)
    }
    Assert-DirectoryIsNotReparsePoint -Path $HPIA_ROOT_FOLDER
    Protect-SecureFolderAcl -FolderPath $HPIA_ROOT_FOLDER

    if (-not (Test-Path -LiteralPath $HPIA_INSTALLER_CACHE_FOLDER)) {
        [void](New-Item -Path $HPIA_INSTALLER_CACHE_FOLDER -ItemType Directory -Force)
    }
    Assert-DirectoryIsNotReparsePoint -Path $HPIA_INSTALLER_CACHE_FOLDER
    Protect-SecureFolderAcl -FolderPath $HPIA_INSTALLER_CACHE_FOLDER

    $staleRunFolders = @(Get-ChildItem -LiteralPath $TEMP_FOLDER -Directory -Filter 'run-*' -ErrorAction SilentlyContinue | Select-Object -First 50)
    foreach ($staleRunFolder in $staleRunFolders) {
        $preserveMarker = Join-Path $staleRunFolder.FullName '.cleanup-blocked'
        if (Test-Path -LiteralPath $preserveMarker -PathType Leaf) {
            Write-Warning "Preserving stale HPIA run folder '$($staleRunFolder.FullName)' because prior process-tree termination was uncertain."
            continue
        }
        try {
            Invoke-LongPathDirectoryCleanup -Path $staleRunFolder.FullName -AllowedRoot $TEMP_FOLDER
            Write-NxtLog -Message "Removed stale HPIA run folder '$($staleRunFolder.Name)'."
        } catch {
            Write-Warning "Could not remove stale HPIA run folder '$($staleRunFolder.FullName)': $($_.Exception.Message)"
        }
    }

    $script:RUN_FOLDER = Join-Path $TEMP_FOLDER ('run-{0}' -f [guid]::NewGuid().ToString('N'))
    $script:RUN_FOLDER_CLEANUP_ALLOWED = $true
    $script:HP_REPORT_FOLDER = Join-Path $RUN_FOLDER 'reports'
    $script:HP_LOG_FOLDER = Join-Path $RUN_FOLDER 'logs'
    $script:HP_DOWNLOAD_FOLDER = Join-Path $RUN_FOLDER 'downloads'
    $script:HP_EXTRACT_FOLDER = Join-Path $RUN_FOLDER 'extract'

    foreach ($folder in @($RUN_FOLDER, $HP_REPORT_FOLDER, $HP_LOG_FOLDER, $HP_DOWNLOAD_FOLDER, $HP_EXTRACT_FOLDER)) {
        [void](New-Item -Path $folder -ItemType Directory -Force)
    }
}

function Get-OrUpdateHPIA {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $expectedExePath = Join-Path $HPIA_ROOT_FOLDER $HP_IMAGE_ASSISTANT_EXE
    $installerValid = Test-HPIAInstaller `
        -Path $HPIA_INSTALLER_PATH `
        -ExpectedSHA256 $InputParameters.hpia_installer_sha256

    if ($installerValid -and
        (Test-HPIADistribution -RootPath $HPIA_ROOT_FOLDER) -and
        (Test-HPIAExecutable -Path $expectedExePath -RequiredVersion $InputParameters.hpia_required_version)) {
        $cachedExe = Get-Item -LiteralPath $expectedExePath
        Write-NxtLog -Message "Using cached signed HPIA $($cachedExe.VersionInfo.FileVersion) with matching installer hash."
        return $cachedExe.FullName
    }

    try {
        if (-not $installerValid) {
            $baseUrl = $InputParameters.hpia_tool_download_url.TrimEnd('/')
            $downloadUrl = "$baseUrl/hp-hpia-$($InputParameters.hpia_required_version).exe"
            $stagedInstallerPath = Join-Path $RUN_FOLDER 'hp-hpia-download.exe'
            Write-NxtLog -Message 'Downloading required HPIA version from configured internal mirror.'

            Invoke-FileDownload -Url $downloadUrl -Destination $stagedInstallerPath -TimeoutSeconds $DOWNLOAD_TIMEOUT_SEC
            Assert-FileHash -Path $stagedInstallerPath -ExpectedSHA256 $InputParameters.hpia_installer_sha256
            Assert-HPAuthenticodeSignature -Path $stagedInstallerPath

            Remove-Item -LiteralPath $HPIA_INSTALLER_PATH -Force -ErrorAction SilentlyContinue
            Move-Item -LiteralPath $stagedInstallerPath -Destination $HPIA_INSTALLER_PATH
        } else {
            Write-NxtLog -Message 'Rebuilding the HPIA application directory from the validated cached installer.'
        }

        if (Test-Path -LiteralPath $HPIA_ROOT_FOLDER) {
            Remove-Item -LiteralPath $HPIA_ROOT_FOLDER -Recurse -Force
        }
        [void](New-Item -Path $HPIA_ROOT_FOLDER -ItemType Directory -Force)
        Assert-DirectoryIsNotReparsePoint -Path $HPIA_ROOT_FOLDER
        Protect-SecureFolderAcl -FolderPath $HPIA_ROOT_FOLDER

        $extractArguments = "/s /e /f `"$HPIA_ROOT_FOLDER`""
        $extractExitCode = Invoke-ProcessWithTimeout `
            -FilePath $HPIA_INSTALLER_PATH `
            -Arguments $extractArguments `
            -TimeoutSeconds $EXTRACTION_TIMEOUT_SEC `
            -CaptureOutput

        if ($HPIA_EXTRACTION_SUCCESS_EXIT_CODES -notcontains $extractExitCode) {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA extraction failed with exit code $extractExitCode."
        }
        if ($extractExitCode -eq 1168) {
            Write-Warning 'HPIA SoftPaq wrapper returned exit code 1168; validating extracted artifacts before continuing.'
        }

        Wait-HPIADistributionReady -RootPath $HPIA_ROOT_FOLDER -TimeoutSeconds 30
        $exePath = Join-Path $HPIA_ROOT_FOLDER $HP_IMAGE_ASSISTANT_EXE
        Assert-HPIAExecutable -Path $exePath -RequiredVersion $InputParameters.hpia_required_version
        $extractedExe = Get-Item -LiteralPath $exePath
        Write-NxtLog -Message "Prepared signed HPIA $($extractedExe.VersionInfo.FileVersion) in an isolated application directory."
        return $exePath
    } catch {
        if ($RUN_FOLDER_CLEANUP_ALLOWED) {
            Remove-Item -LiteralPath $HPIA_ROOT_FOLDER -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Warning "Preserving HPIA tool root '$HPIA_ROOT_FOLDER' because process-tree termination could not be confirmed."
        }
        throw
    }
}

function Invoke-FileDownload {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [Parameter(Mandatory = $true)]
        [string]$Destination,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1800)]
        [int]$TimeoutSeconds,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName = 'HPIA installer from internal mirror'
    )

    $effectiveTimeoutSeconds = Get-EffectiveProcessTimeout `
        -MaximumSeconds $TimeoutSeconds `
        -OperationName "$OperationName download"
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -TimeoutSec $effectiveTimeoutSeconds -ErrorAction Stop
    } catch {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        throw "$($ERROR_EXCEPTION_TYPE.Network) Failed to download ${OperationName}: $($_.Exception.Message)"
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol
    }
}

function Invoke-ProcessWithTimeout {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Arguments,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds,
        [switch]$CaptureOutput
    )

    if ($FilePath.IndexOfAny([char[]]@('"', "`r", "`n")) -ge 0 -or
        $Arguments.IndexOfAny([char[]]@("`r", "`n")) -ge 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Native process path or arguments contain unsupported control characters."
    }

    $processName = [System.IO.Path]::GetFileName($FilePath)
    $effectiveTimeoutSeconds = Get-EffectiveProcessTimeout `
        -MaximumSeconds $TimeoutSeconds `
        -OperationName "Native process '$processName'"
    $process = $null
    $processId = [guid]::NewGuid().ToString('N')
    $standardOutputPath = $null
    $standardErrorPath = $null
    try {
        $workingDirectory = [System.IO.Path]::GetDirectoryName($FilePath)
        if ($CaptureOutput) {
            $standardOutputPath = Join-Path $RUN_FOLDER "process-$processId.stdout.log"
            $standardErrorPath = Join-Path $RUN_FOLDER "process-$processId.stderr.log"

            # Start-Process may expose a blank ExitCode on Windows PowerShell 5.1
            # when it owns redirected streams. ProcessStartInfo preserves the native
            # exit code and writes the extractor's bounded diagnostics to files.
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $FilePath
            $startInfo.Arguments = $Arguments
            $startInfo.WorkingDirectory = $workingDirectory
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $startInfo
            if (-not $process.Start()) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) Failed to start native process '$FilePath'."
            }
            $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
            $standardErrorTask = $process.StandardError.ReadToEndAsync()
        } else {
            # HPIA owns its diagnostic log. Launch it directly from its application
            # directory so the tracked PID is the native HPIA launcher, not a shell.
            $process = Start-Process `
                -FilePath $FilePath `
                -ArgumentList $Arguments `
                -WorkingDirectory $workingDirectory `
                -WindowStyle Hidden `
                -PassThru `
                -ErrorAction Stop
        }

        $processStartedUtc = [DateTime]::UtcNow
        $processDeadlineUtc = $processStartedUtc.AddSeconds($effectiveTimeoutSeconds)
        $nextProgressUtc = $processStartedUtc.AddSeconds($PROCESS_PROGRESS_INTERVAL_SEC)
        $completed = $false
        while ([DateTime]::UtcNow -lt $processDeadlineUtc) {
            $remainingMilliseconds = [int][Math]::Min(
                15000,
                [Math]::Max(1, [Math]::Ceiling(($processDeadlineUtc - [DateTime]::UtcNow).TotalMilliseconds))
            )
            if ($process.WaitForExit($remainingMilliseconds)) {
                $completed = $true
                break
            }

            $elapsedSeconds = [int][Math]::Floor(([DateTime]::UtcNow - $processStartedUtc).TotalSeconds)
            if ($processName -eq $HP_IMAGE_ASSISTANT_EXE -and
                $elapsedSeconds -ge $HPIA_STARTUP_TIMEOUT_SEC -and
                -not (Test-HPIALogCreated)) {
                Invoke-ProcessTreeTermination -Process $process -FilePath $FilePath
                throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA did not initialize or create a debug log within $HPIA_STARTUP_TIMEOUT_SEC seconds. The isolated application directory was validated; check endpoint security controls and run the signed HPIA executable locally as administrator for comparison."
            }

            if ([DateTime]::UtcNow -ge $nextProgressUtc) {
                $activitySummary = Get-HPIALogActivitySummary
                Write-NxtLog -Message "Native process '$processName' (PID $($process.Id)) is still running after $elapsedSeconds second(s); $activitySummary"
                $nextProgressUtc = [DateTime]::UtcNow.AddSeconds($PROCESS_PROGRESS_INTERVAL_SEC)
            }
        }

        if (-not $completed) {
            try {
                Invoke-ProcessTreeTermination -Process $process -FilePath $FilePath
            } finally {
                if ($CaptureOutput) {
                    Complete-ProcessOutputCapture `
                        -StandardOutputTask $standardOutputTask `
                        -StandardErrorTask $standardErrorTask `
                        -StandardOutputPath $standardOutputPath `
                        -StandardErrorPath $standardErrorPath
                }
            }
            throw "$($ERROR_EXCEPTION_TYPE.Internal) Process '$FilePath' exceeded its effective timeout of $effectiveTimeoutSeconds seconds and was terminated."
        }

        # Ensure redirected streams have fully flushed after process termination.
        $process.WaitForExit()
        if ($CaptureOutput) {
            Complete-ProcessOutputCapture `
                -StandardOutputTask $standardOutputTask `
                -StandardErrorTask $standardErrorTask `
                -StandardOutputPath $standardOutputPath `
                -StandardErrorPath $standardErrorPath
        }
        return $process.ExitCode
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Complete-ProcessOutputCapture {
    param (
        [Parameter(Mandatory = $true)]
        [System.Threading.Tasks.Task[string]]$StandardOutputTask,
        [Parameter(Mandatory = $true)]
        [System.Threading.Tasks.Task[string]]$StandardErrorTask,
        [Parameter(Mandatory = $true)]
        [string]$StandardOutputPath,
        [Parameter(Mandatory = $true)]
        [string]$StandardErrorPath
    )

    $captureTasks = @($StandardOutputTask, $StandardErrorTask)
    foreach ($captureTask in $captureTasks) {
        if (-not $captureTask.Wait(5000)) {
            Write-Warning 'Timed out while draining a native process diagnostic stream.'
        }
    }

    if ($StandardOutputTask.IsCompleted -and -not $StandardOutputTask.IsFaulted) {
        Write-BoundedProcessOutput -Path $StandardOutputPath -Content $StandardOutputTask.Result
    }
    if ($StandardErrorTask.IsCompleted -and -not $StandardErrorTask.IsFaulted) {
        Write-BoundedProcessOutput -Path $StandardErrorPath -Content $StandardErrorTask.Result
    }

    Write-ProcessDiagnosticTail -Path $StandardOutputPath -StreamName 'stdout'
    Write-ProcessDiagnosticTail -Path $StandardErrorPath -StreamName 'stderr'
}

function Write-BoundedProcessOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [AllowEmptyString()]
        [string]$Content
    )

    $maximumCharacters = 65536
    if ($Content.Length -gt $maximumCharacters) {
        $Content = $Content.Substring($Content.Length - $maximumCharacters)
    }
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.Encoding]::UTF8)
}

function Get-EffectiveProcessTimeout {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 86400)]
        [int]$MaximumSeconds,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OperationName
    )

    if ($null -eq $WORKFLOW_DEADLINE_UTC) {
        return $MaximumSeconds
    }

    $remainingSeconds = [int][Math]::Floor(($WORKFLOW_DEADLINE_UTC - [DateTime]::UtcNow).TotalSeconds)
    if ($remainingSeconds -lt 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Internal workflow deadline was exhausted before $OperationName could start."
    }

    return [int][Math]::Min($MaximumSeconds, $remainingSeconds)
}

function Get-HPIALogActivitySummary {
    $debugLogPath = Get-HPIADebugLogPath
    if ([string]::IsNullOrWhiteSpace($debugLogPath)) {
        return 'the HPIA log folder does not exist yet.'
    }

    if (-not (Test-Path -LiteralPath $debugLogPath -PathType Leaf)) {
        return "HPIA has not created '$HPIA_DEBUG_LOG_FILE_NAME' yet."
    }

    $debugLog = Get-Item -LiteralPath $debugLogPath
    $ageSeconds = [int][Math]::Max(0, [Math]::Floor(([DateTime]::UtcNow - $debugLog.LastWriteTimeUtc).TotalSeconds))
    return "HPIA debug log '$($debugLog.Name)' has $($debugLog.Length) byte(s) and was updated $ageSeconds second(s) ago."
}

function Test-HPIALogCreated {
    $debugLogPath = Get-HPIADebugLogPath
    return -not [string]::IsNullOrWhiteSpace($debugLogPath) -and
    (Test-Path -LiteralPath $debugLogPath -PathType Leaf)
}

function Get-HPIADebugLogPath {
    if ([string]::IsNullOrWhiteSpace($HP_LOG_FOLDER) -or
        -not (Test-Path -LiteralPath $HP_LOG_FOLDER -PathType Container)) {
        return ''
    }
    return (Join-Path $HP_LOG_FOLDER $HPIA_DEBUG_LOG_FILE_NAME)
}

function Write-ProcessDiagnosticTail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateSet('stdout', 'stderr')]
        [string]$StreamName
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    try {
        foreach ($line in @(Get-Content -LiteralPath $Path -Tail 20 -ErrorAction Stop)) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Write-NxtLog -Message "[process $StreamName] $line"
            }
        }
    } catch {
        Write-Warning "Could not read captured process ${StreamName}: $($_.Exception.Message)"
    }
}

function Invoke-ProcessTreeTermination {
    param (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    if ($Process.HasExited) {
        return
    }

    $taskKillFailure = Invoke-TaskKill -ProcessId $Process.Id

    if (-not $Process.WaitForExit(30000)) {
        try {
            $Process.Kill()
        } catch {
            $taskKillFailure = "$taskKillFailure; direct termination failed: $($_.Exception.Message)".TrimStart(';', ' ')
        }
    }

    if (-not $Process.WaitForExit(30000) -or -not $Process.HasExited) {
        $script:RUN_FOLDER_CLEANUP_ALLOWED = $false
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Timed-out process '$FilePath' could not be terminated. $taskKillFailure"
    }

    if (-not [string]::IsNullOrWhiteSpace($taskKillFailure)) {
        $script:RUN_FOLDER_CLEANUP_ALLOWED = $false
        Write-Warning "Process tree termination required fallback handling: $taskKillFailure"
    }
}

function Invoke-TaskKill {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    if (-not (Test-Path -LiteralPath $taskKill -PathType Leaf)) {
        return "taskkill.exe was not found at '$taskKill'"
    }

    $taskKillProcess = $null
    try {
        $taskKillProcess = Start-Process `
            -FilePath $taskKill `
            -ArgumentList "/PID $ProcessId /T /F" `
            -WindowStyle Hidden `
            -PassThru `
            -ErrorAction Stop

        if (-not $taskKillProcess.WaitForExit(30000)) {
            try {
                $taskKillProcess.Kill()
            } catch {
                return "taskkill.exe timed out and could not be terminated: $($_.Exception.Message)"
            }
            return 'taskkill.exe timed out.'
        }
        if ($taskKillProcess.ExitCode -ne 0) {
            return "taskkill.exe returned exit code $($taskKillProcess.ExitCode)"
        }
        return ''
    } catch {
        return "taskkill.exe failed: $($_.Exception.Message)"
    } finally {
        if ($null -ne $taskKillProcess) {
            $taskKillProcess.Dispose()
        }
    }
}

function Assert-NoExistingHPIAProcess {
    $existingProcesses = @(
        Get-Process -Name 'HPImageAssistant', 'hp-hpia', 'HpFirmwareUpdRec', 'HpFirmwareUpdRec64' -ErrorAction SilentlyContinue |
            Select-Object -First 10
    )
    if ($existingProcesses.Count -gt 0) {
        $processSummary = @($existingProcesses | ForEach-Object { "$($_.ProcessName) PID $($_.Id)" }) -join ', '
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Refusing to start while an existing HP update process is running ($processSummary)."
    }
}

function Assert-HPAuthenticodeSignature {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Invalid Authenticode signature on '$Path': $($signature.StatusMessage)"
    }

    $subject = $signature.SignerCertificate.Subject
    if ($subject -notmatch '(?i)HP Inc\.|Hewlett-Packard') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Unexpected HPIA signer: '$subject'."
    }
}

function Assert-FileHash {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSHA256
    )

    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actualHash -ne $ExpectedSHA256) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) SHA-256 mismatch for '$Path'."
    }
}

function Assert-HPIAExecutable {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA executable not found at '$Path'."
    }
    Assert-HPIAPath -Path $Path

    Assert-HPAuthenticodeSignature -Path $Path

    $fileVersionText = (Get-Item -LiteralPath $Path).VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($fileVersionText)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA executable has no file version."
    }

    $actualVersion = [version]$fileVersionText
    $required = [version]$RequiredVersion
    $versionMatches = $actualVersion.Major -eq $required.Major -and
    $actualVersion.Minor -eq $required.Minor -and
    $actualVersion.Build -eq $required.Build

    if ($required.Revision -ge 0) {
        $versionMatches = $versionMatches -and $actualVersion.Revision -eq $required.Revision
    }

    if (-not $versionMatches) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA version '$fileVersionText' does not match required version '$RequiredVersion'."
    }
}

function Assert-HPIAPath {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($HPIA_ROOT_FOLDER).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA executable resolves outside approved tool root."
    }

    $currentItem = Get-Item -LiteralPath $fullPath -Force
    while ($null -ne $currentItem -and
        $currentItem.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA path contains a reparse point: '$($currentItem.FullName)'."
        }
        $currentItem = $currentItem.Parent
    }
}

function Assert-DirectoryIsNotReparsePoint {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $directory = Get-Item -LiteralPath $Path -Force
    if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Protected working directory must not be a reparse point: '$Path'."
    }
}

function Test-HPIAExecutable {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$RequiredVersion
    )

    try {
        Assert-HPIAExecutable -Path $Path -RequiredVersion $RequiredVersion
        return $true
    } catch {
        Write-NxtLog -Message "Ignoring invalid cached HPIA file '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Test-HPIAInstaller {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Fa-f0-9]{64}$')]
        [string]$ExpectedSHA256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    try {
        Assert-FileHash -Path $Path -ExpectedSHA256 $ExpectedSHA256
        Assert-HPAuthenticodeSignature -Path $Path
        return $true
    } catch {
        Write-NxtLog -Message "Ignoring cached HPIA installer '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Test-HPIADistribution {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        return $false
    }

    try {
        Assert-DirectoryIsNotReparsePoint -Path $RootPath
        foreach ($requiredFileName in $HPIA_REQUIRED_APPLICATION_FILES) {
            $requiredFilePath = Join-Path $RootPath $requiredFileName
            if (-not (Test-Path -LiteralPath $requiredFilePath -PathType Leaf)) {
                return $false
            }
            if ((Get-Item -LiteralPath $requiredFilePath).Length -le 0) {
                return $false
            }
        }

        # The SoftPaq installer is not an HPIA application file. Keeping it here
        # makes the native launcher's pre-log security pass inspect/remove it.
        if (Test-Path -LiteralPath (Join-Path $RootPath 'hp-hpia.exe') -PathType Leaf) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

function Wait-HPIADistributionReady {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds
    )

    $deadlineUtc = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $previousSnapshot = $null
    $stableObservations = 0
    do {
        if (Test-HPIADistribution -RootPath $RootPath) {
            $distributionFiles = @(Get-ChildItem -LiteralPath $RootPath -File -Recurse |
                    Sort-Object -Property FullName |
                    Select-Object -First 2001)
            if ($distributionFiles.Count -gt 2000) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) Extracted HPIA application exceeds the 2,000-file validation limit."
            }
            $snapshot = (@($distributionFiles | ForEach-Object {
                        '{0}:{1}:{2}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.Ticks
                    }) -join '|')

            if ($snapshot -eq $previousSnapshot) {
                $stableObservations++
                if ($stableObservations -ge 2) {
                    return
                }
            } else {
                $previousSnapshot = $snapshot
                $stableObservations = 0
            }
        } else {
            $previousSnapshot = $null
            $stableObservations = 0
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadlineUtc)

    $missingFiles = @($HPIA_REQUIRED_APPLICATION_FILES | Where-Object {
            $candidatePath = Join-Path $RootPath $_
            -not (Test-Path -LiteralPath $candidatePath -PathType Leaf) -or
            (Get-Item -LiteralPath $candidatePath).Length -le 0
        })
    $missingSummary = if ($missingFiles.Count -gt 0) {
        " Missing or empty required files: $($missingFiles -join ', ')."
    } else {
        ''
    }
    throw "$($ERROR_EXCEPTION_TYPE.Internal) Extracted HPIA application did not become complete and stable within $TimeoutSeconds second(s).$missingSummary"
}

function Invoke-HPIAScan {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExePath,
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters,
        [Parameter(Mandatory = $true)]
        [hashtable]$ReturnData
    )

    Write-NxtLog -Message 'Starting HPIA analysis.'
    $arguments = "/Operation:Analyze /Category:$($InputParameters.hpia_installation_category) /Selection:All /Action:List /Silent /ReportFolder:`"$HP_REPORT_FOLDER`" /LogFolder:`"$HP_LOG_FOLDER`" /Debug"
    $exitCode = Invoke-ProcessWithTimeout `
        -FilePath $ExePath `
        -Arguments $arguments `
        -TimeoutSeconds $HPIA_SCAN_TIMEOUT_SEC

    switch ($exitCode) {
        0 {
            Read-HPIAAnalysisReport -ReturnData $ReturnData
        }
        256 {
            Write-NxtLog -Message 'HPIA analysis completed with no recommendations.'
        }
        257 {
            Write-NxtLog -Message 'HPIA analysis completed with no selected recommendations.'
        }
        default {
            throw (Get-HPIAFailureMessage -ExitCode $exitCode -Operation 'analysis')
        }
    }

    $ReturnData.month_and_year_updates_were_scanned = (Get-Date).ToUniversalTime()
    return ($ReturnData.number_ssm_compliant_updates -gt 0)
}

function Read-HPIAAnalysisReport {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ReturnData
    )

    $xmlFiles = @(Get-ChildItem -LiteralPath $HP_REPORT_FOLDER -Filter '*.xml' -File | Sort-Object -Property LastWriteTimeUtc -Descending)
    if ($xmlFiles.Count -eq 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA returned success but generated no XML analysis report."
    }
    if ($xmlFiles.Count -gt 1) {
        Write-Warning "HPIA generated multiple XML reports; parsing newest report '$($xmlFiles[0].Name)'."
    }

    try {
        [xml]$xml = Get-Content -LiteralPath $xmlFiles[0].FullName -Raw
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Failed to parse HPIA XML report: $($_.Exception.Message)"
    }

    if ($null -eq $xml.HPIA -or $null -eq $xml.HPIA.Recommendations) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA XML report schema is unsupported: HPIA/Recommendations is missing."
    }

    $biosSettings = $xml.HPIA.Summary.BIOSSettings
    if ($null -ne $biosSettings) {
        $mismatchedCount = ConvertTo-HPIASummaryCount -Value $biosSettings.Mismatched -FieldName 'BIOSSettings.Mismatched'
        $addedCount = ConvertTo-HPIASummaryCount -Value $biosSettings.Added -FieldName 'BIOSSettings.Added'
        $missingCount = ConvertTo-HPIASummaryCount -Value $biosSettings.Missing -FieldName 'BIOSSettings.Missing'
        $ReturnData.number_bios_settings_drift = $mismatchedCount + $addedCount + $missingCount
    }

    $categories = @('BIOS', 'Drivers', 'Firmware', 'Software', 'Accessories')
    foreach ($category in $categories) {
        $nodes = @($xml.SelectNodes("//Recommendations/$category/Recommendation/Solution/Softpaq"))
        foreach ($node in $nodes) {
            $ssmValue = [string]$node.SSMCompliant
            $isSSMCompliant = $false
            if (-not [bool]::TryParse($ssmValue, [ref]$isSSMCompliant)) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA XML report contains unsupported SSMCompliant value '$ssmValue'."
            }

            if ($isSSMCompliant) {
                $ReturnData.number_ssm_compliant_updates++
                if ($category -eq 'Drivers') {
                    $updateName = Get-HPIAUpdateDisplayName -SoftPaqNode $node -Category $category
                    if ($ReturnData.auto_installable_driver_names -notcontains $updateName) {
                        $ReturnData.auto_installable_driver_names += $updateName
                    }
                } elseif ($category -eq 'BIOS') {
                    $ReturnData.number_auto_installable_bios_recommendations++
                    $biosSoftPaq = Get-HPIASoftPaqIdentity -SoftPaqNode $node -Category $category
                    $knownBIOSSoftPaq = @($ReturnData.auto_installable_bios_softpaqs | Where-Object {
                            $_.Number -eq $biosSoftPaq.Number
                        })
                    if ($knownBIOSSoftPaq.Count -eq 0) {
                        $ReturnData.auto_installable_bios_softpaqs += $biosSoftPaq
                    }
                }
            } else {
                $ReturnData.number_non_ssm_updates++
            }

            switch ($category) {
                'BIOS' { $ReturnData.number_bios_updates++ }
                'Drivers' { $ReturnData.number_driver_updates++ }
                'Firmware' { $ReturnData.number_firmware_updates++ }
                'Software' { $ReturnData.number_software_updates++ }
                'Accessories' { $ReturnData.number_accessories_updates++ }
            }
        }
    }

    $ReturnData.number_total_updates = $ReturnData.number_bios_updates +
    $ReturnData.number_driver_updates +
    $ReturnData.number_firmware_updates +
    $ReturnData.number_software_updates +
    $ReturnData.number_accessories_updates

    Write-NxtLog -Message "HPIA found $($ReturnData.number_total_updates) recommendation(s): $($ReturnData.number_ssm_compliant_updates) auto-installable, $($ReturnData.number_non_ssm_updates) non-auto-installable."
}

function Get-HPIASoftPaqIdentity {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SoftPaqNode,
        [Parameter(Mandatory = $true)]
        [ValidateSet('BIOS', 'Drivers', 'Firmware', 'Software', 'Accessories')]
        [string]$Category
    )

    $softPaqId = Get-FirstXmlNodeText `
        -ParentNode $SoftPaqNode `
        -RelativeXPaths @('./Id', './SoftPaqNumber', './Number')
    if ($softPaqId -notmatch '^(?i:sp)?(?<Number>\d{4,8})$') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA $Category recommendation contains unsupported SoftPaq identifier '$softPaqId'."
    }
    $softPaqNumber = $Matches.Number

    return [pscustomobject]@{
        Id     = "sp$softPaqNumber"
        Number = $softPaqNumber
        Name   = Get-HPIAUpdateDisplayName -SoftPaqNode $SoftPaqNode -Category $Category
    }
}

function ConvertTo-HPIASummaryCount {
    param (
        [AllowNull()]
        [object]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FieldName
    )

    $valueText = if ($Value -is [System.Xml.XmlNode]) {
        $Value.InnerText
    } else {
        [string]$Value
    }
    $valueText = $valueText.Trim()

    $count = 0
    if ([int]::TryParse($valueText, [ref]$count) -and $count -ge 0) {
        return $count
    }

    if ([string]::IsNullOrWhiteSpace($valueText) -or $valueText -match '^(?i:N/?A|N/?V|Not Available|Nicht verfügbar|-)$') {
        Write-NxtLog -Message "HPIA summary field '$FieldName' is unavailable ('$valueText'); using 0."
        return 0
    }

    Write-Warning "HPIA summary field '$FieldName' contains non-numeric value '$valueText'; using 0."
    return 0
}

function Get-HPIAUpdateDisplayName {
    param (
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlElement]$SoftPaqNode,
        [Parameter(Mandatory = $true)]
        [ValidateSet('BIOS', 'Drivers', 'Firmware', 'Software', 'Accessories')]
        [string]$Category
    )

    $recommendationNode = $SoftPaqNode.SelectSingleNode('../..')
    $componentName = Get-FirstXmlNodeText `
        -ParentNode $recommendationNode `
        -RelativeXPaths @('./Name', './ComponentName', './Title')

    if ([string]::IsNullOrWhiteSpace($componentName)) {
        $componentName = Get-FirstXmlNodeText `
            -ParentNode $SoftPaqNode `
            -RelativeXPaths @('./Name', './Title')
    }

    $referenceVersion = Get-FirstXmlNodeText `
        -ParentNode $recommendationNode `
        -RelativeXPaths @('./ReferenceVersion', './RecommendationValue')
    $softPaqId = Get-FirstXmlNodeText `
        -ParentNode $SoftPaqNode `
        -RelativeXPaths @('./Id', './SoftPaqNumber', './Number')

    if ([string]::IsNullOrWhiteSpace($componentName)) {
        $componentName = "$Category update"
    }

    $details = @()
    if (-not [string]::IsNullOrWhiteSpace($referenceVersion)) {
        $details += $referenceVersion
    }
    if (-not [string]::IsNullOrWhiteSpace($softPaqId)) {
        $details += $softPaqId
    }

    if ($details.Count -eq 0) {
        return $componentName
    }
    return "$componentName - $($details -join ' - ')"
}

function Get-FirstXmlNodeText {
    param (
        [AllowNull()]
        [System.Xml.XmlNode]$ParentNode,
        [Parameter(Mandatory = $true)]
        [string[]]$RelativeXPaths
    )

    if ($null -eq $ParentNode) {
        return ''
    }

    foreach ($xpath in $RelativeXPaths) {
        $node = $ParentNode.SelectSingleNode($xpath)
        if ($null -ne $node -and -not [string]::IsNullOrWhiteSpace($node.InnerText)) {
            return $node.InnerText.Trim()
        }
    }
    return ''
}

function Invoke-HPIAInstall {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExePath,
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters,
        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Accessories', 'BIOS', 'Drivers', 'Firmware', 'Software', 'Drivers,Firmware', 'Drivers,Firmware,Software')]
        [string]$InstallationCategory
    )

    Write-NxtLog -Message "Starting unattended HPIA installation for category '$InstallationCategory'."
    $biosPasswordArgument = ''
    if ($InstallationCategory -eq 'BIOS' -or $InstallationCategory -eq 'All') {
        $biosPasswordArgument = Get-BIOSPasswordArgument -InputParameters $InputParameters
    }
    $arguments = "/Operation:Analyze /Category:$InstallationCategory /Selection:All /InstallType:AutoInstallable /Action:Install /Silent /ReportFolder:`"$HP_REPORT_FOLDER`" /LogFolder:`"$HP_LOG_FOLDER`" /SoftPaqDownloadFolder:`"$HP_DOWNLOAD_FOLDER`" /SoftPaqExtractFolder:`"$HP_EXTRACT_FOLDER`" /Debug$biosPasswordArgument"
    $exitCode = Invoke-ProcessWithTimeout `
        -FilePath $ExePath `
        -Arguments $arguments `
        -TimeoutSeconds $HPIA_INSTALL_TIMEOUT_SEC

    switch ($exitCode) {
        0 {
            Write-NxtLog -Message 'HPIA installation completed successfully.'
            return @{ RebootRequired = $false; NonAutoInstallableSkipped = $false; InstallationAttempted = $true }
        }
        3010 {
            Write-NxtLog -Message 'HPIA installation completed successfully; reboot required.'
            return @{ RebootRequired = $true; NonAutoInstallableSkipped = $false; InstallationAttempted = $true }
        }
        3011 {
            Write-NxtLog -Message 'HPIA installation skipped at least one non-auto-installable SoftPaq.'
            return @{ RebootRequired = $false; NonAutoInstallableSkipped = $true; InstallationAttempted = $true }
        }
        { $_ -in @(256, 257) } {
            Write-NxtLog -Message "HPIA installation found no applicable selected recommendations (exit code $exitCode)."
            return @{ RebootRequired = $false; NonAutoInstallableSkipped = $false; InstallationAttempted = $false }
        }
        3020 {
            $diagnostics = Read-HPIAInstallDiagnostic
            throw (Get-HPIAInstallFailureSummary -Diagnostics $diagnostics)
        }
        default {
            throw (Get-HPIAFailureMessage -ExitCode $exitCode -Operation 'installation')
        }
    }
}

function Get-HPIANonBIOSInstallCategory {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Accessories', 'BIOS', 'Drivers', 'Firmware', 'Software', 'Drivers,Firmware')]
        [string]$InstallationCategory
    )

    switch ($InstallationCategory) {
        'All' { return 'Drivers,Firmware,Software' }
        'BIOS' { return '' }
        default { return $InstallationCategory }
    }
}

function Merge-HPIAInstallResult {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Target,
        [Parameter(Mandatory = $true)]
        [hashtable]$Source
    )

    $Target.RebootRequired = [bool]($Target.RebootRequired -or $Source.RebootRequired)
    $Target.NonAutoInstallableSkipped = [bool]($Target.NonAutoInstallableSkipped -or $Source.NonAutoInstallableSkipped)
    $Target.InstallationAttempted = [bool]($Target.InstallationAttempted -or $Source.InstallationAttempted)
}

function Read-HPIAInstallDiagnostic {
    $result = [ordered]@{
        SuccessfulCount = 0
        FailedItems      = @()
        TimedOutItems    = @()
    }
    $debugLogPath = Get-HPIADebugLogPath
    if ([string]::IsNullOrWhiteSpace($debugLogPath) -or
        -not (Test-Path -LiteralPath $debugLogPath -PathType Leaf)) {
        return [pscustomobject]$result
    }

    $currentItem = $null
    $itemCount = 0
    foreach ($line in @(Get-Content -LiteralPath $debugLogPath -Tail 2000 -ErrorAction Stop)) {
        if ($line -match "Launching '(?<Path>[^']*\\(?<Id>sp\d+)_(?<Name>[^\\']+)\\install\.cmd)'") {
            $currentItem = [pscustomobject]@{
                Id   = $Matches.Id.ToLowerInvariant()
                Name = $Matches.Name
            }
            continue
        }

        if ($null -ne $currentItem -and
            $line -match 'timed out after (?<Minutes>\d+) minutes\.') {
            $itemCount++
            if ($itemCount -le 100) {
                $result.TimedOutItems += [pscustomobject]@{
                    Id      = $currentItem.Id
                    Name    = $currentItem.Name
                    Minutes = [int]$Matches.Minutes
                }
            }
            $currentItem = $null
            continue
        }

        if ($null -ne $currentItem -and
            $line -match 'Installation completed\.\s+(?:Exit|Error) code = (?<Code>-?\d+)\.') {
            $nativeExitCode = 0
            if (-not [int]::TryParse($Matches.Code, [ref]$nativeExitCode)) {
                continue
            }
            $itemCount++
            if ($nativeExitCode -eq 0) {
                $result.SuccessfulCount++
            } elseif ($itemCount -le 100) {
                $result.FailedItems += [pscustomobject]@{
                    Id       = $currentItem.Id
                    Name     = $currentItem.Name
                    ExitCode = $nativeExitCode
                }
            }
            $currentItem = $null
        }
    }

    return [pscustomobject]$result
}

function Get-HPIAInstallFailureSummary {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Diagnostics
    )

    $details = @()
    foreach ($timedOutItem in @($Diagnostics.TimedOutItems | Select-Object -First 3)) {
        $label = Get-BoundedDiagnosticText -Value "$($timedOutItem.Id) ($($timedOutItem.Name))" -MaximumCharacters 160
        $details += "$label timed out after $($timedOutItem.Minutes) minute(s)"
    }
    foreach ($failedItem in @($Diagnostics.FailedItems | Select-Object -First 3)) {
        $label = Get-BoundedDiagnosticText -Value "$($failedItem.Id) ($($failedItem.Name))" -MaximumCharacters 160
        $details += "$label returned exit code $($failedItem.ExitCode)"
    }
    if ($Diagnostics.SuccessfulCount -gt 0) {
        $details += "$($Diagnostics.SuccessfulCount) other SoftPaq installation(s) completed successfully"
    }

    if ($details.Count -eq 0) {
        return (Get-HPIAFailureMessage -ExitCode 3020 -Operation 'installation')
    }
    return "HPIA installation failed with exit code 3020: $($details -join '; ')."
}

function Get-BoundedDiagnosticText {
    param (
        [AllowEmptyString()]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1024)]
        [int]$MaximumCharacters
    )

    $singleLineValue = $Value.Replace("`r", ' ').Replace("`n", ' ')
    if ($singleLineValue.Length -le $MaximumCharacters) {
        return $singleLineValue
    }
    return $singleLineValue.Substring(0, $MaximumCharacters)
}

function Invoke-HPIABIOSInstall {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExePath,
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters,
        [Parameter(Mandatory = $true)]
        [object[]]$SoftPaqs
    )

    if ($SoftPaqs.Count -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Direct BIOS installation requires exactly one unique BIOS SoftPaq; HPIA reported $($SoftPaqs.Count)."
    }

    $spListPath = Join-Path $RUN_FOLDER 'hpia-bios-softpaqs.txt'
    [System.IO.File]::WriteAllLines(
        $spListPath,
        [string[]]@($SoftPaqs | ForEach-Object { $_.Number }),
        [System.Text.Encoding]::ASCII
    )

    Write-NxtLog -Message "Preparing signed BIOS SoftPaq '$($SoftPaqs[0].Id)' without using HPIA's installation executor."
    $arguments = "/Operation:Analyze /Category:BIOS /Selection:All /InstallType:AutoInstallable /Action:Extract /SPList:`"$spListPath`" /Silent /ReportFolder:`"$HP_REPORT_FOLDER`" /LogFolder:`"$HP_LOG_FOLDER`" /SoftPaqDownloadFolder:`"$HP_DOWNLOAD_FOLDER`" /SoftPaqExtractFolder:`"$HP_EXTRACT_FOLDER`" /Debug"
    $exitCode = Invoke-ProcessWithTimeout `
        -FilePath $ExePath `
        -Arguments $arguments `
        -TimeoutSeconds $HPIA_BIOS_PREPARE_TIMEOUT_SEC
    if ($exitCode -ne 0) {
        throw (Get-HPIAFailureMessage -ExitCode $exitCode -Operation 'BIOS package preparation')
    }

    $package = Get-HPIABIOSPackage -SoftPaq $SoftPaqs[0] -InputParameters $InputParameters
    Write-NxtLog -Message "Starting direct signed HP BIOS installation for '$($SoftPaqs[0].Id)' with a maximum wait of $HPIA_BIOS_INSTALL_TIMEOUT_SEC seconds."
    try {
        $biosExitCode = Invoke-BIOSFirmwareProcess `
            -FilePath $package.ExecutablePath `
            -Arguments $package.Arguments `
            -TimeoutSeconds $HPIA_BIOS_INSTALL_TIMEOUT_SEC
    } catch {
        $diagnosticSummary = Get-HPFirmwareDiagnosticSummary -ExecutablePath $package.ExecutablePath
        if (-not [string]::IsNullOrWhiteSpace($diagnosticSummary)) {
            throw "$($_.Exception.Message) HP updater log: $diagnosticSummary"
        }
        throw
    }
    $diagnosticSummary = Get-HPFirmwareDiagnosticSummary -ExecutablePath $package.ExecutablePath
    $biosResult = Get-HPIABIOSExitResult `
        -ExitCode $biosExitCode `
        -ReturnCodes $package.ReturnCodes `
        -SoftPaqId $SoftPaqs[0].Id `
        -DiagnosticSummary $diagnosticSummary

    return @{
        RebootRequired            = $biosResult.RebootRequired
        NonAutoInstallableSkipped = $false
        InstallationAttempted     = $true
    }
}

function Get-HPIABIOSPackage {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$SoftPaq,
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $softPaqExePath = Join-Path $HP_DOWNLOAD_FOLDER "$($SoftPaq.Id).exe"
    if (-not (Test-Path -LiteralPath $softPaqExePath -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) HPIA did not prepare expected BIOS SoftPaq '$softPaqExePath'."
    }
    Assert-PathUnderApprovedRoot -Path $softPaqExePath -AllowedRoot $RUN_FOLDER

    $candidateDirectories = @(Get-ChildItem -LiteralPath $HP_EXTRACT_FOLDER -Directory -ErrorAction Stop | Select-Object -First 101)
    if ($candidateDirectories.Count -gt 100) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS extraction folder exceeds the 100-directory validation limit."
    }
    $expectedPrefix = "$($SoftPaq.Id)_"
    $matchingDirectories = @($candidateDirectories | Where-Object {
            $_.Name.Equals($SoftPaq.Id, [System.StringComparison]::OrdinalIgnoreCase) -or
            $_.Name.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($matchingDirectories.Count -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Expected one extracted directory for '$($SoftPaq.Id)', found $($matchingDirectories.Count)."
    }
    $extractDirectory = $matchingDirectories[0].FullName
    Assert-PathUnderApprovedRoot -Path $extractDirectory -AllowedRoot $RUN_FOLDER

    $cvaPath = Get-HPIABIOSCVAPath -SoftPaq $SoftPaq -ExtractDirectory $extractDirectory
    $cva = Read-HPIACVAData -Path $cvaPath
    if ($cva.SoftPaqNumber -notmatch '^(?i:sp)?(?<Number>\d{4,8})$') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA SoftPaq identity does not match '$($SoftPaq.Id)'."
    }
    $cvaSoftPaqNumber = $Matches.Number
    if ($cvaSoftPaqNumber -ne $SoftPaq.Number) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA SoftPaq identity does not match '$($SoftPaq.Id)'."
    }
    if ($cva.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA for '$($SoftPaq.Id)' has no valid SHA-256."
    }
    Assert-FileHash -Path $softPaqExePath -ExpectedSHA256 $cva.SHA256
    Assert-HPAuthenticodeSignature -Path $softPaqExePath

    if ($cva.SilentInstall -notmatch '^\s*"?(?<Executable>HpFirmwareUpdRec(?:64)?\.exe)"?\s+(?<Arguments>.+?)\s*$') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS SoftPaq '$($SoftPaq.Id)' does not use the supported HP firmware updater."
    }
    $firmwareExecutableName = $Matches.Executable
    $silentArguments = $Matches.Arguments
    $argumentTokens = @($silentArguments -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($argumentTokens.Count -eq 0 -or $argumentTokens.Count -gt 3) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS SoftPaq '$($SoftPaq.Id)' has an unsupported silent command."
    }
    $allowedArguments = @('-s', '-b', '-r')
    foreach ($argumentToken in $argumentTokens) {
        if ($allowedArguments -notcontains $argumentToken.ToLowerInvariant()) {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS SoftPaq '$($SoftPaq.Id)' uses unsupported firmware argument '$argumentToken'."
        }
    }
    if (@($argumentTokens | Where-Object { $_.ToLowerInvariant() -eq '-s' }).Count -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS SoftPaq '$($SoftPaq.Id)' does not declare exactly one silent-mode argument."
    }

    $directExtractDirectory = Expand-HPBIOSSoftPaq `
        -SoftPaqPath $softPaqExePath `
        -SoftPaqId $SoftPaq.Id
    if ([Environment]::Is64BitOperatingSystem -and
        $firmwareExecutableName.Equals('HpFirmwareUpdRec.exe', [System.StringComparison]::OrdinalIgnoreCase)) {
        $nativeExecutableName = 'HpFirmwareUpdRec64.exe'
        $nativeExecutablePath = Join-Path $directExtractDirectory $nativeExecutableName
        if (Test-Path -LiteralPath $nativeExecutablePath -PathType Leaf) {
            $firmwareExecutableName = $nativeExecutableName
            Write-NxtLog -Message "Selected native 64-bit signed HP firmware updater for '$($SoftPaq.Id)'."
        }
    }
    $firmwareExecutablePath = Join-Path $directExtractDirectory $firmwareExecutableName
    if (-not (Test-Path -LiteralPath $firmwareExecutablePath -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Signed HP firmware updater was not found at '$firmwareExecutablePath'."
    }
    Assert-PathUnderApprovedRoot -Path $firmwareExecutablePath -AllowedRoot $RUN_FOLDER
    Assert-HPAuthenticodeSignature -Path $firmwareExecutablePath

    $biosPasswordFilePath = Get-BIOSPasswordFilePath -InputParameters $InputParameters
    $processArguments = $argumentTokens -join ' '
    if (-not [string]::IsNullOrWhiteSpace($biosPasswordFilePath)) {
        $processArguments += " -p`"$biosPasswordFilePath`""
    }

    return [pscustomobject]@{
        ExecutablePath = $firmwareExecutablePath
        Arguments      = $processArguments
        ReturnCodes    = $cva.ReturnCodes
    }
}

function Expand-HPBIOSSoftPaq {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SoftPaqPath,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?i:sp)\d{4,8}$')]
        [string]$SoftPaqId
    )

    $extractDirectory = Join-Path $HP_EXTRACT_FOLDER "direct-$SoftPaqId"
    if (Test-Path -LiteralPath $extractDirectory) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Direct BIOS extraction target already exists: '$extractDirectory'."
    }
    [void](New-Item -Path $extractDirectory -ItemType Directory)
    Assert-DirectoryIsNotReparsePoint -Path $extractDirectory
    Assert-PathUnderApprovedRoot -Path $extractDirectory -AllowedRoot $RUN_FOLDER

    Write-NxtLog -Message "Extracting validated signed BIOS SoftPaq '$SoftPaqId' into its owned execution folder."
    $arguments = "/s /e /f `"$extractDirectory`""
    $exitCode = Invoke-ProcessWithTimeout `
        -FilePath $SoftPaqPath `
        -Arguments $arguments `
        -TimeoutSeconds $EXTRACTION_TIMEOUT_SEC `
        -CaptureOutput
    if ($SOFTPAQ_EXTRACTION_SUCCESS_EXIT_CODES -notcontains $exitCode) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS SoftPaq '$SoftPaqId' extraction failed with exit code $exitCode."
    }
    if ($exitCode -eq 1168) {
        Write-Warning "BIOS SoftPaq '$SoftPaqId' extraction returned 1168; validating extracted artifacts before continuing."
    }

    Assert-DirectoryIsNotReparsePoint -Path $extractDirectory
    Assert-PathUnderApprovedRoot -Path $extractDirectory -AllowedRoot $RUN_FOLDER
    return $extractDirectory
}

function Get-HPIABIOSCVAPath {
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$SoftPaq,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExtractDirectory
    )

    $candidatePaths = @(
        (Join-Path $HP_DOWNLOAD_FOLDER "$($SoftPaq.Id).cva"),
        (Join-Path $ExtractDirectory "$($SoftPaq.Id).cva")
    )
    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            Assert-PathUnderApprovedRoot -Path $candidatePath -AllowedRoot $RUN_FOLDER
            return $candidatePath
        }
    }

    $softPaqNumber = 0
    if (-not [int]::TryParse([string]$SoftPaq.Number, [ref]$softPaqNumber) -or
        $softPaqNumber -lt 1 -or $softPaqNumber -gt 99999999) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Cannot derive the official CVA location for SoftPaq '$($SoftPaq.Id)'."
    }
    $rangeStart = ([int][Math]::Floor(($softPaqNumber - 1) / 500)) * 500 + 1
    $rangeEnd = $rangeStart + 499
    $cvaUrl = "https://ftp.hp.com/pub/softpaq/sp$rangeStart-$rangeEnd/sp$softPaqNumber.cva"

    $metadataFolder = Join-Path $RUN_FOLDER 'metadata'
    if (-not (Test-Path -LiteralPath $metadataFolder -PathType Container)) {
        [void](New-Item -Path $metadataFolder -ItemType Directory)
    }
    Assert-DirectoryIsNotReparsePoint -Path $metadataFolder
    Assert-PathUnderApprovedRoot -Path $metadataFolder -AllowedRoot $RUN_FOLDER

    $cvaPath = Join-Path $metadataFolder "sp$softPaqNumber.cva"
    Write-NxtLog -Message "HPIA did not retain CVA metadata for '$($SoftPaq.Id)'; downloading it from the official HP HTTPS repository."
    Invoke-FileDownload `
        -Url $cvaUrl `
        -Destination $cvaPath `
        -TimeoutSeconds 60 `
        -OperationName "HP SoftPaq '$($SoftPaq.Id)' CVA metadata"

    if (-not (Test-Path -LiteralPath $cvaPath -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Network) HP CVA metadata download completed without creating '$cvaPath'."
    }
    Assert-PathUnderApprovedRoot -Path $cvaPath -AllowedRoot $RUN_FOLDER
    return $cvaPath
}

function Read-HPIACVAData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $cvaFile = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($cvaFile.Length -gt 1048576) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA exceeds the 1 MiB parsing limit."
    }

    $section = ''
    $softPaqNumber = ''
    $sha256 = ''
    $silentInstall = ''
    $returnCodes = @{}
    foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $trimmedLine = $line.Trim()
        if ($trimmedLine -match '^\[(?<Section>[^\]]+)\]$') {
            $section = $Matches.Section
            continue
        }
        if ([string]::IsNullOrWhiteSpace($trimmedLine) -or $trimmedLine.StartsWith(';')) {
            continue
        }

        if ($section -eq 'ReturnCode' -and
            $trimmedLine -match '^(?<Code>-?\d+):(?<Status>SUCCESS|FAILURE):(?<Reboot>REBOOT|NOREBOOT)=(?<Description>.*)$') {
            if ($returnCodes.ContainsKey($Matches.Code)) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA contains duplicate return code '$($Matches.Code)'."
            }
            $returnCodes[$Matches.Code] = [pscustomobject]@{
                Status      = $Matches.Status
                Reboot      = $Matches.Reboot -eq 'REBOOT'
                Description = $Matches.Description
            }
            continue
        }

        if ($trimmedLine -notmatch '^(?<Key>[^=]+)=(?<Value>.*)$') {
            continue
        }
        $key = $Matches.Key.Trim()
        $value = $Matches.Value.Trim()
        if ($section -eq 'Softpaq') {
            if ($key -eq 'SoftpaqNumber') {
                $softPaqNumber = $value
            } elseif ($key -eq 'SoftPaqSHA256') {
                $sha256 = $value
            }
        } elseif ($section -eq 'Install Execution' -and $key -eq 'SilentInstall') {
            $silentInstall = $value
        }
    }

    if ([string]::IsNullOrWhiteSpace($softPaqNumber) -or
        [string]::IsNullOrWhiteSpace($sha256) -or
        [string]::IsNullOrWhiteSpace($silentInstall) -or
        $returnCodes.Count -eq 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS CVA is missing required identity, hash, command, or return-code data."
    }

    return [pscustomobject]@{
        SoftPaqNumber = $softPaqNumber
        SHA256        = $sha256
        SilentInstall = $silentInstall
        ReturnCodes   = $returnCodes
    }
}

function Invoke-BIOSFirmwareProcess {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Arguments,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds
    )

    if ($Arguments.IndexOfAny([char[]]@("`r", "`n")) -ge 0) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS firmware arguments contain unsupported control characters."
    }

    $effectiveTimeoutSeconds = Get-EffectiveProcessTimeout `
        -MaximumSeconds $TimeoutSeconds `
        -OperationName 'signed HP BIOS firmware installation'
    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $Arguments
        $startInfo.WorkingDirectory = [System.IO.Path]::GetDirectoryName($FilePath)
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) Failed to start signed HP BIOS firmware updater."
        }

        $processStartedUtc = [DateTime]::UtcNow
        $processDeadlineUtc = $processStartedUtc.AddSeconds($effectiveTimeoutSeconds)
        $nextProgressUtc = $processStartedUtc.AddSeconds($PROCESS_PROGRESS_INTERVAL_SEC)
        while ([DateTime]::UtcNow -lt $processDeadlineUtc) {
            $remainingMilliseconds = [int][Math]::Min(
                15000,
                [Math]::Max(1, [Math]::Ceiling(($processDeadlineUtc - [DateTime]::UtcNow).TotalMilliseconds))
            )
            if ($process.WaitForExit($remainingMilliseconds)) {
                $process.WaitForExit()
                return $process.ExitCode
            }

            if ([DateTime]::UtcNow -ge $nextProgressUtc) {
                $elapsedSeconds = [int][Math]::Floor(([DateTime]::UtcNow - $processStartedUtc).TotalSeconds)
                Write-NxtLog -Message "Signed HP BIOS firmware process (PID $($process.Id)) is still running after $elapsedSeconds second(s)."
                $nextProgressUtc = [DateTime]::UtcNow.AddSeconds($PROCESS_PROGRESS_INTERVAL_SEC)
            }
        }

        $script:RUN_FOLDER_CLEANUP_ALLOWED = $false
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Signed HP BIOS firmware process exceeded $effectiveTimeoutSeconds seconds. It was not terminated because interrupting an active firmware update could damage the device; the protected run folder was preserved."
    } finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Get-HPIABIOSExitResult {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,
        [Parameter(Mandatory = $true)]
        [hashtable]$ReturnCodes,
        [Parameter(Mandatory = $true)]
        [string]$SoftPaqId,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DiagnosticSummary = ''
    )

    $returnCodeKey = [string]$ExitCode
    $diagnosticSuffix = ''
    if (-not [string]::IsNullOrWhiteSpace($DiagnosticSummary)) {
        $boundedDiagnostic = Get-BoundedDiagnosticText -Value $DiagnosticSummary -MaximumCharacters 700
        $diagnosticSuffix = " HP updater log: $boundedDiagnostic"
    }
    if ($ExitCode -eq 259 -and
        $DiagnosticSummary -match '(?i)Flash already in progress\s*-\s*Error code\s*=\s*0x0*13(?:\b|$)') {
        $activeFirmwareProcesses = @(
            Get-Process -Name 'HpFirmwareUpdRec', 'HpFirmwareUpdRec64' -ErrorAction SilentlyContinue |
                Select-Object -First 10
        )
        if ($activeFirmwareProcesses.Count -gt 0) {
            $script:RUN_FOLDER_CLEANUP_ALLOWED = $false
            $processSummary = @($activeFirmwareProcesses | ForEach-Object {
                    "$($_.ProcessName) PID $($_.Id)"
                }) -join ', '
            throw "$($ERROR_EXCEPTION_TYPE.Internal) HP reports a BIOS flash already in progress and an updater process is still active ($processSummary). The process was not terminated and the protected run folder was preserved.$diagnosticSuffix"
        }

        Write-Warning "Signed HP BIOS SoftPaq '$SoftPaqId' returned exit code 259 because BIOS flash staging is already in progress (HP error 0x13); reboot is required before verification or another attempt."
        return @{ RebootRequired = $true }
    }
    if ($ExitCode -eq 0 -and -not $ReturnCodes.ContainsKey($returnCodeKey)) {
        Write-NxtLog -Message "Signed HP BIOS SoftPaq '$SoftPaqId' completed successfully with exit code 0."
        return @{ RebootRequired = $false }
    }
    if (-not $ReturnCodes.ContainsKey($returnCodeKey)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Signed HP BIOS SoftPaq '$SoftPaqId' returned undocumented exit code $ExitCode.$diagnosticSuffix"
    }

    $mapping = $ReturnCodes[$returnCodeKey]
    $description = Get-BoundedDiagnosticText -Value $mapping.Description -MaximumCharacters 300
    if ($mapping.Status -ne 'SUCCESS') {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Signed HP BIOS SoftPaq '$SoftPaqId' failed with exit code $ExitCode. $description$diagnosticSuffix"
    }

    Write-NxtLog -Message "Signed HP BIOS SoftPaq '$SoftPaqId' completed successfully with exit code $ExitCode. $description"
    return @{ RebootRequired = [bool]$mapping.Reboot }
}

function Get-HPFirmwareDiagnosticSummary {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExecutablePath
    )

    $firmwareFolder = [System.IO.Path]::GetDirectoryName($ExecutablePath)
    $executableBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ExecutablePath)
    $candidatePaths = @(
        (Join-Path $firmwareFolder "$executableBaseName.log"),
        (Join-Path $firmwareFolder 'HpFirmwareUpdRec64.log'),
        (Join-Path $firmwareFolder 'HpFirmwareUpdRec.log')
    )
    $logFiles = @()
    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            $candidateFile = Get-Item -LiteralPath $candidatePath -ErrorAction Stop
            if (@($logFiles | Where-Object { $_.FullName -eq $candidateFile.FullName }).Count -eq 0) {
                $logFiles += $candidateFile
            }
        }
    }
    if ($logFiles.Count -eq 0) {
        return ''
    }

    try {
        $logFile = @($logFiles | Sort-Object -Property LastWriteTimeUtc -Descending)[0]
        Assert-PathUnderApprovedRoot -Path $logFile.FullName -AllowedRoot $RUN_FOLDER
        $lines = @(Get-Content -LiteralPath $logFile.FullName -Tail 12 -ErrorAction Stop | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            })
        if ($lines.Count -eq 0) {
            return "'$($logFile.Name)' is empty."
        }
        $summary = @($lines | ForEach-Object {
                Get-BoundedDiagnosticText -Value ([string]$_) -MaximumCharacters 240
            }) -join ' | '
        return (Get-BoundedDiagnosticText -Value "'$($logFile.Name)': $summary" -MaximumCharacters 700)
    } catch {
        return "HP firmware log could not be read: $($_.Exception.Message)"
    }
}

function Assert-PathUnderApprovedRoot {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$AllowedRoot
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Path resolves outside approved run root."
    }

    $currentItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    while ($null -ne $currentItem -and
        $currentItem.FullName.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) BIOS package path contains a reparse point: '$($currentItem.FullName)'."
        }
        $currentItem = $currentItem.Parent
    }
}

function Initialize-HPIAReportFolder {
    if (Test-Path -LiteralPath $HP_REPORT_FOLDER -PathType Container) {
        Invoke-LongPathDirectoryCleanup -Path $HP_REPORT_FOLDER -AllowedRoot $RUN_FOLDER
    }
    [void](New-Item -Path $HP_REPORT_FOLDER -ItemType Directory -Force)
}

function Get-BIOSPasswordArgument {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $passwordFilePath = Get-BIOSPasswordFilePath -InputParameters $InputParameters
    if (-not [string]::IsNullOrWhiteSpace($passwordFilePath)) {
        return " /BIOSPwdFile:`"$passwordFilePath`""
    }
    return ''
}

function Get-BIOSPasswordFilePath {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$InputParameters
    )

    $categories = @($InputParameters.hpia_installation_category -split ',')
    if (($categories -notcontains 'BIOS' -and $categories -notcontains 'All') -or
        [string]::IsNullOrWhiteSpace($InputParameters.hpia_encoded_bios_password)) {
        return ''
    }

    $passwordFilePath = Join-Path $RUN_FOLDER 'hpia-bios-password.bin'
    if (Test-Path -LiteralPath $passwordFilePath -PathType Leaf) {
        return $passwordFilePath
    }

    $decodedData = $null
    try {
        $decodedData = [Convert]::FromBase64String($InputParameters.hpia_encoded_bios_password)
        [System.IO.File]::WriteAllBytes($passwordFilePath, $decodedData)
    } finally {
        if ($null -ne $decodedData) {
            [Array]::Clear($decodedData, 0, $decodedData.Length)
        }
    }
    return $passwordFilePath
}

function Get-HPIAFailureMessage {
    param (
        [Parameter(Mandatory = $true)]
        [int]$ExitCode,
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $description = switch ($ExitCode) {
        1 { 'SoftPaq verification could not find the binary.' }
        2 { 'SoftPaq verification raised an exception.' }
        3 { 'SoftPaq verification found an unexpected signer.' }
        4 { 'SoftPaq Authenticode verification failed.' }
        5 { 'SoftPaq certificate-chain verification failed.' }
        6 { 'HPIA configuration file is corrupted.' }
        256 { 'No recommendations were returned unexpectedly.' }
        257 { 'No recommendations were selected unexpectedly.' }
        3011 { 'A SoftPaq was not auto-installable and was skipped.' }
        3020 { 'One or more SoftPaq installations failed.' }
        4096 { 'Platform is unsupported.' }
        4097 { 'HPIA parameters are invalid.' }
        4098 { 'No internet connection is available to HPIA.' }
        4099 { 'SPList contains an invalid SoftPaq number.' }
        4100 { 'SoftPaq product list is empty.' }
        4101 { 'A supplied parameter is no longer supported.' }
        4102 { 'TLS 1.2 or higher is required.' }
        4103 { 'A complete request could not be sent.' }
        4104 { 'No supported OS reference exists; HPIA would use a generic reference.' }
        512 { 'HP Software Wrapper could not find the SoftPaq file.' }
        513 { 'HP Software Wrapper raised an exception during signature validation.' }
        514 { 'HP Software Wrapper found a SoftPaq not signed by HP.' }
        515 { 'HP Software Wrapper WinVerifyTrust validation failed.' }
        516 { 'HP Software Wrapper certificate-chain validation failed.' }
        517 { 'HP Software Wrapper configuration file is corrupted.' }
        8192 { 'HPIA operation failed.' }
        8193 { 'Image capture failed.' }
        8194 { 'Output folder could not be created.' }
        8195 { 'Download folder could not be created.' }
        8196 { 'Supported platform list download failed.' }
        8197 { 'Knowledge-base download failed.' }
        8198 { 'Extract folder could not be created.' }
        8199 { 'SoftPaq download failed.' }
        8200 { 'SoftPaq extraction failed.' }
        12288 { 'Target file failed to open.' }
        12289 { 'Target file is invalid.' }
        16384 { 'Reference file failed to open.' }
        16385 { 'Reference file is invalid.' }
        16386 { 'Reference file is unsupported on Windows 10.' }
        16387 { 'Reference file does not match the target system or OS.' }
        16388 { 'HPIA failed while processing the specified reference file.' }
        16389 { 'Specified reference file was not found.' }
        20480 { 'OS migration architecture is unsupported.' }
        32768 { 'HPIA returned its internal continue-running code unexpectedly.' }
        9527 { 'HP Software Wrapper requires elevated privileges.' }
        9537 { 'HP Software Wrapper bypassed an install.cmd return code.' }
        9547 { 'HP Software Wrapper failed to install a DCHU/Fusion driver.' }
        9557 { 'HP Software Wrapper failed to install a UWP application.' }
        9627 { 'HP Software Wrapper found nothing to install.' }
        default { 'Undocumented HPIA return code.' }
    }

    return "HPIA $operation failed with exit code $ExitCode. $description"
}

function Write-HPIALogTail {
    $debugLogPath = Get-HPIADebugLogPath
    if ([string]::IsNullOrWhiteSpace($debugLogPath) -or
        -not (Test-Path -LiteralPath $debugLogPath -PathType Leaf)) {
        return
    }

    try {
        foreach ($line in Get-Content -LiteralPath $debugLogPath -Tail 50 -ErrorAction Stop) {
            Write-NxtLog -Message "[HPIA] $line"
        }
    } catch {
        Write-Warning "Could not read HPIA log tail: $($_.Exception.Message)"
    }
}

function Invoke-RunFolderCleanup {
    if ([string]::IsNullOrWhiteSpace($RUN_FOLDER) -or -not (Test-Path -LiteralPath $RUN_FOLDER)) {
        return
    }

    if (-not $RUN_FOLDER_CLEANUP_ALLOWED) {
        $preserveMarker = Join-Path $RUN_FOLDER '.cleanup-blocked'
        try {
            [System.IO.File]::WriteAllText($preserveMarker, 'Automatic cleanup blocked because process-tree termination could not be confirmed.')
        } catch {
            Write-Warning "Could not create cleanup-blocked marker in '$RUN_FOLDER': $($_.Exception.Message)"
        }
        Write-Warning "Preserving run folder '$RUN_FOLDER' because termination of a process using it could not be confirmed."
        return
    }

    try {
        Invoke-LongPathDirectoryCleanup -Path $RUN_FOLDER -AllowedRoot $TEMP_FOLDER
    } catch {
        Write-Warning "Could not remove run folder '$RUN_FOLDER': $($_.Exception.Message)"
    }
}

function Invoke-LongPathDirectoryCleanup {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AllowedRoot
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $fullAllowedRoot = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $allowedPrefix = $fullAllowedRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Refusing directory cleanup outside approved root '$fullAllowedRoot'."
    }
    $extendedPath = if ($fullPath.StartsWith('\\')) {
        '\\?\UNC\' + $fullPath.TrimStart('\')
    } else {
        '\\?\' + $fullPath
    }

    $lastError = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            [System.IO.Directory]::Delete($extendedPath, $true)
        } catch {
            $lastError = $_.Exception
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            return
        }
        Start-Sleep -Milliseconds 250
    }

    $message = if ($null -ne $lastError) { $lastError.Message } else { 'Unknown deletion error.' }
    throw "$($ERROR_EXCEPTION_TYPE.Internal) Long-path directory cleanup failed after 2 attempts: $message"
}

function Initialize-NxtLogging {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RemoteActionName
    )

    $logPath = Get-LogPath
    if (-not (Test-Path -LiteralPath $logPath)) {
        [void](New-Item -Path $logPath -ItemType Directory -Force)
    }
    $logFile = Join-Path $logPath "$RemoteActionName.log"
    Invoke-NxtLogRotation -LogFile $logFile
    $script:NXT_LOG_FILE = $logFile
    Write-NxtLog -Message "Running Remote Action $RemoteActionName."
}

function Get-LogPath {
    return "$env:ProgramData\Nexthink\RemoteActions\Logs"
}

function Invoke-NxtLogRotation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )

    if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 1000000) {
        $oldLog = "$LogFile.001"
        Remove-Item -LiteralPath $oldLog -Force -ErrorAction SilentlyContinue
        Move-Item -LiteralPath $LogFile -Destination $oldLog -Force
    }
}

function Write-NxtLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $logMessage = "$(Get-Date -Format 'yyyy/MM/dd HH:mm:ss') - $Message"
    Write-Information -MessageData $logMessage -InformationAction Continue

    if (-not [string]::IsNullOrWhiteSpace($NXT_LOG_FILE)) {
        try {
            $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::AppendAllText($NXT_LOG_FILE, $logMessage + [Environment]::NewLine, $utf8WithoutBom)
        } catch {
            $script:NXT_LOG_FILE = $null
            Write-Warning "Could not append to the Remote Action log; console diagnostics remain available: $($_.Exception.Message)"
        }
    }
}

function Add-NexthinkDLL {
    $dll = "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
    if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink DLL not found: $dll"
    }
    Add-Type -LiteralPath $dll
}

function Add-NexthinkCampaignDLL {
    $dll = "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll"
    if (-not (Test-Path -LiteralPath $dll -PathType Leaf)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink campaign DLL not found: $dll"
    }
    Add-Type -LiteralPath $dll
}

function Invoke-InProgressCampaign {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CampaignId
    )

    [void][nxt.campaignaction]::RunStandAloneCampaign($CampaignId)
    Write-NxtLog -Message "Triggered in-progress campaign '$CampaignId'."
}

function Wait-RandomTime {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 600)]
        [int]$MaximumDelayInSeconds
    )

    if ($MaximumDelayInSeconds -gt 0) {
        $seconds = Get-Random -Minimum 0 -Maximum ($MaximumDelayInSeconds + 1)
        Write-NxtLog -Message "Waiting $seconds second(s) before HPIA execution."
        Start-Sleep -Seconds $seconds
    }
}

function Complete-NxtLogging {
    param (
        [Parameter(Mandatory = $true)]
        [int]$Result
    )

    if ($Result -eq 0) {
        Write-NxtLog -Message 'Remote Action execution succeeded.'
    } else {
        Write-NxtLog -Message 'Remote Action execution failed.'
    }
}

function Write-EngineOutputVariable {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Outputs
    )

    Write-NxtLog -Message 'Updating Nexthink output variables.'
    [nxt]::WriteOutputString('hpia_mode', $Outputs.hpia_mode)
    [nxt]::WriteOutputString('hpia_installation_category', $Outputs.hpia_installation_category)
    [nxt]::WriteOutputBool('all_updates_applied_successfully', $Outputs.all_updates_applied_successfully)
    [nxt]::WriteOutputBool('reboot_required', $Outputs.reboot_required)

    $updatedItems = @()
    if ($Outputs.updated_drivers.Count -gt 0) {
        foreach ($updatedDriver in $Outputs.updated_drivers) {
            $updatedItems += ConvertTo-NxtString -Value ([string]$updatedDriver) -FieldName 'list_of_updated_drivers'
        }
    } else {
        $updatedItems = @('-')
    }
    [nxt]::WriteOutputStringList('list_of_updated_drivers', [string[]]$updatedItems)
    [nxt]::WriteOutputDateTime('last_successful_scan', $Outputs.month_and_year_updates_were_scanned)
    [nxt]::WriteOutputUInt32('number_total_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_total_updates -FieldName 'number_total_updates'))
    [nxt]::WriteOutputUInt32('number_accessories_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_accessories_updates -FieldName 'number_accessories_updates'))
    [nxt]::WriteOutputUInt32('number_bios_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_bios_updates -FieldName 'number_bios_updates'))
    [nxt]::WriteOutputUInt32('number_driver_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_driver_updates -FieldName 'number_driver_updates'))
    [nxt]::WriteOutputUInt32('number_firmware_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_firmware_updates -FieldName 'number_firmware_updates'))
    [nxt]::WriteOutputUInt32('number_software_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_software_updates -FieldName 'number_software_updates'))
    [nxt]::WriteOutputUInt32('number_ssm_compliant_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_ssm_compliant_updates -FieldName 'number_ssm_compliant_updates'))
    [nxt]::WriteOutputUInt32('number_non_ssm_updates', (ConvertTo-NxtUInt32 -Value $Outputs.number_non_ssm_updates -FieldName 'number_non_ssm_updates'))
    [nxt]::WriteOutputUInt32('number_bios_settings_drift', (ConvertTo-NxtUInt32 -Value $Outputs.number_bios_settings_drift -FieldName 'number_bios_settings_drift'))
}

function ConvertTo-NxtString {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FieldName
    )

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    if ($utf8.GetByteCount($Value) -le 1024) {
        return $Value
    }

    $low = 0
    $high = $Value.Length
    while ($low -lt $high) {
        $middle = [int][math]::Ceiling(($low + $high) / 2)
        if ($utf8.GetByteCount($Value.Substring(0, $middle)) -le 1024) {
            $low = $middle
        } else {
            $high = $middle - 1
        }
    }

    if ($low -gt 0 -and [char]::IsHighSurrogate($Value[$low - 1])) {
        $low--
    }
    Write-Warning "Nexthink output '$FieldName' exceeded 1024 UTF-8 bytes and was truncated."
    return $Value.Substring(0, $low)
}

function ConvertTo-NxtUInt32 {
    param (
        [Parameter(Mandatory = $true)]
        [long]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FieldName
    )

    if ($Value -lt 0) {
        Write-Warning "Nexthink output '$FieldName' was negative and was clamped to 0."
        return [uint32]0
    }
    if ($Value -gt [uint32]::MaxValue) {
        Write-Warning "Nexthink output '$FieldName' exceeded UInt32 maximum and was clamped."
        return [uint32]::MaxValue
    }
    return [uint32]$Value
}

function Protect-SecureFolderAcl {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FolderPath
    )

    $acl = Get-Acl -LiteralPath $FolderPath
    $acl.SetAccessRuleProtection($true, $false)

    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleAll($rule)
    }

    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    $systemSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::LocalSystemSid,
        $null
    )
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
        $null
    )

    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $systemSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    )
    $administratorsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $administratorsSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        $propagation,
        $allow
    )

    [void]$acl.AddAccessRule($systemRule)
    [void]$acl.AddAccessRule($administratorsRule)
    Set-Acl -LiteralPath $FolderPath -AclObject $acl
}

$finalExitCode = Invoke-Main -InputParameters $MyInvocation.BoundParameters
exit $finalExitCode
