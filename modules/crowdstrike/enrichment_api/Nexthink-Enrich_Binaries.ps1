<#
    .SYNOPSIS
        Exports binaries from Nexthink NQL API and enriches binary custom fields using CrowdStrike vulnerability data.

    .DESCRIPTION
        Flow:
        1) Start NQL export for binaries with compression = NONE.
        2) Poll export status until completion and download CSV.
        3) Read all binary SHA-256 hashes from CSV and query CrowdStrike in batches.
        4) Map CrowdStrike vulnerability fields to Nexthink custom fields.
        5) Send enrichments in batches to Nexthink Enrichment API.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BaseUrl = 'https://<replace_me>.api.eu.nexthink.cloud',

    [Parameter(Mandatory = $false)]
    [string]$NqlQueryId = '#<replace_me>',

    [Parameter(Mandatory = $false)]
    [hashtable]$NqlParameters = @{},

    [Parameter(Mandatory = $false)]
    [string]$BinaryUidColumn = 'binary.uid',

    [Parameter(Mandatory = $false)]
    [string]$BinaryHashColumn = 'binary.sha-256_hash_hex',

    [Parameter(Mandatory = $false)]
    [string]$OutputFolder = (Join-Path -Path $PSScriptRoot -ChildPath 'output'),

    [Parameter(Mandatory = $false)]
    [string]$ExportFileName = 'nexthink_binaries.csv',

    [Parameter(Mandatory = $false)]
    [string]$VulnerabilityCacheFileName = 'crowdstrike_vulnerabilities_by_hash.json',

    [Parameter(Mandatory = $false)]
    [int]$BatchSize = 4500,

    [Parameter(Mandatory = $false)]
    [int]$CrowdStrikeHashBatchSize = 50,

    [Parameter(Mandatory = $false)]
    [int]$MaxAttempts = 5,

    [Parameter(Mandatory = $false)]
    [string]$Domain = 'binary_custom_fields',

    [Parameter(Mandatory = $false)]
    [string]$CrowdStrikeBaseUrl = 'https://api.eu-1.crowdstrike.com',

    [Parameter(Mandatory = $false)]
    [string]$CrowdStrikeModulePath = (Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath '.\CrowdStrikeSoftwareVulnByHash.psm1'),

    [Parameter(Mandatory = $false)]
    [string]$NexthinkCredentialPath = '<replace_me>\nexthink.xml',

    [Parameter(Mandatory = $false)]
    [string]$CrowdStrikeCredentialPath = '<replace_me>\crowdstrike.xml',

    [Parameter(Mandatory = $false)]
    [string]$Proxy = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$customFieldIds = [ordered]@{
    CveId                    = 'binary/binary/#vulnerability_cve'
    Category                 = 'binary/binary/#vulnerability_category'
    ExprtRating              = 'binary/binary/#vulnerability_exprt_rating'
    CvssRating               = 'binary/binary/#vulnerability_cvss_rating'
    Exploitable              = 'binary/binary/#vulnerability_exploitable'
    RemediationLevel         = 'binary/binary/#vulnerability_remediation_level'
    RemediationLevelCode     = 'binary/binary/#vulnerability_remediation_code'
    RemediationAvailableCount = 'binary/binary/#vulnerability_total_remediations'
}

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )

    $normalized = $InputString.Replace('-', '+').Replace('_', '/')
    switch ($normalized.Length % 4) {
        2 { $normalized += '==' }
        3 { $normalized += '=' }
    }

    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($normalized))
}

function Get-ExpirationDate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    try {
        $segments = $AccessToken -split '\.'
        if ($segments.Length -lt 2) {
            return (Get-Date).AddMinutes(50)
        }

        $payload = ConvertFrom-Base64Url -InputString $segments[1] | ConvertFrom-Json
        return [DateTimeOffset]::FromUnixTimeSeconds([int64]$payload.exp).LocalDateTime.AddSeconds(-30)
    } catch {
        return (Get-Date).AddMinutes(50)
    }
}

function Get-RowColumnValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,

        [Parameter(Mandatory = $true)]
        [string]$ColumnName
    )

    $property = $Row.PSObject.Properties[$ColumnName]
    if ($null -eq $property) {
        return ''
    }

    if ($null -eq $property.Value) {
        return ''
    }

    return [string]$property.Value
}

function Test-RowHasColumn {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Row,

        [Parameter(Mandatory = $true)]
        [string]$ColumnName
    )

    return $null -ne $Row.PSObject.Properties[$ColumnName]
}

function Get-NormalizedHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Hash
    )

    if ([string]::IsNullOrWhiteSpace($Hash)) {
        return $null
    }

    $normalized = $Hash.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    return $normalized
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $false)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter(Mandatory = $false)]
        [object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function Save-CrowdStrikeVulnerabilityCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$HashToVulnerability,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $entries = @()
    foreach ($key in $HashToVulnerability.Keys) {
        $entries += [PSCustomObject]@{
            Hash = [string]$key
            Vulnerability = $HashToVulnerability[$key]
        }
    }

    $payload = [PSCustomObject]@{
        CreatedAt = (Get-Date).ToString('o')
        Entries = $entries
    }

    $payload | ConvertTo-Json -Depth 20 | Set-Content -Path $Path -Encoding UTF8
}

function Load-CrowdStrikeVulnerabilityCache {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content -Path $Path -Raw
    $cache = $content | ConvertFrom-Json

    $map = @{}
    $entries = @($cache.Entries)
    foreach ($entry in $entries) {
        $hash = Get-NormalizedHash -Hash ([string]$entry.Hash)
        if ([string]::IsNullOrWhiteSpace($hash)) {
            continue
        }

        if ($null -eq $entry.Vulnerability) {
            continue
        }

        if (-not $map.ContainsKey($hash)) {
            $map[$hash] = $entry.Vulnerability
        }
    }

    return $map
}

function Remove-TemporaryWorkingFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths
    )

    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if (Test-Path -Path $path -PathType Leaf) {
            Remove-Item -Path $path -Force -ErrorAction Stop
            Write-Information "Removed temporary file: $path"
        }
    }
}

function Convert-ExploitAvailableToText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [bool]) {
        return $(if ($Value) { 'Yes' } else { 'No' })
    }

    $valueText = [string]$Value
    if ([string]::Equals($valueText, 'true', [System.StringComparison]::OrdinalIgnoreCase) -or $valueText -eq '1') {
        return 'Yes'
    }

    if ([string]::Equals($valueText, 'false', [System.StringComparison]::OrdinalIgnoreCase) -or $valueText -eq '0') {
        return 'No'
    }

    return ''
}

function Test-RequiredConfiguration {
    [CmdletBinding()]
    param()

    $missing = @()

    if ([string]::IsNullOrWhiteSpace($BaseUrl) -or $BaseUrl -like '*<replace_me>*') {
        $missing += 'BaseUrl'
    }

    if ([string]::IsNullOrWhiteSpace($NqlQueryId) -or $NqlQueryId -like '*<replace_me>*') {
        $missing += 'NqlQueryId'
    }

    if ([string]::IsNullOrWhiteSpace($CrowdStrikeBaseUrl) -or $CrowdStrikeBaseUrl -like '*<replace_me>*') {
        $missing += 'CrowdStrikeBaseUrl'
    }

    if ([string]::IsNullOrWhiteSpace($CrowdStrikeModulePath) -or -not (Test-Path -Path $CrowdStrikeModulePath -PathType Leaf)) {
        $missing += 'CrowdStrikeModulePath'
    }

    if ([string]::IsNullOrWhiteSpace($NexthinkCredentialPath) -or -not (Test-Path -Path $NexthinkCredentialPath -PathType Leaf)) {
        $missing += 'NexthinkCredentialPath'
    }

    if ([string]::IsNullOrWhiteSpace($CrowdStrikeCredentialPath) -or -not (Test-Path -Path $CrowdStrikeCredentialPath -PathType Leaf)) {
        $missing += 'CrowdStrikeCredentialPath'
    }

    if ($BatchSize -lt 1) {
        $missing += 'BatchSize'
    }

    if ($CrowdStrikeHashBatchSize -lt 1 -or $CrowdStrikeHashBatchSize -gt 100) {
        $missing += 'CrowdStrikeHashBatchSize (must be 1..100)'
    }

    if ($missing.Count -gt 0) {
        throw "Missing/invalid configuration detected: $($missing -join ', ')"
    }
}

function Get-PlainTextSecretFromSecureString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$SecureValue
    )

    if (Get-Command -Name 'ConvertFrom-SecureString' -ErrorAction SilentlyContinue) {
        try {
            return (ConvertFrom-SecureString -SecureString $SecureValue -AsPlainText)
        } catch {
            # Fallback below.
            Write-Error $_
        }
    }

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-ApiCredentialsFromClixml {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $credential = Import-Clixml -Path $Path
    if ($null -eq $credential) {
        throw "Could not load credentials from '$Path'."
    }

    $userName = [string]$credential.UserName
    $password = Get-PlainTextSecretFromSecureString -SecureValue $credential.Password

    if ([string]::IsNullOrWhiteSpace($userName) -or [string]::IsNullOrWhiteSpace($password)) {
        throw "Credential file '$Path' does not contain a valid username/password."
    }

    return [PSCustomObject]@{
        UserName = $userName
        Password = $password
    }
}

function Get-NexthinkAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AuthUrl,

        [Parameter(Mandatory = $true)]
        [string]$AuthClientId,

        [Parameter(Mandatory = $true)]
        [string]$AuthClientSecret
    )

    $credentials = "${AuthClientId}:${AuthClientSecret}"
    $credentialsBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($credentials))

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
        'Authorization' = "Basic $credentialsBase64"
    }

    $body = @{
        grant_type = 'client_credentials'
        scope = 'service:integration'
    }

    $requestParams = @{
        Uri = $AuthUrl
        Method = 'Post'
        Headers = $headers
        Body = $body
        ContentType = 'application/x-www-form-urlencoded'
    }
    if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
        $requestParams.Proxy = $Proxy
    }

    $response = Invoke-RestMethod @requestParams

    $expiresAt = $null
    if ($response.PSObject.Properties.Name -contains 'expires_in' -and [int]$response.expires_in -gt 0) {
        $expiresAt = (Get-Date).AddSeconds([int]$response.expires_in).AddSeconds(-30)
    } else {
        $expiresAt = Get-ExpirationDate -AccessToken $response.access_token
    }

    return [PSCustomObject]@{
        AccessToken = [string]$response.access_token
        ExpiresAt = $expiresAt
    }
}

function New-BearerHeaders {
    <#
        .OUTPUTS
        System.Collections.Hashtable
        Correlated rows with this nested structure:
        - Authorization
        - Content-Type
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$ContentType = 'application/json'
    )

    return @{
        'Authorization' = "Bearer $AccessToken"
        'Content-Type' = $ContentType
    }
}

function Start-NqlExport {
    <#
        .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportUrl,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$QueryId,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )

    $normalizedQueryId = if ($QueryId.StartsWith('#')) { $QueryId } else { "#$QueryId" }

    $body = @{
        queryId = $normalizedQueryId
        compression = 'NONE'
    }

    if ($Parameters.Count -gt 0) {
        $body.parameters = $Parameters
    }

    $requestParams = @{
        Uri = $ExportUrl
        Method = 'Post'
        Headers = $Headers
        Body = ($body | ConvertTo-Json -Depth 10)
    }
    if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
        $requestParams.Proxy = $Proxy
    }

    $response = Invoke-RestMethod @requestParams
    return [string]$response.exportId
}

function Wait-NqlExportCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StatusUrl,

        [Parameter(Mandatory = $true)]
        [string]$ExportId,

        [Parameter(Mandatory = $true)]
        [ref]$TokenState,

        [Parameter(Mandatory = $true)]
        [scriptblock]$RefreshToken,

        [Parameter(Mandatory = $false)]
        [int]$PollSeconds = 5
    )

    $status = 'SUBMITTED'
    $lastResponse = $null
    $exportStatusUrl = "$StatusUrl/$ExportId"

    while ($status -eq 'SUBMITTED' -or $status -eq 'IN_PROGRESS') {
        if ($TokenState.Value.ExpiresAt -lt (Get-Date)) {
            Write-Information 'Access token expired during export polling. Refreshing token...'
            $TokenState.Value = & $RefreshToken
        }

        $headers = New-BearerHeaders -AccessToken $TokenState.Value.AccessToken
        Start-Sleep -Seconds $PollSeconds
        $requestParams = @{
            Uri = $exportStatusUrl
            Method = 'Get'
            Headers = $headers
        }
        if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
            $requestParams.Proxy = $Proxy
        }

        $lastResponse = Invoke-RestMethod @requestParams
        $status = [string]$lastResponse.status
        Write-Information "Export status: $status"
    }

    if ([string]::IsNullOrWhiteSpace([string]$lastResponse.resultsFileUrl)) {
        throw "Export did not finish successfully. Last status: $status"
    }

    return $lastResponse
}

function Send-EnrichmentBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Batch,

        [Parameter(Mandatory = $true)]
        [string]$ApiUrl,

        [Parameter(Mandatory = $true)]
        [string]$BatchDomain,

        [Parameter(Mandatory = $true)]
        [int]$AttemptLimit,

        [Parameter(Mandatory = $true)]
        [ref]$TokenState,

        [Parameter(Mandatory = $true)]
        [scriptblock]$RefreshToken
    )

    if ($Batch.Count -eq 0) {
        return
    }

    $body = @{
        enrichments = $Batch
        domain = $BatchDomain
    }

    $attempt = 0
    while ($attempt -lt $AttemptLimit) {
        $attempt = $attempt + 1

        if ($TokenState.Value.ExpiresAt -lt (Get-Date)) {
            Write-Information 'Access token expired. Refreshing token...'
            $TokenState.Value = & $RefreshToken
        }

        $headers = New-BearerHeaders -AccessToken $TokenState.Value.AccessToken

        try {
            $requestParams = @{
                Uri = $ApiUrl
                Method = 'Post'
                Headers = $headers
                Body = ($body | ConvertTo-Json -Depth 10)
            }
            if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
                $requestParams.Proxy = $Proxy
            }

            Invoke-RestMethod @requestParams | Out-Null
            return
        } catch {
            $statusCode = $null
            $retryAfterSeconds = 30

            if ($_.Exception.Response) {
                try {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                } catch {
                    $statusCode = $null
                }

                try {
                    if ($_.Exception.Response.Headers.RetryAfter -and $_.Exception.Response.Headers.RetryAfter.Delta) {
                        $retryAfterSeconds = [Math]::Ceiling($_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds)
                    }
                } catch {
                    $retryAfterSeconds = 30
                }
            }

            if ($statusCode -eq 401 -or $statusCode -eq 403) {
                Write-Information 'Authorization error received. Refreshing token...'
                Start-Sleep -Seconds 20
                $TokenState.Value = & $RefreshToken
                continue
            }

            if ($statusCode -eq 429) {
                Write-Information "Rate limit received. Sleeping for $retryAfterSeconds seconds before retrying..."
                Start-Sleep -Seconds $retryAfterSeconds
                continue
            }

            Write-Information "Batch send attempt $attempt failed. Retrying in 30 seconds..."
            Start-Sleep -Seconds 30
        }
    }

    throw "Max attempts reached while sending enrichment batch of size $($Batch.Count)."
}

function Get-CrowdStrikeVulnerabilityByHashMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Hashes,

        [Parameter(Mandatory = $true)]
        [int]$LookupBatchSize,

        [Parameter(Mandatory = $true)]
        [string]$ModulePath,

        [Parameter(Mandatory = $true)]
        [string]$ApiClientId,

        [Parameter(Mandatory = $true)]
        [string]$ApiClientSecret,

        [Parameter(Mandatory = $true)]
        [string]$ApiBaseUrl,

        [Parameter(Mandatory = $false)]
        [string]$ProxyUrl = ''
    )

    $hashToVulnerability = @{}
    $normalizedHashes = @(
        $Hashes |
            ForEach-Object { Get-NormalizedHash -Hash ([string]$_) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    if ($normalizedHashes.Count -eq 0) {
        return $hashToVulnerability
    }

    Import-Module -Name $ModulePath -Force

    Write-Information "Connecting to CrowdStrike API at $ApiBaseUrl"
    $connectParams = @{
        ClientId = $ApiClientId
        ClientSecret = $ApiClientSecret
        BaseUrl = $ApiBaseUrl
    }
    if (-not [string]::IsNullOrWhiteSpace($ProxyUrl)) {
        $connectParams.Proxy = $ProxyUrl
    }

    Connect-CrowdStrikeApi @connectParams | Out-Null

    for ($offset = 0; $offset -lt $normalizedHashes.Count; $offset += $LookupBatchSize) {
        $batchEnd = [Math]::Min($offset + $LookupBatchSize - 1, $normalizedHashes.Count - 1)
        $batchHashes = @($normalizedHashes[$offset..$batchEnd])

        Write-Information "Querying CrowdStrike vulnerability data for hash batch $($offset + 1)-$($batchEnd + 1) of $($normalizedHashes.Count)..."

        $queryParams = @{
            FileHashes = $batchHashes
            BaseUrl = $ApiBaseUrl
            HashBatchSize = $LookupBatchSize
        }
        if (-not [string]::IsNullOrWhiteSpace($ProxyUrl)) {
            $queryParams.Proxy = $ProxyUrl
        }

        $results = @(Get-CrowdStrikeSoftwareVulnerabilityByHash @queryParams)

        foreach ($result in $results) {
            $fileHash = Get-NormalizedHash -Hash ([string](Get-ObjectPropertyValue -InputObject $result -PropertyName 'FileHash' -DefaultValue ''))
            if ([string]::IsNullOrWhiteSpace($fileHash)) {
                continue
            }

            if ($hashToVulnerability.ContainsKey($fileHash)) {
                continue
            }

            $vuln = Get-ObjectPropertyValue -InputObject $result -PropertyName 'Vulnerability'
            if ($null -ne $vuln) {
                $hashToVulnerability[$fileHash] = $vuln
            }
        }
    }

    return $hashToVulnerability
}

function New-BinaryEnrichmentFromVulnerability {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BinaryUid,

        [Parameter(Mandatory = $false)]
        [object]$Vulnerability
    )

    $cveId = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'CveId' -DefaultValue '')
    $category = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'Category' -DefaultValue '')

    $exprtRating = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'ExprtRating' -DefaultValue '')
    $cvss = Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'Cvss'
    $cvssSeverity = [string](Get-ObjectPropertyValue -InputObject $cvss -PropertyName 'Severity' -DefaultValue '')

    $exploit = Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'Exploit'
    $exploitableValue = Convert-ExploitAvailableToText -Value (Get-ObjectPropertyValue -InputObject $exploit -PropertyName 'Available')

    $remediation = Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'Remediation'
    $remediationLevel = [string](Get-ObjectPropertyValue -InputObject $remediation -PropertyName 'Level' -DefaultValue '')
    $remediationLevelCode = [string](Get-ObjectPropertyValue -InputObject $remediation -PropertyName 'LevelCode' -DefaultValue '')
    $availableCountValue = Get-ObjectPropertyValue -InputObject $remediation -PropertyName 'AvailableCount'
    $availableCount = if ($null -eq $availableCountValue) { '' } else { [string]$availableCountValue }

    $fields = @(
        @{ name = $customFieldIds.CveId; value = $cveId },
        @{ name = $customFieldIds.Category; value = $category },
        @{ name = $customFieldIds.ExprtRating; value = $exprtRating },
        @{ name = $customFieldIds.CvssRating; value = $cvssSeverity },
        @{ name = $customFieldIds.Exploitable; value = $exploitableValue },
        @{ name = $customFieldIds.RemediationLevel; value = $remediationLevel },
        @{ name = $customFieldIds.RemediationLevelCode; value = $remediationLevelCode },
        @{ name = $customFieldIds.RemediationAvailableCount; value = $availableCount }
    )

    return @{
        identification = @(
            @{
                name = 'binary/binary/uid'
                value = $BinaryUid
            }
        )
        fields = $fields
    }
}

try {
    Test-RequiredConfiguration

    if (-not (Test-Path -Path $OutputFolder)) {
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }

    $nexthinkCredentials = Get-ApiCredentialsFromClixml -Path $NexthinkCredentialPath
    $crowdStrikeCredentials = Get-ApiCredentialsFromClixml -Path $CrowdStrikeCredentialPath

    $nexthinkApiUser = $nexthinkCredentials.UserName
    $nexthinkApiPassword = $nexthinkCredentials.Password

    $falconClientId = $crowdStrikeCredentials.UserName
    $falconClientSecret = $crowdStrikeCredentials.Password

    $authUrl = "$BaseUrl/api/v1/token"
    $exportUrl = "$BaseUrl/api/v1/nql/export"
    $statusUrl = "$BaseUrl/api/v1/nql/status"
    $enrichmentUrl = "$BaseUrl/api/v1/enrichment/data/fields"
    $exportFilePath = Join-Path -Path $OutputFolder -ChildPath $ExportFileName
    $vulnerabilityCachePath = Join-Path -Path $OutputFolder -ChildPath $VulnerabilityCacheFileName

    Write-Information 'Getting Nexthink authorization token...'
    $tokenState = Get-NexthinkAccessToken -AuthUrl $authUrl -AuthClientId $nexthinkApiUser -AuthClientSecret $nexthinkApiPassword

    $refreshToken = {
        Get-NexthinkAccessToken -AuthUrl $authUrl -AuthClientId $nexthinkApiUser -AuthClientSecret $nexthinkApiPassword
    }

    $headers = New-BearerHeaders -AccessToken $tokenState.AccessToken

    if (Test-Path -Path $exportFilePath -PathType Leaf) {
        Write-Information "Using existing Nexthink export CSV from previous run: $exportFilePath"
    } else {
        Write-Information 'Starting NQL export for binaries (compression: NONE)...'
        $exportId = Start-NqlExport -ExportUrl $exportUrl -Headers $headers -QueryId $NqlQueryId -Parameters $NqlParameters
        Write-Information "Export started. Export ID: $exportId"

        $exportStatus = Wait-NqlExportCompletion -StatusUrl $statusUrl -ExportId $exportId -TokenState ([ref]$tokenState) -RefreshToken $refreshToken

        Write-Information "Downloading export CSV to $exportFilePath"
        $downloadParams = @{
            Uri = $exportStatus.resultsFileUrl
            Method = 'Get'
            OutFile = $exportFilePath
        }
        if (-not [string]::IsNullOrWhiteSpace($Proxy)) {
            $downloadParams.Proxy = $Proxy
        }
        Invoke-WebRequest @downloadParams
    }

    Write-Information 'Importing CSV...'
    $binaryRows = @(Import-Csv -Path $exportFilePath)

    if ($binaryRows.Count -eq 0) {
        Write-Information 'No binaries found in export result. Nothing to enrich.'
        return
    }

    $firstRow = $binaryRows[0]
    if (-not (Test-RowHasColumn -Row $firstRow -ColumnName $BinaryUidColumn)) {
        throw "Expected UID column '$BinaryUidColumn' not found in CSV headers."
    }

    if (-not (Test-RowHasColumn -Row $firstRow -ColumnName $BinaryHashColumn)) {
        throw "Expected hash column '$BinaryHashColumn' not found in CSV headers."
    }

    $allHashes = @(
        $binaryRows |
            ForEach-Object { Get-NormalizedHash -Hash (Get-RowColumnValue -Row $_ -ColumnName $BinaryHashColumn) } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    Write-Information "Export contains $($binaryRows.Count) binaries and $($allHashes.Count) unique non-empty hashes."

    $vulnerabilityByHash = @{}
    $falconDataReady = $false
    if (Test-Path -Path $vulnerabilityCachePath -PathType Leaf) {
        Write-Information "Using existing CrowdStrike vulnerability cache from previous run: $vulnerabilityCachePath"
        $vulnerabilityByHash = Load-CrowdStrikeVulnerabilityCache -Path $vulnerabilityCachePath
        $falconDataReady = $true
    } else {
        $vulnerabilityByHash = Get-CrowdStrikeVulnerabilityByHashMap `
            -Hashes $allHashes `
            -LookupBatchSize $CrowdStrikeHashBatchSize `
            -ModulePath $CrowdStrikeModulePath `
            -ApiClientId $falconClientId `
            -ApiClientSecret $falconClientSecret `
            -ApiBaseUrl $CrowdStrikeBaseUrl `
            -ProxyUrl $Proxy

        Save-CrowdStrikeVulnerabilityCache -HashToVulnerability $vulnerabilityByHash -Path $vulnerabilityCachePath
        Write-Information "Saved CrowdStrike vulnerability cache: $vulnerabilityCachePath"
        $falconDataReady = $true
    }

    Write-Information "CrowdStrike returned vulnerability matches for $($vulnerabilityByHash.Count) hashes."

    $enrichments = @()
    $processed = 0
    $skipped = 0
    $withVulnerability = 0

    $enrichmentUploadCompleted = $false
    foreach ($row in $binaryRows) {
        $binaryUid = Get-RowColumnValue -Row $row -ColumnName $BinaryUidColumn
        if ([string]::IsNullOrWhiteSpace($binaryUid)) {
            $skipped = $skipped + 1
            continue
        }

        $binaryHash = Get-NormalizedHash -Hash (Get-RowColumnValue -Row $row -ColumnName $BinaryHashColumn)

        $vulnerability = $null
        if (-not [string]::IsNullOrWhiteSpace($binaryHash) -and $vulnerabilityByHash.ContainsKey($binaryHash)) {
            $vulnerability = $vulnerabilityByHash[$binaryHash]
            $withVulnerability = $withVulnerability + 1
        }

        $enrichment = New-BinaryEnrichmentFromVulnerability -BinaryUid $binaryUid -Vulnerability $vulnerability
        $enrichments += $enrichment
        $processed = $processed + 1

        if ($enrichments.Count -ge $BatchSize) {
            Write-Information "Sending batch of $($enrichments.Count) enrichments..."
            Send-EnrichmentBatch -Batch $enrichments -ApiUrl $enrichmentUrl -BatchDomain $Domain -AttemptLimit $MaxAttempts -TokenState ([ref]$tokenState) -RefreshToken $refreshToken
            $enrichments = @()
        }
    }

    if ($enrichments.Count -gt 0) {
        Write-Information "Sending final batch of $($enrichments.Count) enrichments..."
        Send-EnrichmentBatch -Batch $enrichments -ApiUrl $enrichmentUrl -BatchDomain $Domain -AttemptLimit $MaxAttempts -TokenState ([ref]$tokenState) -RefreshToken $refreshToken
    }
    $enrichmentUploadCompleted = $true

    Write-Information "Finished. Processed binaries: $processed | With vulnerability data: $withVulnerability | Skipped (missing UID): $skipped"
    if ($falconDataReady -and $enrichmentUploadCompleted) {
        Remove-TemporaryWorkingFiles -Paths @($exportFilePath, $vulnerabilityCachePath)
    }
} catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
}
