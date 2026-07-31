Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$script:CrowdStrikeSession = [PSCustomObject]@{
    BaseUrl         = $null
    ClientId        = $null
    ClientSecret    = $null
    AccessToken     = $null
    TokenAcquired   = $null
    Proxy           = $null
    ProxyCredential = $null
}

<#
.SYNOPSIS
Creates or refreshes an authenticated CrowdStrike API session.

.DESCRIPTION
Requests an OAuth2 access token from CrowdStrike and stores session context
(base URL, token, proxy settings, and client credentials) in module scope.

.PARAMETER ClientId
CrowdStrike API client ID.

.PARAMETER ClientSecret
CrowdStrike API client secret.

.PARAMETER BaseUrl
CrowdStrike API base URL. Defaults to the EU-1 cloud endpoint.

.PARAMETER Proxy
Optional proxy URL for all API calls.

.PARAMETER ProxyCredential
Optional proxy credentials.

.OUTPUTS
System.Management.Automation.PSCustomObject
CrowdStrike session information including token metadata.

.EXAMPLE
Connect-CrowdStrikeApi -ClientId $ClientId -ClientSecret $ClientSecret
#>
function Connect-CrowdStrikeApi {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$ClientSecret,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUrl = 'https://api.eu-1.crowdstrike.com',

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    $effectiveProxy = if ($PSBoundParameters.ContainsKey('Proxy')) { $Proxy } else { $script:CrowdStrikeSession.Proxy }
    $effectiveProxyCredential = if ($PSBoundParameters.ContainsKey('ProxyCredential')) { $ProxyCredential } else { $script:CrowdStrikeSession.ProxyCredential }

    $rawBaseUrl = [string]$BaseUrl
    if ([string]::IsNullOrWhiteSpace($rawBaseUrl) -or $rawBaseUrl -in @('True', 'False')) {
        throw "Invalid BaseUrl value '$rawBaseUrl'. Provide a full CrowdStrike API URL such as 'https://api.eu-1.crowdstrike.com'."
    }

    $parsedBaseUrl = $null
    $isValidBaseUrl = [Uri]::TryCreate($rawBaseUrl, [System.UriKind]::Absolute, [ref]$parsedBaseUrl)
    if (-not $isValidBaseUrl -or $null -eq $parsedBaseUrl -or [string]::IsNullOrWhiteSpace($parsedBaseUrl.Host) -or ($parsedBaseUrl.Scheme -notin @('http', 'https'))) {
        throw "Invalid BaseUrl value '$rawBaseUrl'. Provide a valid absolute http/https URL such as 'https://api.eu-1.crowdstrike.com'."
    }

    $normalizedBaseUrl = $parsedBaseUrl.GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')
    $script:CrowdStrikeSession.BaseUrl = $normalizedBaseUrl
    $script:CrowdStrikeSession.ClientId = $ClientId
    $script:CrowdStrikeSession.ClientSecret = $ClientSecret
    $script:CrowdStrikeSession.Proxy = $effectiveProxy
    $script:CrowdStrikeSession.ProxyCredential = $effectiveProxyCredential

    $tokenParams = @{
        Method = 'Post'
        Uri    = "$normalizedBaseUrl/oauth2/token"
        ContentType = 'application/x-www-form-urlencoded'
        Body   = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($effectiveProxy)) {
        $tokenParams.Proxy = $effectiveProxy
        if ($effectiveProxyCredential) {
            $tokenParams.ProxyCredential = $effectiveProxyCredential
        }
    }

    try {
        $tokenResponse = Invoke-RestMethod @tokenParams
    }
    catch {
        $proxyInfo = if ([string]::IsNullOrWhiteSpace($effectiveProxy)) { '<none>' } else { $effectiveProxy }
        throw "Failed to retrieve CrowdStrike OAuth token from '$($tokenParams.Uri)' (proxy: $proxyInfo). Original error: $($_.Exception.Message)"
    }
    $script:CrowdStrikeSession.AccessToken = $tokenResponse.access_token
    $script:CrowdStrikeSession.TokenAcquired = Get-Date

    return $script:CrowdStrikeSession
}

function Invoke-CrowdStrikeApiRequest {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter()]
        [hashtable]$Query,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [int]$MaxRetries = 5,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    if ([string]::IsNullOrWhiteSpace($script:CrowdStrikeSession.AccessToken)) {
        throw 'No active CrowdStrike session. Call Connect-CrowdStrikeApi first.'
    }

    if ([string]::IsNullOrWhiteSpace([string]$script:CrowdStrikeSession.BaseUrl) -or ([string]$script:CrowdStrikeSession.BaseUrl) -in @('True', 'False')) {
        throw "Invalid CrowdStrike session BaseUrl '$($script:CrowdStrikeSession.BaseUrl)'. Reconnect with Connect-CrowdStrikeApi -BaseUrl 'https://api.eu-1.crowdstrike.com'."
    }

    $effectiveProxy = if ($PSBoundParameters.ContainsKey('Proxy')) { $Proxy } else { $script:CrowdStrikeSession.Proxy }
    $effectiveProxyCredential = if ($PSBoundParameters.ContainsKey('ProxyCredential')) { $ProxyCredential } else { $script:CrowdStrikeSession.ProxyCredential }

    if ($script:CrowdStrikeSession.TokenAcquired -and (((Get-Date) - $script:CrowdStrikeSession.TokenAcquired).TotalMinutes -ge 25)) {
        Connect-CrowdStrikeApi -ClientId $script:CrowdStrikeSession.ClientId -ClientSecret $script:CrowdStrikeSession.ClientSecret -BaseUrl $script:CrowdStrikeSession.BaseUrl -Proxy $effectiveProxy -ProxyCredential $effectiveProxyCredential | Out-Null
    }

    $url = "$($script:CrowdStrikeSession.BaseUrl)$Path"
    if ($Query -and $Query.Count -gt 0) {
        $encodedPairs = foreach ($key in $Query.Keys) {
            $queryValue = $Query[$key]
            if ($null -eq $queryValue) {
                continue
            }

            if ($queryValue -is [System.Collections.IEnumerable] -and -not ($queryValue -is [string])) {
                foreach ($item in $queryValue) {
                    if ($null -eq $item) { continue }
                    '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$item)
                }
                continue
            }

            '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$queryValue)
        }

        if ($encodedPairs) {
            $url = "${url}?" + ($encodedPairs -join '&')
        }
    }

    $headers = @{
        Authorization = "Bearer $($script:CrowdStrikeSession.AccessToken)"
        Accept        = 'application/json'
    }

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            $invokeParams = @{
                Method  = $Method
                Uri     = $url
                Headers = $headers
            }

            if ($PSBoundParameters.ContainsKey('Body')) {
                $invokeParams.ContentType = 'application/json'
                $invokeParams.Body = ($Body | ConvertTo-Json -Depth 20)
            }

            if (-not [string]::IsNullOrWhiteSpace($effectiveProxy)) {
                $invokeParams.Proxy = $effectiveProxy
                if ($effectiveProxyCredential) {
                    $invokeParams.ProxyCredential = $effectiveProxyCredential
                }
            }

            return Invoke-RestMethod @invokeParams
        }
        catch {
            $requestException = $_.Exception
            $statusCode = $null
            if ($requestException.Response -and $requestException.Response.StatusCode) {
                $statusCode = [int]$requestException.Response.StatusCode
            }

            $webException = $requestException -as [System.Net.WebException]
            $webExceptionStatus = $null
            if ($null -ne $webException) {
                $webExceptionStatus = [string]$webException.Status
            }

            $timeoutLikeFailure = $false
            if ($statusCode -in @(408, 504)) {
                $timeoutLikeFailure = $true
            }
            elseif ($webExceptionStatus -in @('Timeout', 'ConnectFailure', 'ConnectionClosed', 'KeepAliveFailure', 'ReceiveFailure', 'SendFailure')) {
                $timeoutLikeFailure = $true
            }
            elseif ([string]$requestException.Message -match '(?i)timed out|timeout|request was canceled|operation was canceled|task was canceled') {
                $timeoutLikeFailure = $true
            }

            if ($statusCode -in @(401, 403) -and $attempt -lt $MaxRetries) {
                Write-Verbose ("CrowdStrike API request retry: status={0}, attempt={1}/{2}, action=refresh_token" -f $statusCode, ($attempt + 1), ($MaxRetries + 1))
                Connect-CrowdStrikeApi -ClientId $script:CrowdStrikeSession.ClientId -ClientSecret $script:CrowdStrikeSession.ClientSecret -BaseUrl $script:CrowdStrikeSession.BaseUrl -Proxy $effectiveProxy -ProxyCredential $effectiveProxyCredential | Out-Null
                $headers.Authorization = "Bearer $($script:CrowdStrikeSession.AccessToken)"
                continue
            }

            if ($timeoutLikeFailure -and $attempt -lt $MaxRetries) {
                Write-Verbose ("CrowdStrike API request retry: timeout/transient failure detected (status={0}, web_status={1}), attempt={2}/{3}, action=refresh_token_and_retry" -f $statusCode, $webExceptionStatus, ($attempt + 1), ($MaxRetries + 1))
                Connect-CrowdStrikeApi -ClientId $script:CrowdStrikeSession.ClientId -ClientSecret $script:CrowdStrikeSession.ClientSecret -BaseUrl $script:CrowdStrikeSession.BaseUrl -Proxy $effectiveProxy -ProxyCredential $effectiveProxyCredential | Out-Null
                $headers.Authorization = "Bearer $($script:CrowdStrikeSession.AccessToken)"
                Start-Sleep -Seconds ([Math]::Min(30, 3 * ($attempt + 1)))
                continue
            }

            if (($statusCode -eq 429 -or $statusCode -eq 503) -and $attempt -lt $MaxRetries) {
                Write-Verbose ("CrowdStrike API request retry: throttled/unavailable status={0}, attempt={1}/{2}" -f $statusCode, ($attempt + 1), ($MaxRetries + 1))
                Start-Sleep -Seconds ([Math]::Min(60, 5 * ($attempt + 1)))
                continue
            }

            throw
        }
    }
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName,

        [Parameter()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) {
        return $DefaultValue
    }

    $prop = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $prop) {
        return $DefaultValue
    }

    return $prop.Value
}

function Get-FqlEscapedValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return $Value.Replace("'", "''")
}

function Get-NormalizedHash {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$FileHash
    )

    if ([string]::IsNullOrWhiteSpace($FileHash)) {
        return $null
    }

    $normalized = $FileHash.Trim()

    # Accept quoted hash strings (for example values copied from JSON/CSV: "abc..." or 'abc...')
    if ($normalized.Length -ge 2) {
        if (($normalized.StartsWith('"') -and $normalized.EndsWith('"')) -or ($normalized.StartsWith("'") -and $normalized.EndsWith("'"))) {
            $normalized = $normalized.Substring(1, $normalized.Length - 2).Trim()
        }
    }

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    return $normalized.ToLowerInvariant()
}

function Add-ListMapItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Map,

        [Parameter()]
        [AllowNull()]
        [string]$Key,

        [Parameter()]
        [AllowNull()]
        [object]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Key) -or $null -eq $Value) {
        return
    }

    if (-not $Map.ContainsKey($Key)) {
        $Map[$Key] = New-Object System.Collections.Generic.List[object]
    }

    $Map[$Key].Add($Value)
}

function Convert-ToObjectArraySafe {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return @()
    }

    if ($InputObject -is [string]) {
        return @([string]$InputObject)
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $results = New-Object System.Collections.Generic.List[object]
        foreach ($item in $InputObject) {
            $results.Add($item)
        }

        return @($results.ToArray())
    }

    return @($InputObject)
}

function Test-ExploitAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [Nullable[int]]$ExploitStatus,

        [Parameter()]
        [Nullable[bool]]$IsCisaKev
    )

    if ($IsCisaKev -eq $true) {
        return $true
    }

    if ($null -eq $ExploitStatus) {
        return $false
    }

    return @('1', '2', '3') -contains ([string]$ExploitStatus)
}

function Get-CrowdStrikeDiscoverApplicationIdsByFilter {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Filter,

        [Parameter()]
        [int]$PageSize = 100,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential,
        [Parameter()]
        [switch]$FirstOnly
    )

    if ($PageSize -lt 1 -or $PageSize -gt 100) {
        throw 'PageSize must be in range 1..100 for Discover application queries.'
    }

    $ids = New-Object System.Collections.Generic.List[string]
    $offset = 0
    $limit = if ($FirstOnly) { 1 } else { [Math]::Min($PageSize, 100) }
    Write-Verbose ("Discover/queries applications: filter='{0}', limit={1}" -f $Filter, $limit)

    while ($true) {
        $query = @{
            filter = $Filter
            limit  = [string]$limit
            offset = [string]$offset
        }

        $response = Invoke-CrowdStrikeApiRequest -Method GET -Path '/discover/queries/applications/v1' -Query $query -Proxy $Proxy -ProxyCredential $ProxyCredential
        $resources = @(Get-ObjectPropertyValue -InputObject $response -PropertyName 'resources' -DefaultValue @())
        Write-Verbose ("Discover/queries page: offset={0}, received_ids={1}" -f $offset, @($resources).Count)
        foreach ($resourceId in $resources) {
            $normalizedId = [string]$resourceId
            if (-not [string]::IsNullOrWhiteSpace($normalizedId)) {
                $ids.Add($normalizedId)
            }
        }

        if ($FirstOnly -and $ids.Count -gt 0) {
            break
        }

        if (@($resources).Count -lt $limit) {
            break
        }

        $meta = Get-ObjectPropertyValue -InputObject $response -PropertyName 'meta'
        $pagination = Get-ObjectPropertyValue -InputObject $meta -PropertyName 'pagination'
        $pageOffset = [int](Get-ObjectPropertyValue -InputObject $pagination -PropertyName 'offset' -DefaultValue $offset)
        $pageLimit = [int](Get-ObjectPropertyValue -InputObject $pagination -PropertyName 'limit' -DefaultValue $limit)
        $pageTotal = [int](Get-ObjectPropertyValue -InputObject $pagination -PropertyName 'total' -DefaultValue -1)
        $nextOffset = $pageOffset + $pageLimit

        if ($pageTotal -ge 0 -and $nextOffset -ge $pageTotal) {
            break
        }

        if ($nextOffset -le $offset) {
            break
        }

        $offset = $nextOffset
    }

    $uniqueIds = @($ids | Select-Object -Unique)
    Write-Verbose ("Discover/queries complete: unique_application_ids={0}" -f @($uniqueIds).Count)
    return $uniqueIds
}

function Get-CrowdStrikeDiscoverApplicationIdsByHashSet {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string[]]$FileHashes,

        [Parameter()]
        [int]$PageSize = 100,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential,
        [Parameter()]
        [switch]$FirstOnly
    )

    if ($PageSize -lt 1 -or $PageSize -gt 1000) {
        throw 'PageSize must be in range 1..1000 for Discover applications.'
    }

    $normalizedHashes = @(
        $FileHashes |
        ForEach-Object { Get-NormalizedHash -FileHash ([string]$_) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )

    if (@($normalizedHashes).Count -eq 0) {
        return @()
    }
    Write-Verbose ("Discover hash lookup: normalized_hashes={0}" -f ($normalizedHashes -join ','))

    $hashLiteral = ($normalizedHashes | ForEach-Object { "'$(Get-FqlEscapedValue -Value $_)'" }) -join ','
    $listFilter = "last_used_file_hash:[$hashLiteral]"
    $singleFilter = "last_used_file_hash:'$(Get-FqlEscapedValue -Value $normalizedHashes[0])'"
    $limit = if ($FirstOnly) { 1 } else { [Math]::Min($PageSize, 100) }

    $filterCandidates = @($listFilter)
    if ($normalizedHashes.Count -eq 1) {
        $filterCandidates += $singleFilter
    }

    $lastError = $null
    foreach ($filter in $filterCandidates) {
        try {
            Write-Verbose ("Discover hash lookup: trying filter='{0}'" -f $filter)
            $ids = @(Get-CrowdStrikeDiscoverApplicationIdsByFilter -Filter $filter -PageSize $limit -Proxy $Proxy -ProxyCredential $ProxyCredential -FirstOnly:$FirstOnly)
            if ($FirstOnly -and @($ids).Count -gt 0) {
                $ids = @($ids[0])
            }
            Write-Verbose ("Discover hash lookup: filter succeeded, ids={0}" -f @($ids).Count)
            return $ids
        }
        catch {
            $lastError = $_
            Write-Verbose ("Discover hash lookup: filter failed -> {0}" -f $_.Exception.Message)
            continue
        }
    }

    if ($lastError) {
        throw "Discover hash query failed for hashes '$($normalizedHashes -join ',')'. Last error: $($lastError.Exception.Message)"
    }

    return @()
}

function Get-CrowdStrikeDiscoverApplicationByIdSet {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string[]]$ApplicationIds,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    $normalizedIds = @(
        $ApplicationIds |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        ForEach-Object { [string]$_ } |
        Select-Object -Unique
    )

    if (@($normalizedIds).Count -eq 0) {
        return @()
    }
    Write-Verbose ("Discover/entities applications: requested_ids={0}" -f @($normalizedIds).Count)

    $resultsById = @{}
    $chunkSize = 100

    for ($index = 0; $index -lt $normalizedIds.Count; $index += $chunkSize) {
        $endIndex = [Math]::Min($index + $chunkSize - 1, $normalizedIds.Count - 1)
        $batchIds = @($normalizedIds[$index..$endIndex])
        Write-Verbose ("Discover/entities applications: chunk_start={0}, chunk_ids={1}" -f $index, @($batchIds).Count)

        $responses = New-Object System.Collections.Generic.List[object]
        $batchHandled = $false
        $lastError = $null

        try {
            $responses.Add((Invoke-CrowdStrikeApiRequest -Method GET -Path '/discover/entities/applications/v1' -Query @{ ids = $batchIds } -Proxy $Proxy -ProxyCredential $ProxyCredential))
            $batchHandled = $true
            Write-Verbose ("Discover/entities applications: chunk_start={0} used query ids[]=multi" -f $index)
        }
        catch {
            $lastError = $_
            Write-Verbose ("Discover/entities applications: chunk_start={0} ids[]=multi failed -> {1}" -f $index, $_.Exception.Message)
        }

        if (-not $batchHandled) {
            try {
                $responses.Add((Invoke-CrowdStrikeApiRequest -Method GET -Path '/discover/entities/applications/v1' -Query @{ ids = ($batchIds -join ',') } -Proxy $Proxy -ProxyCredential $ProxyCredential))
                $batchHandled = $true
                Write-Verbose ("Discover/entities applications: chunk_start={0} used query ids=csv" -f $index)
            }
            catch {
                $lastError = $_
                Write-Verbose ("Discover/entities applications: chunk_start={0} ids=csv failed -> {1}" -f $index, $_.Exception.Message)
            }
        }

        if (-not $batchHandled) {
            foreach ($singleId in $batchIds) {
                $singleHandled = $false
                try {
                    $responses.Add((Invoke-CrowdStrikeApiRequest -Method GET -Path '/discover/entities/applications/v1' -Query @{ ids = @([string]$singleId) } -Proxy $Proxy -ProxyCredential $ProxyCredential))
                    $singleHandled = $true
                    Write-Verbose ("Discover/entities applications: single id '{0}' used ids[]=single" -f $singleId)
                }
                catch {
                    $lastError = $_
                }

                if (-not $singleHandled) {
                    try {
                        $responses.Add((Invoke-CrowdStrikeApiRequest -Method GET -Path '/discover/entities/applications/v1' -Query @{ ids = [string]$singleId } -Proxy $Proxy -ProxyCredential $ProxyCredential))
                        $singleHandled = $true
                        Write-Verbose ("Discover/entities applications: single id '{0}' used ids=single" -f $singleId)
                    }
                    catch {
                        $lastError = $_
                    }
                }

                if (-not $singleHandled) {
                    throw "Discover entities lookup failed for application id '$singleId'. Last error: $($lastError.Exception.Message)"
                }
            }
        }

        foreach ($response in $responses) {
            foreach ($resource in @(Get-ObjectPropertyValue -InputObject $response -PropertyName 'resources' -DefaultValue @())) {
                $resourceId = [string](Get-ObjectPropertyValue -InputObject $resource -PropertyName 'id' -DefaultValue '')
                if ([string]::IsNullOrWhiteSpace($resourceId)) {
                    continue
                }

                $resultsById[$resourceId] = $resource
            }
        }
        Write-Verbose ("Discover/entities applications: accumulated_unique_entities={0}" -f $resultsById.Count)
    }

    $orderedResults = New-Object System.Collections.Generic.List[object]
    foreach ($applicationId in $normalizedIds) {
        if ($resultsById.ContainsKey($applicationId)) {
            $orderedResults.Add($resultsById[$applicationId])
        }
    }

    Write-Verbose ("Discover/entities applications complete: entities={0}" -f $orderedResults.Count)
    return @(Convert-ToObjectArraySafe -InputObject $orderedResults)
}

function Get-CrowdStrikeSpotlightVulnerabilityIdsByFilter {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Filter,

        [Parameter()]
        [int]$PageSize = 400,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    if ($PageSize -lt 1 -or $PageSize -gt 400) {
        throw 'PageSize must be in range 1..400 for Spotlight vulnerability queries.'
    }

    $results = New-Object System.Collections.Generic.List[string]
    $limit = [Math]::Min($PageSize, 400)
    $after = $null
    Write-Verbose ("Spotlight/queries vulnerabilities: filter='{0}', limit={1}" -f $Filter, $limit)

    do {
        $query = @{
            filter = $Filter
            limit  = [string]$limit
            sort   = 'updated_timestamp|desc'
        }

        if ($after) {
            $query.after = $after
        }

        $response = Invoke-CrowdStrikeApiRequest -Method GET -Path '/spotlight/queries/vulnerabilities/v1' -Query $query -Proxy $Proxy -ProxyCredential $ProxyCredential
        $resources = @(Get-ObjectPropertyValue -InputObject $response -PropertyName 'resources' -DefaultValue @())
        Write-Verbose ("Spotlight/queries vulnerabilities page: after='{0}', received_ids={1}" -f ([string]$after), @($resources).Count)
        foreach ($resourceId in $resources) {
            $normalizedId = [string]$resourceId
            if (-not [string]::IsNullOrWhiteSpace($normalizedId)) {
                $results.Add($normalizedId)
            }
        }

        $meta = Get-ObjectPropertyValue -InputObject $response -PropertyName 'meta'
        $pagination = Get-ObjectPropertyValue -InputObject $meta -PropertyName 'pagination'
        $after = [string](Get-ObjectPropertyValue -InputObject $pagination -PropertyName 'after' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($after)) {
            $after = $null
        }
    } while ($after)

    $uniqueIds = @($results | Select-Object -Unique)
    Write-Verbose ("Spotlight/queries vulnerabilities complete: unique_ids={0}" -f @($uniqueIds).Count)
    return $uniqueIds
}

function Get-CrowdStrikeSpotlightVulnerabilityByIdSet {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string[]]$VulnerabilityIds,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    $normalizedIds = @(
        $VulnerabilityIds |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { [string]$_ } |
            Select-Object -Unique
    )

    if (@($normalizedIds).Count -eq 0) {
        return @()
    }
    Write-Verbose ("Spotlight/entities vulnerabilities: requested_ids={0}" -f @($normalizedIds).Count)

    $results = New-Object System.Collections.Generic.List[object]
    $chunkSize = 400

    for ($index = 0; $index -lt $normalizedIds.Count; $index += $chunkSize) {
        $endIndex = [Math]::Min($index + $chunkSize - 1, $normalizedIds.Count - 1)
        $batchIds = @($normalizedIds[$index..$endIndex])
        Write-Verbose ("Spotlight/entities vulnerabilities: chunk_start={0}, chunk_ids={1}" -f $index, @($batchIds).Count)
        $response = Invoke-CrowdStrikeApiRequest -Method GET -Path '/spotlight/entities/vulnerabilities/v2' -Query @{ ids = $batchIds } -Proxy $Proxy -ProxyCredential $ProxyCredential

        foreach ($resource in @(Get-ObjectPropertyValue -InputObject $response -PropertyName 'resources' -DefaultValue @())) {
            $results.Add($resource)
        }
        Write-Verbose ("Spotlight/entities vulnerabilities: accumulated_entities={0}" -f $results.Count)
    }

    $entities = @(Convert-ToObjectArraySafe -InputObject $results)
    Write-Verbose ("Spotlight/entities vulnerabilities complete: entities={0}" -f @($entities).Count)
    return $entities
}

function Get-CrowdStrikeSpotlightVulnerabilitiesByAidBatch {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Aids,

        [Parameter()]
        [int]$PageSize = 5000,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    if ($PageSize -lt 1 -or $PageSize -gt 5000) {
        throw 'PageSize must be in range 1..5000 for Spotlight vulnerabilities.'
    }

    $normalizedAids = @($Aids | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ } | Select-Object -Unique)
    if (@($normalizedAids).Count -eq 0) {
        return @()
    }
    Write-Verbose ("Spotlight lookup by clients: aid_count={0}" -f @($normalizedAids).Count)

    $queryLimit = [Math]::Min($PageSize, 100)
    $aidLiteral = ($normalizedAids | ForEach-Object { "'$(Get-FqlEscapedValue -Value $_)'" }) -join ','
    $baseTail = "status:['open','reopen']+suppression_info.is_suppressed:false"
    $filterCandidates = @("aid:[$aidLiteral]+$baseTail")
    if ($normalizedAids.Count -eq 1) {
        $filterCandidates += "aid:'$(Get-FqlEscapedValue -Value $normalizedAids[0])'+$baseTail"
    }

    $lastError = $null
    foreach ($filter in $filterCandidates) {
        try {
            Write-Verbose ("Spotlight lookup by clients: trying filter='{0}'" -f $filter)
            $vulnerabilityIds = @(Get-CrowdStrikeSpotlightVulnerabilityIdsByFilter -Filter $filter -PageSize $queryLimit -Proxy $Proxy -ProxyCredential $ProxyCredential)
            Write-Verbose ("Spotlight lookup by clients: filter succeeded, vulnerability_ids={0}" -f @($vulnerabilityIds).Count)
            $vulnerabilities = @(Get-CrowdStrikeSpotlightVulnerabilityByIdSet -VulnerabilityIds $vulnerabilityIds -Proxy $Proxy -ProxyCredential $ProxyCredential)
            Write-Verbose ("Spotlight lookup by clients: vulnerability_entities={0}" -f @($vulnerabilities).Count)
            return $vulnerabilities
        }
        catch {
            $lastError = $_
            Write-Verbose ("Spotlight lookup by clients: filter failed -> {0}" -f $_.Exception.Message)
            continue
        }
    }

    $fallbackVulnerabilityIds = New-Object System.Collections.Generic.List[string]
    foreach ($aidValue in $normalizedAids) {
        $singleFilter = "aid:'$(Get-FqlEscapedValue -Value $aidValue)'+$baseTail"
        try {
            Write-Verbose ("Spotlight lookup by clients fallback: querying aid='{0}'" -f $aidValue)
            foreach ($vulnId in @(Get-CrowdStrikeSpotlightVulnerabilityIdsByFilter -Filter $singleFilter -PageSize $queryLimit -Proxy $Proxy -ProxyCredential $ProxyCredential)) {
                $fallbackVulnerabilityIds.Add([string]$vulnId)
            }
        }
        catch {
            $lastError = $_
            continue
        }
    }

    $uniqueFallbackIds = @($fallbackVulnerabilityIds | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    if (@($uniqueFallbackIds).Count -gt 0) {
        Write-Verbose ("Spotlight lookup by clients fallback: unique_vulnerability_ids={0}" -f @($uniqueFallbackIds).Count)
        $vulnerabilities = @(Get-CrowdStrikeSpotlightVulnerabilityByIdSet -VulnerabilityIds $uniqueFallbackIds -Proxy $Proxy -ProxyCredential $ProxyCredential)
        Write-Verbose ("Spotlight lookup by clients fallback: vulnerability_entities={0}" -f @($vulnerabilities).Count)
        return $vulnerabilities
    }

    if ($lastError) {
        throw "Spotlight vulnerability lookup failed for aids '$($normalizedAids -join ',')'. Last error: $($lastError.Exception.Message)"
    }

    return @()
}

function Get-CrowdStrikeFirstDiscoverEntryByHash {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Hash,

        [Parameter(Mandatory)]
        [object[]]$Applications
    )

    foreach ($application in $Applications) {
        $hostInfo = Get-ObjectPropertyValue -InputObject $application -PropertyName 'host'
        $aid = [string](Get-ObjectPropertyValue -InputObject $hostInfo -PropertyName 'aid' -DefaultValue '')
        $applicationName = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'name' -DefaultValue '')
        $vendor = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'vendor' -DefaultValue '')
        if ([string]::IsNullOrWhiteSpace($aid) -or [string]::IsNullOrWhiteSpace($applicationName)) {
            continue
        }

        return [PSCustomObject]@{
            FileHash          = $Hash
            LastUsedFileHash  = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_file_hash' -DefaultValue $Hash)
            LastUsedFileName  = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_file_name' -DefaultValue '')
            LastUsedTimestamp = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_timestamp' -DefaultValue '')
            LastUsedUserName  = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_user_name' -DefaultValue '')
            LastUsedUserSid   = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_user_sid' -DefaultValue '')
            Aid               = $aid
            Hostname          = [string](Get-ObjectPropertyValue -InputObject $hostInfo -PropertyName 'hostname' -DefaultValue '')
            PlatformName      = [string](Get-ObjectPropertyValue -InputObject $hostInfo -PropertyName 'platform_name' -DefaultValue '')
            OsVersion         = [string](Get-ObjectPropertyValue -InputObject $hostInfo -PropertyName 'os_version' -DefaultValue '')
            ApplicationName   = $applicationName
            Vendor            = $vendor
            Version           = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'version' -DefaultValue '')
            NameVendorVersion = [string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'name_vendor_version' -DefaultValue '')
        }
    }

    return $null
}

function Get-CrowdStrikeSpotlightFirstVulnerabilityMatchForDiscoverEntry {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$DiscoverEntry,

        [Parameter()]
        [int]$PageSize = 5000,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    $aid = [string](Get-ObjectPropertyValue -InputObject $DiscoverEntry -PropertyName 'Aid' -DefaultValue '')
    $applicationName = [string](Get-ObjectPropertyValue -InputObject $DiscoverEntry -PropertyName 'ApplicationName' -DefaultValue '')
    $vendor = [string](Get-ObjectPropertyValue -InputObject $DiscoverEntry -PropertyName 'Vendor' -DefaultValue '')
    if ([string]::IsNullOrWhiteSpace($aid) -or [string]::IsNullOrWhiteSpace($applicationName)) {
        return $null
    }

    $normalizedAppName = $applicationName.Trim().ToLowerInvariant()
    $normalizedVendor = $vendor.Trim().ToLowerInvariant()
    $queryLimit = [Math]::Min($PageSize, 400)
    $baseTail = "status:['open','reopen']+suppression_info.is_suppressed:false"
    $filterCandidates = @(
        "aid:['$(Get-FqlEscapedValue -Value $aid)']+$baseTail"
        "aid:'$(Get-FqlEscapedValue -Value $aid)'+$baseTail"
    )

    $lastError = $null
    foreach ($filter in $filterCandidates) {
        try {
            Write-Verbose ("Spotlight first-match: trying filter='{0}' for hash='{1}' app='{2}' vendor='{3}'" -f $filter, [string]$DiscoverEntry.FileHash, $applicationName, $vendor)
            $after = $null

            do {
                $query = @{
                    filter = $filter
                    limit  = [string]$queryLimit
                    sort   = 'updated_timestamp|desc'
                }
                if ($after) {
                    $query.after = $after
                }

                $queryResponse = Invoke-CrowdStrikeApiRequest -Method GET -Path '/spotlight/queries/vulnerabilities/v1' -Query $query -Proxy $Proxy -ProxyCredential $ProxyCredential
                $vulnerabilityIds = @(Get-ObjectPropertyValue -InputObject $queryResponse -PropertyName 'resources' -DefaultValue @())
                Write-Verbose ("Spotlight first-match: received vulnerability ids={0}" -f @($vulnerabilityIds).Count)

                if (@($vulnerabilityIds).Count -gt 0) {
                    $vulnerabilities = @(Get-CrowdStrikeSpotlightVulnerabilityByIdSet -VulnerabilityIds $vulnerabilityIds -Proxy $Proxy -ProxyCredential $ProxyCredential)
                    $firstAidOnlyCandidate = $null
                    foreach ($vulnerability in $vulnerabilities) {
                        $cveInfo = Get-ObjectPropertyValue -InputObject $vulnerability -PropertyName 'cve'
                        if ($null -eq $cveInfo) {
                            continue
                        }

                        if ($null -eq $firstAidOnlyCandidate) {
                            $firstAidOnlyCandidate = $vulnerability
                        }

                        $fallbackApp = $null
                        foreach ($vulnerabilityApp in @(Get-ObjectPropertyValue -InputObject $vulnerability -PropertyName 'apps' -DefaultValue @())) {
                            $productName = [string](Get-ObjectPropertyValue -InputObject $vulnerabilityApp -PropertyName 'product_name_normalized' -DefaultValue '')
                            if ([string]::IsNullOrWhiteSpace($productName) -or $productName.Trim().ToLowerInvariant() -ne $normalizedAppName) {
                                continue
                            }

                            $vulnVendor = [string](Get-ObjectPropertyValue -InputObject $vulnerabilityApp -PropertyName 'vendor_normalized' -DefaultValue '')
                            $normalizedVulnVendor = $vulnVendor.Trim().ToLowerInvariant()

                            if ([string]::IsNullOrWhiteSpace($normalizedVendor) -or $normalizedVendor -eq $normalizedVulnVendor) {
                                return [PSCustomObject]@{
                                    Vulnerability   = $vulnerability
                                    VulnerabilityApp = $vulnerabilityApp
                                    MatchType       = 'aid+name+vendor'
                                }
                            }

                            if ($null -eq $fallbackApp) {
                                $fallbackApp = $vulnerabilityApp
                            }
                        }

                        if ($null -ne $fallbackApp) {
                            return [PSCustomObject]@{
                                Vulnerability   = $vulnerability
                                VulnerabilityApp = $fallbackApp
                                MatchType       = 'aid+name'
                            }
                        }
                    }

                    if ($null -ne $firstAidOnlyCandidate) {
                        Write-Verbose ("Spotlight first-match: no app-name match found, using first aid-level vulnerability as global finding")
                        return [PSCustomObject]@{
                            Vulnerability    = $firstAidOnlyCandidate
                            VulnerabilityApp = $null
                            MatchType        = 'aid-only'
                        }
                    }
                }

                $meta = Get-ObjectPropertyValue -InputObject $queryResponse -PropertyName 'meta'
                $pagination = Get-ObjectPropertyValue -InputObject $meta -PropertyName 'pagination'
                $after = [string](Get-ObjectPropertyValue -InputObject $pagination -PropertyName 'after' -DefaultValue '')
                if ([string]::IsNullOrWhiteSpace($after)) {
                    $after = $null
                }
            } while ($after)
        }
        catch {
            $lastError = $_
            Write-Verbose ("Spotlight first-match: filter failed -> {0}" -f $_.Exception.Message)
            continue
        }
    }

    if ($lastError) {
        throw "Spotlight first-match failed for aid '$aid' app '$applicationName'. Last error: $($lastError.Exception.Message)"
    }

    return $null
}

function ConvertTo-CrowdStrikeHashVulnerabilityRow {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [object]$DiscoverEntry,

        [Parameter(Mandatory)]
        [object]$Vulnerability,

        [Parameter()]
        [AllowNull()]
        [object]$VulnerabilityApp
    )

    $cveInfo = Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'cve'
    if ($null -eq $cveInfo) {
        return $null
    }

    $cisaInfo = Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'cisa_info'
    $rawRemediationLevel = [string](Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'remediation_level' -DefaultValue '')
    $normalizedRemediationLevel = $rawRemediationLevel.Trim().ToUpperInvariant()
    $cvssRemediationLevel = switch ($normalizedRemediationLevel) {
        'U' { 'Unavailable (U)' ; break }
        'UNAVAILABLE' { 'Unavailable (U)' ; break }
        'W' { 'Workaround (W)' ; break }
        'WORKAROUND' { 'Workaround (W)' ; break }
        'T' { 'Temporary Fix (T)' ; break }
        'TEMPORARY FIX' { 'Temporary Fix (T)' ; break }
        'TEMPORARY_FIX' { 'Temporary Fix (T)' ; break }
        'O' { 'Official Fix (O/OF)' ; break }
        'OF' { 'Official Fix (O/OF)' ; break }
        'OFFICIAL FIX' { 'Official Fix (O/OF)' ; break }
        'OFFICIAL_FIX' { 'Official Fix (O/OF)' ; break }
        'X' { 'Not Defined (X/ND)' ; break }
        'ND' { 'Not Defined (X/ND)' ; break }
        'NOT DEFINED' { 'Not Defined (X/ND)' ; break }
        'NOT_DEFINED' { 'Not Defined (X/ND)' ; break }
        '' { 'Not Defined (X/ND)' ; break }
        default { $rawRemediationLevel }
    }

    $aid = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'aid' -DefaultValue ([string]$DiscoverEntry.Aid))
    $cveId = [string](Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'id' -DefaultValue '')
    $vulnerabilityLabel = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'vulnerability_id' -DefaultValue $cveId)

    $remediationIds = @{}

    $vulnerabilityRemediation = Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'remediation'
    foreach ($rid in @(Get-ObjectPropertyValue -InputObject $vulnerabilityRemediation -PropertyName 'ids' -DefaultValue @())) {
        $normalizedRid = [string]$rid
        if (-not [string]::IsNullOrWhiteSpace($normalizedRid)) {
            $remediationIds[$normalizedRid] = $true
        }
    }

    foreach ($remediationEntity in @(Get-ObjectPropertyValue -InputObject $vulnerabilityRemediation -PropertyName 'entities' -DefaultValue @())) {
        $entityId = [string](Get-ObjectPropertyValue -InputObject $remediationEntity -PropertyName 'id' -DefaultValue '')
        if (-not [string]::IsNullOrWhiteSpace($entityId)) {
            $remediationIds[$entityId] = $true
        }
    }

    $appRemediation = Get-ObjectPropertyValue -InputObject $VulnerabilityApp -PropertyName 'remediation'
    foreach ($rid in @(Get-ObjectPropertyValue -InputObject $appRemediation -PropertyName 'ids' -DefaultValue @())) {
        $normalizedRid = [string]$rid
        if (-not [string]::IsNullOrWhiteSpace($normalizedRid)) {
            $remediationIds[$normalizedRid] = $true
        }
    }

    $appRemediationInfo = Get-ObjectPropertyValue -InputObject $VulnerabilityApp -PropertyName 'remediation_info'
    $recommendedRemediationId = [string](Get-ObjectPropertyValue -InputObject $appRemediationInfo -PropertyName 'recommended_id' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($recommendedRemediationId)) {
        $remediationIds[$recommendedRemediationId] = $true
    }

    $minimumRemediationId = [string](Get-ObjectPropertyValue -InputObject $appRemediationInfo -PropertyName 'minimum_id' -DefaultValue '')
    if (-not [string]::IsNullOrWhiteSpace($minimumRemediationId)) {
        $remediationIds[$minimumRemediationId] = $true
    }

    $availableRemediationCount = $remediationIds.Count

    return [PSCustomObject]@{
        FileHash = [string]$DiscoverEntry.FileHash
        Detection = [PSCustomObject]@{
            LastUsedFileHash  = [string]$DiscoverEntry.LastUsedFileHash
            LastUsedFileName  = [string]$DiscoverEntry.LastUsedFileName
            LastUsedTimestamp = [string]$DiscoverEntry.LastUsedTimestamp
            LastUsedUserName  = [string]$DiscoverEntry.LastUsedUserName
            LastUsedUserSid   = [string]$DiscoverEntry.LastUsedUserSid
            Aid               = $aid
            Hostname          = [string]$DiscoverEntry.Hostname
            PlatformName      = [string]$DiscoverEntry.PlatformName
            OsVersion         = [string]$DiscoverEntry.OsVersion
        }
        Application = [PSCustomObject]@{
            Name    = [string]$DiscoverEntry.ApplicationName
            Vendor  = [string]$DiscoverEntry.Vendor
            Version = [string]$DiscoverEntry.Version
        }
        Vulnerability = [PSCustomObject]@{
            EntityId     = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'id' -DefaultValue '')
            Id           = $vulnerabilityLabel
            CveId        = $cveId
            Status       = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'status' -DefaultValue '')
            Category     = (@(Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'types' -DefaultValue @()) | Where-Object { $_ } | Select-Object -Unique) -join ', '
            ExprtRating  = [string](Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'exprt_rating' -DefaultValue '')
            Cvss         = [PSCustomObject]@{
                Severity           = [string](Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'severity' -DefaultValue '')
                BaseScore          = Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'base_score'
                ExploitabilityScore = Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'exploitability_score'
            }
            Exploit      = [PSCustomObject]@{
                Available = Test-ExploitAvailable -ExploitStatus (Get-ObjectPropertyValue -InputObject $cveInfo -PropertyName 'exploit_status') -IsCisaKev (Get-ObjectPropertyValue -InputObject $cisaInfo -PropertyName 'is_cisa_kev')
                IsCisaKev = Get-ObjectPropertyValue -InputObject $cisaInfo -PropertyName 'is_cisa_kev'
            }
            Remediation  = [PSCustomObject]@{
                Level          = $cvssRemediationLevel
                LevelCode      = $rawRemediationLevel
                AvailableCount = $availableRemediationCount
                FixAvailable   = ($availableRemediationCount -gt 0)
                RecommendedId  = $recommendedRemediationId
                MinimumId      = $minimumRemediationId
            }
            CreatedTimestamp = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'created_timestamp' -DefaultValue '')
            UpdatedTimestamp = [string](Get-ObjectPropertyValue -InputObject $Vulnerability -PropertyName 'updated_timestamp' -DefaultValue '')
        }
    }
}

<#
.SYNOPSIS
Retrieves one correlated Spotlight vulnerability finding per file hash.

.DESCRIPTION
For each file hash, this cmdlet executes a Discover -> application details ->
first client -> Spotlight vulnerability flow and returns one correlated row.
Hashes are normalized to lowercase before query execution.

.PARAMETER FileHashes
One or more file hashes (for example SHA256 values).

.PARAMETER ClientId
Optional CrowdStrike API client ID. When provided together with ClientSecret,
the cmdlet authenticates automatically.

.PARAMETER ClientSecret
Optional CrowdStrike API client secret used with ClientId.

.PARAMETER BaseUrl
CrowdStrike API base URL. Defaults to the EU-1 cloud endpoint.

.PARAMETER DiscoverPageSize
Discover query page size (1..1000).

.PARAMETER SpotlightPageSize
Spotlight query page size (1..5000).

.PARAMETER AidBatchSize
Reserved tuning parameter for client batching (1..100).

.PARAMETER HashBatchSize
Reserved tuning parameter for hash batching (1..100).

.PARAMETER Proxy
Optional proxy URL for all API calls.

.PARAMETER ProxyCredential
Optional proxy credentials.

.OUTPUTS
System.Management.Automation.PSCustomObject[]
Correlated rows with this nested structure:
- FileHash
- Detection (client/host and file usage context)
- Application (name, vendor, version)
- Vulnerability (CVE, CVSS, exploit, remediation, timestamps)

.EXAMPLE
Get-CrowdStrikeSoftwareVulnerabilityByHash -FileHashes $hashes

.EXAMPLE
Get-CrowdStrikeSoftwareVulnerabilityByHash -ClientId $ClientId -ClientSecret $ClientSecret -FileHashes $hashes -Verbose
#>
function Get-CrowdStrikeSoftwareVulnerabilityByHash {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [string[]]$FileHashes,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$ClientSecret,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUrl = 'https://api.eu-1.crowdstrike.com',

        [Parameter()]
        [int]$DiscoverPageSize = 1000,

        [Parameter()]
        [int]$SpotlightPageSize = 5000,

        [Parameter()]
        [int]$AidBatchSize = 50,

        [Parameter()]
        [int]$HashBatchSize = 20,

        [Parameter()]
        [string]$Proxy,

        [Parameter()]
        [System.Management.Automation.PSCredential]$ProxyCredential
    )

    if ($DiscoverPageSize -lt 1 -or $DiscoverPageSize -gt 1000) {
        throw 'DiscoverPageSize must be in range 1..1000.'
    }

    if ($SpotlightPageSize -lt 1 -or $SpotlightPageSize -gt 5000) {
        throw 'SpotlightPageSize must be in range 1..5000.'
    }

    if ($AidBatchSize -lt 1 -or $AidBatchSize -gt 100) {
        throw 'AidBatchSize must be in range 1..100.'
    }

    if ($HashBatchSize -lt 1 -or $HashBatchSize -gt 100) {
        throw 'HashBatchSize must be in range 1..100.'
    }

    if (-not [string]::IsNullOrWhiteSpace($ClientId) -or -not [string]::IsNullOrWhiteSpace($ClientSecret)) {
        if ([string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
            throw 'When one of ClientId or ClientSecret is provided, both must be provided.'
        }

        Connect-CrowdStrikeApi -ClientId $ClientId -ClientSecret $ClientSecret -BaseUrl $BaseUrl -Proxy $Proxy -ProxyCredential $ProxyCredential | Out-Null
    }
    elseif ([string]::IsNullOrWhiteSpace($script:CrowdStrikeSession.AccessToken)) {
        throw 'No active CrowdStrike session. Call Connect-CrowdStrikeApi first, or pass ClientId and ClientSecret.'
    }

    if ($PSBoundParameters.ContainsKey('Proxy')) {
        $script:CrowdStrikeSession.Proxy = $Proxy
        $script:CrowdStrikeSession.ProxyCredential = $ProxyCredential
    }

    $normalizedHashes = @(
        $FileHashes |
        ForEach-Object { Get-NormalizedHash -FileHash ([string]$_) } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )

    if (@($normalizedHashes).Count -eq 0) {
        return @()
    }
    Write-Verbose ("Start vulnerability by hash flow: hashes={0}" -f ($normalizedHashes -join ','))

    $discoverApplicationsByHash = @{}
    $discoverLookupErrors = New-Object System.Collections.Generic.List[string]
    foreach ($hash in $normalizedHashes) {
        try {
            Write-Verbose ("Discover first-client step: querying first application id for hash='{0}'" -f $hash)
            $firstIds = @(Get-CrowdStrikeDiscoverApplicationIdsByHashSet -FileHashes @($hash) -PageSize 1 -Proxy $Proxy -ProxyCredential $ProxyCredential -FirstOnly)
            if (@($firstIds).Count -eq 0) {
                Write-Verbose ("Discover first-client step: hash='{0}' returned no application id" -f $hash)
                continue
            }

            $firstApplicationId = [string]$firstIds[0]
            Write-Verbose ("Discover first-client step: hash='{0}' selected application_id='{1}'" -f $hash, $firstApplicationId)
            $applications = @(Get-CrowdStrikeDiscoverApplicationByIdSet -ApplicationIds @($firstApplicationId) -Proxy $Proxy -ProxyCredential $ProxyCredential)
            Write-Verbose ("Discover first-client step: hash='{0}' app_entities={1}" -f $hash, @($applications).Count)

            $selectedApplication = $null
            foreach ($application in $applications) {
                $resourceHash = Get-NormalizedHash -FileHash ([string](Get-ObjectPropertyValue -InputObject $application -PropertyName 'last_used_file_hash' -DefaultValue ''))
                if ($resourceHash -eq $hash) {
                    $selectedApplication = $application
                    break
                }
            }

            if ($null -eq $selectedApplication -and @($applications).Count -gt 0) {
                # Keep processing moving when the entities response does not echo the hash exactly.
                $selectedApplication = $applications[0]
            }

            if ($null -ne $selectedApplication) {
                Add-ListMapItem -Map $discoverApplicationsByHash -Key $hash -Value $selectedApplication
            }
        }
        catch {
            Write-Verbose ("Discover first-client step: hash='{0}' failed -> {1}" -f $hash, $_.Exception.Message)
            $discoverLookupErrors.Add([string]$hash)
            continue
        }
    }

    if ($discoverApplicationsByHash.Count -eq 0) {
        if ($discoverLookupErrors.Count -gt 0) {
            throw "Discover hash lookup failed for hashes '$($normalizedHashes -join ',')'."
        }

        return @()
    }

    $results = New-Object System.Collections.Generic.List[object]
    Write-Verbose ("Correlation step: hashes_with_discover_matches={0}" -f $discoverApplicationsByHash.Keys.Count)

    foreach ($hash in $normalizedHashes) {
        $applications = @()
        if ($discoverApplicationsByHash.ContainsKey($hash)) {
            $applications = @(Convert-ToObjectArraySafe -InputObject $discoverApplicationsByHash[$hash])
        }
        Write-Verbose ("Hash '{0}': discover_application_entities={1}" -f $hash, @($applications).Count)
        if (@($applications).Count -eq 0) {
            continue
        }

        $firstDiscoverEntry = Get-CrowdStrikeFirstDiscoverEntryByHash -Hash $hash -Applications $applications
        if ($null -eq $firstDiscoverEntry) {
            Write-Verbose ("Hash '{0}': no valid discover entry with app + client aid" -f $hash)
            continue
        }

        Write-Verbose ("Hash '{0}': selected first client aid='{1}', app='{2}', vendor='{3}'" -f $hash, [string]$firstDiscoverEntry.Aid, [string]$firstDiscoverEntry.ApplicationName, [string]$firstDiscoverEntry.Vendor)

        $match = $null
        try {
            $match = Get-CrowdStrikeSpotlightFirstVulnerabilityMatchForDiscoverEntry -DiscoverEntry $firstDiscoverEntry -PageSize $SpotlightPageSize -Proxy $Proxy -ProxyCredential $ProxyCredential
        }
        catch {
            Write-Verbose ("Hash '{0}': first vulnerability lookup failed -> {1}" -f $hash, $_.Exception.Message)
            continue
        }

        if ($null -eq $match) {
            Write-Verbose ("Hash '{0}': no vulnerability matched selected first client/app" -f $hash)
            continue
        }

        $row = ConvertTo-CrowdStrikeHashVulnerabilityRow -DiscoverEntry $firstDiscoverEntry -Vulnerability (Get-ObjectPropertyValue -InputObject $match -PropertyName 'Vulnerability') -VulnerabilityApp (Get-ObjectPropertyValue -InputObject $match -PropertyName 'VulnerabilityApp')
        if ($null -eq $row) {
            Write-Verbose ("Hash '{0}': first match missing CVE facet, skipping output row" -f $hash)
            continue
        }

        $results.Add($row)
        $matchType = [string](Get-ObjectPropertyValue -InputObject $match -PropertyName 'MatchType' -DefaultValue 'unknown')
        $rowVuln = Get-ObjectPropertyValue -InputObject $row -PropertyName 'Vulnerability'
        $rowVulnId = [string](Get-ObjectPropertyValue -InputObject $rowVuln -PropertyName 'Id' -DefaultValue '')
        $rowCveId = [string](Get-ObjectPropertyValue -InputObject $rowVuln -PropertyName 'CveId' -DefaultValue '')
        Write-Verbose ("Hash '{0}': correlated first vulnerability id='{1}', cve='{2}', match_type='{3}'" -f $hash, $rowVulnId, $rowCveId, $matchType)
    }

    Write-Verbose ("Completed vulnerability by hash flow: output_rows={0}" -f $results.Count)
    return @(
        $results | Sort-Object `
            @{ Expression = { [string](Get-ObjectPropertyValue -InputObject $_ -PropertyName 'FileHash' -DefaultValue '') } }, `
            @{ Expression = { [string](Get-ObjectPropertyValue -InputObject (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'Application') -PropertyName 'Name' -DefaultValue '') } }, `
            @{ Expression = { [string](Get-ObjectPropertyValue -InputObject (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'Vulnerability') -PropertyName 'CveId' -DefaultValue '') } }, `
            @{ Expression = { [string](Get-ObjectPropertyValue -InputObject (Get-ObjectPropertyValue -InputObject $_ -PropertyName 'Detection') -PropertyName 'Aid' -DefaultValue '') } }
    )
}

Export-ModuleMember -Function @('Get-CrowdStrikeSoftwareVulnerabilityByHash','Connect-CrowdStrikeApi')
