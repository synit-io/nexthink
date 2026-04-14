# CrowdStrike Software Vulnerability By Hash - PowerShell Module

## Overview
`CrowdStrikeSoftwareVulnByHash.psm1` provides reusable functions to correlate software vulnerabilities by file hash using CrowdStrike APIs.

Flow used per hash:
1. Discover query by `last_used_file_hash`.
2. Discover entity lookup for application details.
3. Select first matching client (`aid`).
4. Spotlight vulnerability query/entity lookup.
5. Return first correlated vulnerability as a global finding.

The module is optimized to minimize local post-processing and includes retry/token-refresh logic for long-running requests.

## Exported Functions
- `Connect-CrowdStrikeApi`
- `Get-CrowdStrikeSoftwareVulnerabilityByHash`

## Requirements
- PowerShell 7+ (recommended)
- CrowdStrike Falcon API client credentials (`client_id` + `client_secret`)
- Network access to your Falcon API cloud endpoint

## Setup CrowdStrike API Client and Token
1. Open Falcon Console.
2. Navigate to **Support and resources** -> **API clients and keys**.
3. Create a new API client.
4. Grant the minimum required scopes:
   - `discover:read`
   - `spotlight-vulnerabilities:read`
5. Save/copy the generated:
   - `Client ID`
   - `Client Secret`

The module requests OAuth2 tokens from:
- `https://<falcon-api-cloud>/oauth2/token`

Example for EU cloud:
- `https://api.eu-1.crowdstrike.com/oauth2/token`

## Import Module
```powershell
Import-Module /path/to/CrowdStrikeSoftwareVulnByHash.psm1
```

## Usage Examples

### 1. Connect once, then query
```powershell
$clientId = '<client-id>'
$clientSecret = '<client-secret>'

Connect-CrowdStrikeApi -ClientId $clientId -ClientSecret $clientSecret -BaseUrl 'https://api.eu-1.crowdstrike.com'

$hashes = @(
  'A1244BE904024F8D75D028B217D5618DC74434661848DB88731C13E99872F00B',
  '2f3c5b3b50c2df61f7bbf6319f53d6a30d80a70e2fa5a53922c8f5fcbf7f8c31'
)

$result = Get-CrowdStrikeSoftwareVulnerabilityByHash -FileHashes $hashes -Verbose
$result | Select-Object `
  FileHash, `
  @{Name='Hostname';Expression={$_.Detection.Hostname}}, `
  @{Name='Application';Expression={$_.Application.Name}}, `
  @{Name='CVE';Expression={$_.Vulnerability.CveId}}, `
  @{Name='Severity';Expression={$_.Vulnerability.Cvss.Severity}} | Format-Table -AutoSize
```

### 2. Query with inline credentials
```powershell
$result = Get-CrowdStrikeSoftwareVulnerabilityByHash `
  -ClientId '<client-id>' `
  -ClientSecret '<client-secret>' `
  -BaseUrl 'https://api.eu-1.crowdstrike.com' `
  -FileHashes @('A1244BE904024F8D75D028B217D5618DC74434661848DB88731C13E99872F00B')
```

### 3. Use proxy
```powershell
$proxyCred = Get-Credential
$result = Get-CrowdStrikeSoftwareVulnerabilityByHash `
  -ClientId '<client-id>' `
  -ClientSecret '<client-secret>' `
  -FileHashes @('A1244BE904024F8D75D028B217D5618DC74434661848DB88731C13E99872F00B') `
  -Proxy 'http://proxy.company.local:8080' `
  -ProxyCredential $proxyCred
```

### 4. Export results to JSON
```powershell
$result = Get-CrowdStrikeSoftwareVulnerabilityByHash -FileHashes $hashes
$result | ConvertTo-Json -Depth 10 | Set-Content -Path './CrowdStrike_Software_Vuln_ByHash_Report.json' -Encoding UTF8
```

## Output Structure
Each result row is a structured `PSCustomObject`:

- `FileHash`
- `Detection`
- `Application`
- `Vulnerability`

### Detection object
- `LastUsedFileHash`
- `LastUsedFileName`
- `LastUsedTimestamp`
- `LastUsedUserName`
- `LastUsedUserSid`
- `Aid`
- `Hostname`
- `PlatformName`
- `OsVersion`

### Application object
- `Name`
- `Vendor`
- `Version`

### Vulnerability object
- `EntityId`
- `Id`
- `CveId`
- `Status`
- `Category`
- `ExprtRating`
- `Cvss`:
  - `Severity`
  - `BaseScore`
  - `ExploitabilityScore`
- `Exploit`:
  - `Available`
  - `IsCisaKev`
- `Remediation`:
  - `Level`
  - `LevelCode`
  - `AvailableCount`
  - `FixAvailable`
  - `RecommendedId`
  - `MinimumId`
- `CreatedTimestamp`
- `UpdatedTimestamp`

### Sample output shape
```powershell
@{
  FileHash = 'a1244b...'
  Detection = @{
    Aid = '923fcf...'
    Hostname = 'HOST01'
    LastUsedFileName = 'KeePass.exe'
  }
  Application = @{
    Name = 'KeePass'
    Vendor = 'Dominik Reichl'
    Version = '2.51.1.0'
  }
  Vulnerability = @{
    Id = 'CVE-2025-54660'
    CveId = 'CVE-2025-54660'
    Status = 'open'
    Cvss = @{
      Severity = 'MEDIUM'
      BaseScore = 5.5
      ExploitabilityScore = 1.8
    }
    Exploit = @{
      Available = $false
      IsCisaKev = $false
    }
    Remediation = @{
      Level = 'Official Fix (O/OF)'
      LevelCode = 'O'
      AvailableCount = 2
      FixAvailable = $true
    }
  }
}
```

## Reliability and Token Refresh Behavior
The module automatically re-authenticates and retries when needed:
- Proactive token refresh before expiry window.
- Refresh on auth failures (`401`, `403`).
- Refresh/retry on timeout/transient conditions (`408`, `504`, timeout/connect failures).
- Backoff retry for throttling/service availability (`429`, `503`).

## Notes
- Input hashes are normalized to lowercase before querying.
- Current correlation strategy intentionally returns first client + first vulnerability per hash for performance.

## Integration with Nexthink
See [Nexthink-Enrich_Binaries.ps1](../enrichment_api/Nexthink-Enrich_Binaries.ps1) for example of how to send CrowdStrike vulnerability information to Nexthink.
