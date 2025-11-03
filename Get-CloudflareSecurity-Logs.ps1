<#
.SYNOPSIS
    Retrieves CloudFlare security logs and analyzes ASN and Country data.

.DESCRIPTION
    This script connects to the CloudFlare API, retrieves logs for security rules (firewall events),
    analyzes the data by ASN and Country, and exports the results to CSV files.

.PARAMETER ApiToken
    Your CloudFlare API Token with appropriate permissions for reading logs.

.PARAMETER ZoneId
    The CloudFlare Zone ID for your domain.

.PARAMETER StartTime
    Start time for log retrieval (default: 24 hours ago).

.PARAMETER EndTime
    End time for log retrieval (default: current time).

.PARAMETER OutputPath
    Path where CSV files will be saved (default: current directory).

.EXAMPLE
    .\Get-CloudflareSecurity-Logs.ps1 -ApiToken "your_token" -ZoneId "your_zone_id"

.EXAMPLE
    .\Get-CloudflareSecurity-Logs.ps1 -ApiToken "your_token" -ZoneId "your_zone_id" -StartTime (Get-Date).AddDays(-7) -OutputPath "C:\Logs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ApiToken,

    [Parameter(Mandatory = $true)]
    [string]$ZoneId,

    [Parameter(Mandatory = $false)]
    [DateTime]$StartTime = (Get-Date).AddHours(-24),

    [Parameter(Mandatory = $false)]
    [DateTime]$EndTime = (Get-Date),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "."
)

# Set TLS to 1.2 for API calls
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function to convert DateTime to RFC3339 format for CloudFlare API
function ConvertTo-RFC3339 {
    param([DateTime]$DateTime)
    return $DateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

# Function to make CloudFlare API calls
function Invoke-CloudFlareAPI {
    param(
        [string]$Endpoint,
        [hashtable]$Headers,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )

    try {
        $params = @{
            Uri     = $Endpoint
            Headers = $Headers
            Method  = $Method
        }

        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
            $params.ContentType = "application/json"
        }

        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        Write-Error "API call failed: $_"
        throw
    }
}

Write-Host "CloudFlare Security Logs Analyzer" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Prepare API headers
$headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

# Convert times to RFC3339
$startTimeRFC = ConvertTo-RFC3339 -DateTime $StartTime
$endTimeRFC = ConvertTo-RFC3339 -DateTime $EndTime

Write-Host "Retrieving logs from $StartTime to $EndTime..." -ForegroundColor Yellow

# Build GraphQL query for firewall events
$query = @"
{
  viewer {
    zones(filter: {zoneTag: "$ZoneId"}) {
      firewallEventsAdaptive(
        filter: {
          datetime_geq: "$startTimeRFC"
          datetime_leq: "$endTimeRFC"
        }
        limit: 10000
        orderBy: [datetime_DESC]
      ) {
        action
        clientAsn
        clientASNDescription
        clientCountryName
        clientIP
        clientRequestHTTPHost
        clientRequestPath
        datetime
        rayName
        ruleId
        source
        userAgent
      }
    }
  }
}
"@

# Make API call to CloudFlare GraphQL endpoint
$graphqlEndpoint = "https://api.cloudflare.com/client/v4/graphql"

try {
    Write-Host "Connecting to CloudFlare API..." -ForegroundColor Yellow
    
    $body = @{
        query = $query
    }
    
    $response = Invoke-RestMethod -Uri $graphqlEndpoint -Method Post -Headers $headers -Body ($body | ConvertTo-Json) -ContentType "application/json"
    
    if ($response.errors) {
        Write-Error "GraphQL errors: $($response.errors | ConvertTo-Json)"
        exit 1
    }

    $events = $response.data.viewer.zones[0].firewallEventsAdaptive

    if (-not $events -or $events.Count -eq 0) {
        Write-Warning "No security events found for the specified time range."
        exit 0
    }

    Write-Host "Retrieved $($events.Count) security events" -ForegroundColor Green
    Write-Host ""

    # Analyze by ASN
    Write-Host "Analyzing by ASN..." -ForegroundColor Yellow
    $asnStats = $events | 
        Where-Object { $_.clientAsn } |
        Group-Object -Property clientAsn | 
        ForEach-Object {
            $asn = $_.Name
            $description = ($_.Group | Select-Object -First 1).clientASNDescription
            $countries = ($_.Group | Select-Object -ExpandProperty clientCountryName -Unique) -join ", "
            $actions = $_.Group | Group-Object -Property action | ForEach-Object { "$($_.Name): $($_.Count)" }
            
            [PSCustomObject]@{
                ASN              = $asn
                Description      = $description
                HitCount         = $_.Count
                Countries        = $countries
                Actions          = $actions -join "; "
                SampleIPs        = (($_.Group | Select-Object -First 5 -ExpandProperty clientIP) -join ", ")
            }
        } | 
        Sort-Object -Property HitCount -Descending

    # Analyze by Country
    Write-Host "Analyzing by Country..." -ForegroundColor Yellow
    $countryStats = $events | 
        Where-Object { $_.clientCountryName } |
        Group-Object -Property clientCountryName | 
        ForEach-Object {
            $country = $_.Name
            $topASNs = $_.Group | Group-Object -Property clientAsn | Sort-Object Count -Descending | Select-Object -First 5
            $actions = $_.Group | Group-Object -Property action | ForEach-Object { "$($_.Name): $($_.Count)" }
            
            [PSCustomObject]@{
                Country          = $country
                HitCount         = $_.Count
                UniqueASNs       = ($_.Group | Select-Object -ExpandProperty clientAsn -Unique).Count
                TopASNs          = ($topASNs | ForEach-Object { "ASN$($_.Name) ($($_.Count))" }) -join ", "
                Actions          = $actions -join "; "
                SampleIPs        = (($_.Group | Select-Object -First 5 -ExpandProperty clientIP) -join ", ")
            }
        } | 
        Sort-Object -Property HitCount -Descending

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $asnCsvPath = Join-Path $OutputPath "CloudFlare_SecurityLogs_ASN_$timestamp.csv"
    $countryCsvPath = Join-Path $OutputPath "CloudFlare_SecurityLogs_Country_$timestamp.csv"
    $rawCsvPath = Join-Path $OutputPath "CloudFlare_SecurityLogs_Raw_$timestamp.csv"

    Write-Host ""
    Write-Host "Exporting results..." -ForegroundColor Yellow

    # Export ASN stats
    $asnStats | Export-Csv -Path $asnCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "ASN statistics exported to: $asnCsvPath" -ForegroundColor Green

    # Export Country stats
    $countryStats | Export-Csv -Path $countryCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Country statistics exported to: $countryCsvPath" -ForegroundColor Green

    # Export raw events
    $events | Select-Object action, clientAsn, clientASNDescription, clientCountryName, clientIP, `
                           clientRequestHTTPHost, clientRequestPath, datetime, rayName, ruleId, source, userAgent | 
        Export-Csv -Path $rawCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Raw events exported to: $rawCsvPath" -ForegroundColor Green

    # Display summary
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "--------" -ForegroundColor Cyan
    Write-Host "Total Events: $($events.Count)"
    Write-Host "Unique ASNs: $($asnStats.Count)"
    Write-Host "Unique Countries: $($countryStats.Count)"
    Write-Host ""
    Write-Host "Top 5 ASNs by Hit Count:" -ForegroundColor Yellow
    $asnStats | Select-Object -First 5 | Format-Table -AutoSize
    Write-Host ""
    Write-Host "Top 5 Countries by Hit Count:" -ForegroundColor Yellow
    $countryStats | Select-Object -First 5 | Format-Table -AutoSize

}
catch {
    Write-Error "Failed to retrieve or process CloudFlare logs: $_"
    Write-Error $_.Exception.Message
    exit 1
}

Write-Host ""
Write-Host "Script completed successfully!" -ForegroundColor Green
