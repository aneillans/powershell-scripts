#Requires -Version 5.1

<#
.SYNOPSIS
    Cloudflare Configuration Backup Script

.DESCRIPTION
    This PowerShell script creates a comprehensive backup of your Cloudflare configuration
    including zones, DNS records, page rules, firewall rules, SSL settings, and more.

.PARAMETER ApiToken
    Your Cloudflare API token with appropriate permissions

.PARAMETER Email
    Your Cloudflare account email (optional, used with Global API Key)

.PARAMETER ApiKey
    Your Cloudflare Global API Key (optional, alternative to API token)

.PARAMETER BackupPath
    Path where backup files will be stored (default: current directory)

.PARAMETER ZoneId
    Specific zone ID to backup (optional, if not provided all zones will be backed up)

.EXAMPLE
    .\CloudflareBackup.ps1 -ApiToken "your_api_token_here"
    
.EXAMPLE
    .\CloudflareBackup.ps1 -Email "your@email.com" -ApiKey "your_global_api_key"
    
.EXAMPLE
    .\CloudflareBackup.ps1 -ApiToken "your_api_token_here" -BackupPath "C:\Backups\Cloudflare"
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ApiToken,
    
    [Parameter(Mandatory = $false)]
    [string]$Email,
    
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = ".\CloudflareBackup_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')",
    
    [Parameter(Mandatory = $false)]
    [string]$ZoneId
)

# Cloudflare API base URL
$CloudflareApiUrl = "https://api.cloudflare.com/client/v4"

# Function to make API requests
function Invoke-CloudflareApi {
    param(
        [string]$Endpoint,
        [hashtable]$Headers,
        [string]$Method = "GET"
    )
    
    try {
        $uri = "$CloudflareApiUrl$Endpoint"
        Write-Host "Fetching: $Endpoint" -ForegroundColor Yellow
        
        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method $Method -ErrorAction Stop
        
        if ($response.success -eq $false) {
            Write-Warning "API Error for $Endpoint : $($response.errors | ConvertTo-Json)"
            return $null
        }
        
        return $response.result
    }
    catch {
        Write-Error "Failed to fetch $Endpoint : $($_.Exception.Message)"
        return $null
    }
}

# Function to get all pages of results
function Get-AllPages {
    param(
        [string]$Endpoint,
        [hashtable]$Headers
    )
    
    $allResults = @()
    $page = 1
    $perPage = 100
    
    do {
        if ($Endpoint.Contains('?')) {
            $pagedEndpoint = $Endpoint + "&page=" + $page + "&per_page=" + $perPage
        } else {
            $pagedEndpoint = $Endpoint + "?page=" + $page + "&per_page=" + $perPage
        }
        
        try {
            $uri = "$CloudflareApiUrl$pagedEndpoint"
            $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method GET -ErrorAction Stop
            
            if ($response.success -eq $false) {
                Write-Warning "API Error for $pagedEndpoint : $($response.errors | ConvertTo-Json)"
                break
            }
            
            $allResults += $response.result
            
            # Check if we have more pages
            $hasMorePages = ($response.result_info.page * $response.result_info.per_page) -lt $response.result_info.total_count
            $page++
            
        } catch {
            Write-Error "Failed to fetch $pagedEndpoint : $($_.Exception.Message)"
            break
        }
        
    } while ($hasMorePages)
    
    return $allResults
}

# Function to save data to JSON file
function Save-ToJson {
    param(
        [object]$Data,
        [string]$FileName,
        [string]$Path
    )
    
    if ($Data) {
        $filePath = Join-Path $Path "$FileName.json"
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $filePath -Encoding UTF8
        Write-Host "Saved: $filePath" -ForegroundColor Green
    } else {
        Write-Warning "No data to save for $FileName"
    }
}

# Validate parameters
if (-not $ApiToken -and (-not $Email -or -not $ApiKey)) {
    Write-Error "You must provide either an API Token or both Email and API Key"
    exit 1
}

# Set up headers for API requests
$headers = @{
    "Content-Type" = "application/json"
}

if ($ApiToken) {
    $headers["Authorization"] = "Bearer $ApiToken"
    Write-Host "Using API Token authentication" -ForegroundColor Green
} else {
    $headers["X-Auth-Email"] = $Email
    $headers["X-Auth-Key"] = $ApiKey
    Write-Host "Using Global API Key authentication" -ForegroundColor Green
}

# Create backup directory
if (-not (Test-Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    Write-Host "Created backup directory: $BackupPath" -ForegroundColor Green
}

Write-Host "Starting Cloudflare configuration backup..." -ForegroundColor Cyan
Write-Host "Backup location: $BackupPath" -ForegroundColor Cyan

# Test API connection
Write-Host "`nTesting API connection..." -ForegroundColor Yellow
$userInfo = Invoke-CloudflareApi -Endpoint "/user" -Headers $headers
if (-not $userInfo) {
    Write-Error "Failed to connect to Cloudflare API. Please check your credentials."
    exit 1
}
Write-Host "Connected successfully as: $($userInfo.email)" -ForegroundColor Green

# Get zones
Write-Host "`nFetching zones..." -ForegroundColor Yellow
if ($ZoneId) {
    $zones = @(Invoke-CloudflareApi -Endpoint "/zones/$ZoneId" -Headers $headers)
} else {
    $zones = Get-AllPages -Endpoint "/zones" -Headers $headers
}

if (-not $zones) {
    Write-Error "No zones found or failed to fetch zones"
    exit 1
}

Write-Host "Found $($zones.Count) zone(s)" -ForegroundColor Green
Save-ToJson -Data $zones -FileName "zones" -Path $BackupPath

# Create a summary file
$summary = @{
    BackupDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    CloudflareUser = $userInfo.email
    TotalZonesFound = $zones.Count
    ZonesWithAccess = 0  # Will be updated later
    ZonesSkipped = 0     # Will be updated later
    Zones = @()
}

# Process each zone
$successfulZones = @()
foreach ($zone in $zones) {
    $zoneName = $zone.name
    $zoneId = $zone.id
    Write-Host "`nProcessing zone: $zoneName" -ForegroundColor Cyan
    
    # First, test if we have basic read permissions by trying to fetch DNS records
    Write-Host "  - Testing zone permissions..." -ForegroundColor Yellow
    $testDnsRecords = Get-AllPages -Endpoint "/zones/$zoneId/dns_records" -Headers $headers
    
    # Check if we have any meaningful access to this zone
    $hasAccess = $false
    if ($testDnsRecords -and $testDnsRecords.Count -gt 0) {
        $hasAccess = $true
    } else {
        # Try basic zone settings as a fallback test
        $testSettings = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/ssl" -Headers $headers
        if ($testSettings) {
            $hasAccess = $true
        }
    }
    
    if (-not $hasAccess) {
        Write-Host "  - No access to zone data (insufficient permissions). Skipping..." -ForegroundColor Red
        continue
    }
    
    Write-Host "  - Zone access confirmed. Proceeding with backup..." -ForegroundColor Green
    
    $zoneBackupPath = Join-Path $BackupPath $zoneName
    if (-not (Test-Path $zoneBackupPath)) {
        New-Item -ItemType Directory -Path $zoneBackupPath -Force | Out-Null
    }
    
    $zoneInfo = @{
        Name = $zoneName
        Id = $zoneId
        Status = $zone.status
        Items = @{}
    }
    
    # DNS Records (use the test data we already fetched)
    Write-Host "  - DNS Records" -ForegroundColor Yellow
    $dnsRecords = $testDnsRecords  # Use the records we already fetched during testing
    Save-ToJson -Data $dnsRecords -FileName "dns_records" -Path $zoneBackupPath
    $zoneInfo.Items.DnsRecords = if ($dnsRecords) { $dnsRecords.Count } else { 0 }
    
    # Page Rules
    Write-Host "  - Page Rules" -ForegroundColor Yellow
    $pageRules = Get-AllPages -Endpoint "/zones/$zoneId/pagerules" -Headers $headers
    Save-ToJson -Data $pageRules -FileName "page_rules" -Path $zoneBackupPath
    $zoneInfo.Items.PageRules = if ($pageRules) { $pageRules.Count } else { 0 }
    
    # Firewall Rules
    Write-Host "  - Firewall Rules" -ForegroundColor Yellow
    $firewallRules = Get-AllPages -Endpoint "/zones/$zoneId/firewall/rules" -Headers $headers
    Save-ToJson -Data $firewallRules -FileName "firewall_rules" -Path $zoneBackupPath
    $zoneInfo.Items.FirewallRules = if ($firewallRules) { $firewallRules.Count } else { 0 }
    
    # Rate Limiting Rules
    Write-Host "  - Rate Limiting Rules" -ForegroundColor Yellow
    $rateLimitRules = Get-AllPages -Endpoint "/zones/$zoneId/rate_limits" -Headers $headers
    Save-ToJson -Data $rateLimitRules -FileName "rate_limit_rules" -Path $zoneBackupPath
    $zoneInfo.Items.RateLimitRules = if ($rateLimitRules) { $rateLimitRules.Count } else { 0 }
    
    # SSL/TLS Settings
    Write-Host "  - SSL/TLS Settings" -ForegroundColor Yellow
    $sslSettings = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/ssl" -Headers $headers
    Save-ToJson -Data $sslSettings -FileName "ssl_settings" -Path $zoneBackupPath
    
    # Security Level
    $securityLevel = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/security_level" -Headers $headers
    Save-ToJson -Data $securityLevel -FileName "security_level" -Path $zoneBackupPath
    
    # Cache Level
    $cacheLevel = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/cache_level" -Headers $headers
    Save-ToJson -Data $cacheLevel -FileName "cache_level" -Path $zoneBackupPath
    
    # Browser Cache TTL
    $browserCacheTtl = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/browser_cache_ttl" -Headers $headers
    Save-ToJson -Data $browserCacheTtl -FileName "browser_cache_ttl" -Path $zoneBackupPath
    
    # Always Online
    $alwaysOnline = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/always_online" -Headers $headers
    Save-ToJson -Data $alwaysOnline -FileName "always_online" -Path $zoneBackupPath
    
    # Development Mode
    $developmentMode = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/development_mode" -Headers $headers
    Save-ToJson -Data $developmentMode -FileName "development_mode" -Path $zoneBackupPath
    
    # Origin Error Page Pass-thru
    $originErrorPagePassthru = Invoke-CloudflareApi -Endpoint "/zones/$zoneId/settings/origin_error_page_pass_thru" -Headers $headers
    Save-ToJson -Data $originErrorPagePassthru -FileName "origin_error_page_pass_thru" -Path $zoneBackupPath
    
    # WAF Settings
    Write-Host "  - WAF Packages and Rules" -ForegroundColor Yellow
    $wafPackages = Get-AllPages -Endpoint "/zones/$zoneId/firewall/waf/packages" -Headers $headers
    Save-ToJson -Data $wafPackages -FileName "waf_packages" -Path $zoneBackupPath
    $zoneInfo.Items.WafPackages = if ($wafPackages) { $wafPackages.Count } else { 0 }
    
    # Access Rules
    Write-Host "  - Access Rules" -ForegroundColor Yellow
    $accessRules = Get-AllPages -Endpoint "/zones/$zoneId/firewall/access_rules/rules" -Headers $headers
    Save-ToJson -Data $accessRules -FileName "access_rules" -Path $zoneBackupPath
    $zoneInfo.Items.AccessRules = if ($accessRules) { $accessRules.Count } else { 0 }
    
    # Load Balancers
    Write-Host "  - Load Balancers" -ForegroundColor Yellow
    $loadBalancers = Get-AllPages -Endpoint "/zones/$zoneId/load_balancers" -Headers $headers
    Save-ToJson -Data $loadBalancers -FileName "load_balancers" -Path $zoneBackupPath
    $zoneInfo.Items.LoadBalancers = if ($loadBalancers) { $loadBalancers.Count } else { 0 }
    
    # Workers Routes
    Write-Host "  - Workers Routes" -ForegroundColor Yellow
    $workerRoutes = Get-AllPages -Endpoint "/zones/$zoneId/workers/routes" -Headers $headers
    Save-ToJson -Data $workerRoutes -FileName "worker_routes" -Path $zoneBackupPath
    $zoneInfo.Items.WorkerRoutes = if ($workerRoutes) { $workerRoutes.Count } else { 0 }
    
    # Custom Pages
    Write-Host "  - Custom Pages" -ForegroundColor Yellow
    $customPages = Get-AllPages -Endpoint "/zones/$zoneId/custom_pages" -Headers $headers
    Save-ToJson -Data $customPages -FileName "custom_pages" -Path $zoneBackupPath
    $zoneInfo.Items.CustomPages = if ($customPages) { $customPages.Count } else { 0 }
    
    # Zone Lockdown Rules
    Write-Host "  - Zone Lockdown Rules" -ForegroundColor Yellow
    $zoneLockdown = Get-AllPages -Endpoint "/zones/$zoneId/firewall/lockdowns" -Headers $headers
    Save-ToJson -Data $zoneLockdown -FileName "zone_lockdown" -Path $zoneBackupPath
    $zoneInfo.Items.ZoneLockdown = if ($zoneLockdown) { $zoneLockdown.Count } else { 0 }
    
    # UA Block Rules
    Write-Host "  - User Agent Block Rules" -ForegroundColor Yellow
    $uaBlockRules = Get-AllPages -Endpoint "/zones/$zoneId/firewall/ua_rules" -Headers $headers
    Save-ToJson -Data $uaBlockRules -FileName "ua_block_rules" -Path $zoneBackupPath
    $zoneInfo.Items.UaBlockRules = if ($uaBlockRules) { $uaBlockRules.Count } else { 0 }
    
    # Add this zone to our successful zones list
    $successfulZones += $zoneInfo
}

# Account-level settings
Write-Host "`nFetching account-level settings..." -ForegroundColor Yellow

# Get account info
$accounts = Get-AllPages -Endpoint "/accounts" -Headers $headers
Save-ToJson -Data $accounts -FileName "accounts" -Path $BackupPath

if ($accounts -and $accounts.Count -gt 0) {
    $accountId = $accounts[0].id
    
    # Account members
    Write-Host "  - Account Members" -ForegroundColor Yellow
    $accountMembers = Get-AllPages -Endpoint "/accounts/$accountId/members" -Headers $headers
    Save-ToJson -Data $accountMembers -FileName "account_members" -Path $BackupPath
    
    # Account roles
    Write-Host "  - Account Roles" -ForegroundColor Yellow
    $accountRoles = Get-AllPages -Endpoint "/accounts/$accountId/roles" -Headers $headers
    Save-ToJson -Data $accountRoles -FileName "account_roles" -Path $BackupPath
    
    # Load Balancer pools
    Write-Host "  - Load Balancer Pools" -ForegroundColor Yellow
    $loadBalancerPools = Get-AllPages -Endpoint "/accounts/$accountId/load_balancers/pools" -Headers $headers
    Save-ToJson -Data $loadBalancerPools -FileName "load_balancer_pools" -Path $BackupPath
    
    # Load Balancer monitors
    Write-Host "  - Load Balancer Monitors" -ForegroundColor Yellow
    $loadBalancerMonitors = Get-AllPages -Endpoint "/accounts/$accountId/load_balancers/monitors" -Headers $headers
    Save-ToJson -Data $loadBalancerMonitors -FileName "load_balancer_monitors" -Path $BackupPath
}

# Update summary with final counts
$summary.ZonesWithAccess = $successfulZones.Count
$summary.ZonesSkipped = $zones.Count - $successfulZones.Count
$summary.Zones = $successfulZones

# Save summary
Save-ToJson -Data $summary -FileName "backup_summary" -Path $BackupPath

# Create README file
$readmeContent = @"
# Cloudflare Configuration Backup

**Backup Date:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Cloudflare Account:** $($userInfo.email)
**Total Zones Found:** $($zones.Count)
**Zones Successfully Backed Up:** $($successfulZones.Count)
**Zones Skipped (No Access):** $($zones.Count - $successfulZones.Count)

## Contents

### Root Level Files
- ``accounts.json`` - Account information
- ``zones.json`` - All zones configuration
- ``account_members.json`` - Account members
- ``account_roles.json`` - Account roles
- ``load_balancer_pools.json`` - Load balancer pools
- ``load_balancer_monitors.json`` - Load balancer monitors
- ``backup_summary.json`` - Summary of this backup

### Per-Zone Folders
Each zone has its own folder containing:

- ``dns_records.json`` - DNS records
- ``page_rules.json`` - Page rules
- ``firewall_rules.json`` - Firewall rules
- ``rate_limit_rules.json`` - Rate limiting rules
- ``ssl_settings.json`` - SSL/TLS settings
- ``security_level.json`` - Security level setting
- ``cache_level.json`` - Cache level setting
- ``browser_cache_ttl.json`` - Browser cache TTL
- ``always_online.json`` - Always Online setting
- ``development_mode.json`` - Development mode setting
- ``origin_error_page_pass_thru.json`` - Origin error page pass-through
- ``waf_packages.json`` - WAF packages
- ``access_rules.json`` - Access rules
- ``load_balancers.json`` - Load balancers
- ``worker_routes.json`` - Workers routes
- ``custom_pages.json`` - Custom error/challenge pages
- ``zone_lockdown.json`` - Zone lockdown rules
- ``ua_block_rules.json`` - User Agent blocking rules

## Restore Notes

This backup contains the configuration data in JSON format. To restore:

1. Review the JSON files to understand your configuration
2. Use the Cloudflare API or dashboard to recreate the settings
3. For DNS records, you can use the API to bulk import
4. For other settings, you may need to configure them individually

## Security Warning

These files contain sensitive configuration information. Store them securely and do not share them publicly.
"@

$readmeContent | Out-File -FilePath (Join-Path $BackupPath "README.md") -Encoding UTF8

Write-Host "`n" -NoNewline
Write-Host "Backup completed successfully!" -ForegroundColor Green
Write-Host "Backup location: $BackupPath" -ForegroundColor Cyan
Write-Host "Total zones found: $($zones.Count)" -ForegroundColor Cyan
Write-Host "Zones successfully backed up: $($successfulZones.Count)" -ForegroundColor Green
if (($zones.Count - $successfulZones.Count) -gt 0) {
    Write-Host "Zones skipped (no access): $($zones.Count - $successfulZones.Count)" -ForegroundColor Yellow
}

# Display summary
if ($successfulZones.Count -gt 0) {
    Write-Host "`nBackup Summary:" -ForegroundColor Yellow
    foreach ($zone in $successfulZones) {
        Write-Host "  $($zone.Name):" -ForegroundColor White
        Write-Host "    DNS Records: $($zone.Items.DnsRecords)" -ForegroundColor Gray
        Write-Host "    Page Rules: $($zone.Items.PageRules)" -ForegroundColor Gray
        Write-Host "    Firewall Rules: $($zone.Items.FirewallRules)" -ForegroundColor Gray
        Write-Host "    Rate Limit Rules: $($zone.Items.RateLimitRules)" -ForegroundColor Gray
        Write-Host "    WAF Packages: $($zone.Items.WafPackages)" -ForegroundColor Gray
        Write-Host "    Access Rules: $($zone.Items.AccessRules)" -ForegroundColor Gray
        Write-Host "    Load Balancers: $($zone.Items.LoadBalancers)" -ForegroundColor Gray
        Write-Host "    Worker Routes: $($zone.Items.WorkerRoutes)" -ForegroundColor Gray
    }
} else {
    Write-Host "`nNo zones were successfully backed up due to insufficient permissions." -ForegroundColor Red
    Write-Host "Please check your API token permissions and try again." -ForegroundColor Red
}

Write-Host "`nIMPORTANT: Store this backup securely as it contains sensitive configuration data." -ForegroundColor Red