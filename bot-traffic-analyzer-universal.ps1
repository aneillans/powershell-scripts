# Universal Bot Traffic Analyzer for Log Files (Apache/Nginx + IIS Support)
# Extracts compressed files, identifies bot traffic, and generates summary reports

param(
    [string]$LogDirectory = ".",
    [string]$OutputReport = "bot-traffic-report-universal.txt",
    [switch]$IncludeSubdirectories = $false
)

# Initialize counters and collections
$botTraffic = @{}
$totalRequests = 0
$botRequests = 0
$extractedFiles = @()

# Bot identification patterns (ENHANCED WITH AI BOTS)
$botPatterns = @(
    # AI Company Bots (PRIORITY PATTERNS)
    "ClaudeBot", "claudebot", "Claude-Web", "anthropic",
    "GPTBot", "gptbot", "ChatGPT-User", "CCBot", 
    "OpenAI", "openai", "ChatGPT",
    "Google-Extended", "GoogleOther", "Bard", "Gemini",
    "PerplexityBot", "Claude", "Anthropic",
    "AI2Bot", "Meta-ExternalAgent", "Meta-ExternalFetcher",
    "Bytedance", "ByteSpider", "TikTok",
    "cohere-ai", "YouBot", "ChatSonic",
    "PaLM", "LaMDA", "T5", "BERT",
    
    # Common bot/crawler names
    "bot", "Bot", "BOT",
    "crawler", "Crawler", "CRAWLER", 
    "spider", "Spider", "SPIDER",
    "scraper", "Scraper", "SCRAPER",
    
    # Search Engine Bots
    "googlebot", "Googlebot", "GoogleBot",
    "bingbot", "BingBot", "bingbot",
    "slurp", "Slurp", "SLURP",
    "duckduckbot", "DuckDuckBot",
    "baiduspider", "BaiduSpider",
    "yandexbot", "YandexBot",
    
    # Social Media Bots
    "facebookexternalhit", "FacebookExternalHit",
    "twitterbot", "Twitterbot", "TwitterBot",
    "linkedinbot", "LinkedInBot",
    "whatsapp", "WhatsApp",
    "telegrambot", "TelegramBot",
    "discordbot", "DiscordBot",
    "slackbot", "Slackbot",
    
    # SEO/Marketing bots
    "semrush", "ahrefs", "majestic",
    "moz\.com", "screaming frog", "SemrushBot", "AhrefsBot",
    
    # Monitoring/uptime bots  
    "pingdom", "uptimerobot", "statuscake",
    "newrelic", "datadog", "nagios",
    
    # Archive/wayback bots
    "wayback", "archive\.org", "ia_archiver",
    
    # Academic/research bots
    "researchscan", "censys", "shodan", "CensysInspect",
    "GenomeCrawler", "nokia", "ModatScanner",
    
    # Security scanners
    "nmap", "masscan", "zmap", "nuclei",
    "sqlmap", "nikto", "dirb", "gobuster",
    "Keydrop", "onlyscans", "Palo Alto Networks",
    
    # Fediverse/ActivityPub crawlers
    "FediIndex", "FediDB", "GenomeCrawlerd", "Minoru",
    
    # Generic patterns
    "check", "monitor", "scan", "test",
    "fetch", "download", "index",
    "verification", "validator"
)

function Test-BotUserAgent {
    param([string]$UserAgent)
    
    if ([string]::IsNullOrEmpty($UserAgent) -or $UserAgent -eq "-") {
        return $false
    }
    
    foreach ($pattern in $botPatterns) {
        if ($UserAgent -match $pattern) {
            return $true
        }
    }
    return $false
}

function Detect-LogFormat {
    param([string]$SampleLine)
    
    # IIS logs start with #Software, #Version, #Date, or #Fields
    if ($SampleLine -match "^#(Software|Version|Date|Fields)") {
        return "IIS"
    }
    
    # Apache/Nginx logs typically have IP address at start and quoted strings
    if ($SampleLine -match "^\d+\.\d+\.\d+\.\d+" -and $SampleLine -match '"[^"]*"') {
        return "Apache"
    }
    
    # Additional checks for IIS data lines (space-separated, specific field count)
    $fields = $SampleLine -split '\s+'
    if ($fields.Count -ge 14 -and $fields[0] -match "^\d{4}-\d{2}-\d{2}$" -and $fields[1] -match "^\d{2}:\d{2}:\d{2}$") {
        return "IIS"
    }
    
    # Default to Apache for other formats
    return "Apache"
}

function Extract-UserAgent-Apache {
    param([string]$LogLine)
    
    # Extract user agent from Apache/Nginx common log format
    # Format: IP - - [date] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
    $matches = [regex]::Matches($LogLine, '"([^"]*)"')
    if ($matches.Count -ge 4) {
        # User agent should be the 4th quoted field
        return $matches[$matches.Count - 1].Groups[1].Value
    } elseif ($matches.Count -eq 3) {
        # Sometimes referer might be missing, so UA is 3rd quoted field
        return $matches[2].Groups[1].Value
    } else {
        # Fallback: try to find any quoted string that looks like a user agent
        if ($LogLine -match '"([^"]*(?:Mozilla|bot|Bot|crawler|spider|scan)[^"]*)"') {
            return $matches[1]
        }
    }
    return $null
}

function Extract-UserAgent-IIS {
    param([string]$LogLine)
    
    # Skip comment lines
    if ($LogLine.StartsWith("#")) {
        return $null
    }
    
    # IIS W3C Extended Log Format (space-separated)
    # Standard fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
    $fields = $LogLine -split '\s+', 15  # Split into max 15 fields to preserve user agent with spaces
    
    if ($fields.Count -ge 10) {
        $userAgent = $fields[9]  # cs(User-Agent) is typically the 10th field (0-indexed = 9)
        
        # Decode URL-encoded user agent (replace + with spaces, decode %XX)
        $userAgent = $userAgent -replace '\+', ' '
        $userAgent = [System.Web.HttpUtility]::UrlDecode($userAgent)
        
        return $userAgent
    }
    
    return $null
}

function Extract-CompressedFiles {
    param([string]$Directory)
    
    Write-Host "=== EXTRACTING COMPRESSED FILES ===" -ForegroundColor Yellow
    
    $searchPattern = if ($IncludeSubdirectories) { "**/*" } else { "*" }
    
    # Handle .gz files
    $gzFiles = Get-ChildItem -Path $Directory -Filter "$searchPattern.gz" -Recurse:$IncludeSubdirectories
    foreach ($gzFile in $gzFiles) {
        $baseName = $gzFile.BaseName
        $extractedPath = Join-Path $gzFile.DirectoryName "extracted_$baseName"
        
        try {
            Write-Host "Extracting $($gzFile.Name) -> extracted_$baseName"
            
            # Extract gzip file
            $gzStream = New-Object System.IO.FileStream($gzFile.FullName, [System.IO.FileMode]::Open)
            $gzipStream = New-Object System.IO.Compression.GzipStream($gzStream, [System.IO.Compression.CompressionMode]::Decompress)
            $outputStream = New-Object System.IO.FileStream($extractedPath, [System.IO.FileMode]::Create)
            
            $gzipStream.CopyTo($outputStream)
            
            $outputStream.Close()
            $gzipStream.Close()
            $gzStream.Close()
            
            $extractedFiles += $extractedPath
        }
        catch {
            Write-Warning "Failed to extract $($gzFile.Name): $($_.Exception.Message)"
        }
    }
    
    # Handle .zip files
    $zipFiles = Get-ChildItem -Path $Directory -Filter "$searchPattern.zip" -Recurse:$IncludeSubdirectories
    foreach ($zipFile in $zipFiles) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($zipFile.Name)
        $extractedDir = Join-Path $zipFile.DirectoryName "extracted_$baseName"
        
        try {
            Write-Host "Extracting $($zipFile.Name) -> extracted_$baseName/"
            
            if (Test-Path $extractedDir) {
                Remove-Item $extractedDir -Recurse -Force
            }
            
            Expand-Archive -Path $zipFile.FullName -DestinationPath $extractedDir -Force
            
            # Add extracted files to list
            $extractedLogFiles = Get-ChildItem -Path $extractedDir -Recurse -File | Where-Object { $_.Extension -match '\.(log|txt)$' }
            foreach ($file in $extractedLogFiles) {
                $newName = "extracted_" + $file.Name
                $newPath = Join-Path $zipFile.DirectoryName $newName
                Copy-Item $file.FullName $newPath
                $extractedFiles += $newPath
            }
        }
        catch {
            Write-Warning "Failed to extract $($zipFile.Name): $($_.Exception.Message)"
        }
    }
    
    Write-Host "Extracted $($extractedFiles.Count) files" -ForegroundColor Green
    return $extractedFiles
}

function Process-LogFile {
    param(
        [string]$FilePath,
        [string]$FileName
    )
    
    $fileRequests = 0
    $fileBotRequests = 0
    $fileBots = @{}
    $logFormat = $null
    
    try {
        # Read first few non-comment lines to detect format
        $sampleLines = Get-Content $FilePath -TotalCount 10 | Where-Object { -not $_.StartsWith("#") -and $_.Trim() -ne "" }
        if ($sampleLines.Count -gt 0) {
            $logFormat = Detect-LogFormat $sampleLines[0]
        }
        
        Write-Host "  Detected format: $logFormat" -ForegroundColor Gray
        
        Get-Content $FilePath -Encoding UTF8 -ErrorAction Stop | ForEach-Object {
            $line = $_
            
            # Skip empty lines and comments
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
                return
            }
            
            $fileRequests++
            
            # Extract user agent based on detected format
            $userAgent = $null
            if ($logFormat -eq "IIS") {
                $userAgent = Extract-UserAgent-IIS $line
            } else {
                $userAgent = Extract-UserAgent-Apache $line
            }
            
            # Skip if user agent is empty, dash, or looks like a request method
            if ($userAgent -and $userAgent -ne "-" -and $userAgent -notmatch "^(GET|POST|PUT|DELETE|HEAD|OPTIONS)") {
                
                if (Test-BotUserAgent $userAgent) {
                    $fileBotRequests++
                    
                    # Count this bot
                    if ($fileBots.ContainsKey($userAgent)) {
                        $fileBots[$userAgent]++
                    } else {
                        $fileBots[$userAgent] = 1
                    }
                    
                    # Add to global bot counter
                    if ($botTraffic.ContainsKey($userAgent)) {
                        $botTraffic[$userAgent] += 1
                    } else {
                        $botTraffic[$userAgent] = 1
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error processing $FileName`: $($_.Exception.Message)"
        return @{
            FileName = $FileName
            LogFormat = "Unknown"
            TotalRequests = 0
            BotRequests = 0
            BotPercentage = 0
            UniqueBots = 0
            TopBots = @()
        }
    }
    
    $botPercentage = if ($fileRequests -gt 0) { [Math]::Round(($fileBotRequests / $fileRequests) * 100, 2) } else { 0 }
    $topBots = $fileBots.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    
    return @{
        FileName = $FileName
        LogFormat = $logFormat
        TotalRequests = $fileRequests
        BotRequests = $fileBotRequests
        BotPercentage = $botPercentage
        UniqueBots = $fileBots.Count
        TopBots = $topBots
    }
}

# Main execution
Write-Host "=== UNIVERSAL BOT TRAFFIC ANALYZER ===" -ForegroundColor Cyan
Write-Host "Supporting Apache/Nginx and IIS log formats" -ForegroundColor Cyan
Write-Host "Starting analysis in: $LogDirectory" -ForegroundColor Cyan

# Add System.Web for URL decoding (required for IIS logs)
Add-Type -AssemblyName System.Web

# Step 1: Extract compressed files
if (-not (Get-ChildItem -Path $LogDirectory -Filter "extracted_*" -Recurse:$IncludeSubdirectories -ErrorAction SilentlyContinue)) {
    $extracted = Extract-CompressedFiles -Directory $LogDirectory
} else {
    Write-Host "Using previously extracted files" -ForegroundColor Yellow
    $extracted = Get-ChildItem -Path $LogDirectory -Filter "extracted_*" -Recurse:$IncludeSubdirectories
}

# Step 2: Get all log files (original + extracted, access logs and IIS logs)
$allLogFiles = @()

# Apache/Nginx logs
$originalAccessLogs = Get-ChildItem -Path $LogDirectory -Filter "access*.log" -Recurse:$IncludeSubdirectories | Where-Object { -not $_.Name.StartsWith("extracted_") }
$extractedAccessLogs = Get-ChildItem -Path $LogDirectory -Filter "extracted_access*" -Recurse:$IncludeSubdirectories

# IIS logs (u_ex*.log pattern)
$originalIISLogs = Get-ChildItem -Path $LogDirectory -Filter "u_ex*.log" -Recurse:$IncludeSubdirectories | Where-Object { -not $_.Name.StartsWith("extracted_") }
$extractedIISLogs = Get-ChildItem -Path $LogDirectory -Filter "extracted_u_ex*" -Recurse:$IncludeSubdirectories

$allLogFiles += $originalAccessLogs
$allLogFiles += $extractedAccessLogs
$allLogFiles += $originalIISLogs
$allLogFiles += $extractedIISLogs

Write-Host "`n=== ANALYZING LOG FILES ===" -ForegroundColor Yellow
Write-Host "Found $($allLogFiles.Count) log files to analyze"

# Step 3: Process each log file
$fileResults = @()
foreach ($logFile in $allLogFiles) {
    Write-Host "Processing: $($logFile.Name)" -NoNewline
    $result = Process-LogFile -FilePath $logFile.FullName -FileName $logFile.Name
    $fileResults += $result
    
    $totalRequests += $result.TotalRequests
    $botRequests += $result.BotRequests
    Write-Host " [$($result.TotalRequests) requests, $($result.BotRequests) bots]" -ForegroundColor Green
}

# Step 4: Generate report
$reportContent = @"
=== UNIVERSAL BOT TRAFFIC ANALYSIS REPORT ===
Generated: $(Get-Date)
Directory: $LogDirectory
Log Formats Supported: Apache/Nginx Common Log Format, IIS W3C Extended Log Format

=== SUMMARY ===
Total Log Files Processed: $($fileResults.Count)
Extracted Compressed Files: $($extracted.Count)
Total HTTP Requests: $totalRequests
Total Bot Requests: $botRequests
Bot Traffic Percentage: $([Math]::Round(($botRequests / $totalRequests) * 100, 2))%
Unique Bot User Agents: $($botTraffic.Count)

=== LOG FORMAT BREAKDOWN ===
"@

$formatGroups = $fileResults | Group-Object LogFormat
foreach ($group in $formatGroups) {
    $formatRequests = ($group.Group | Measure-Object -Property TotalRequests -Sum).Sum
    $formatBots = ($group.Group | Measure-Object -Property BotRequests -Sum).Sum
    $reportContent += "`n$($group.Name) Format: $($group.Count) files, $formatRequests requests, $formatBots bot requests"
}

$reportContent += "`n`n=== TOP 20 BOT USER AGENTS ==="

$topBots = $botTraffic.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20
for ($i = 0; $i -lt $topBots.Count; $i++) {
    $bot = $topBots[$i]
    $percentage = [Math]::Round(($bot.Value / $botRequests) * 100, 2)
    $reportContent += "`n$($i+1). ($($bot.Value) hits, $percentage%) $($bot.Key)"
}

# Categorize bots
$aiTraffic = $botTraffic.GetEnumerator() | Where-Object { 
    $_.Key -match "(Claude|GPT|OpenAI|Anthropic|Bard|Gemini|Perplexity|AI2|Meta-External|Bytedance|cohere)" 
}
$searchTraffic = $botTraffic.GetEnumerator() | Where-Object { 
    $_.Key -match "(google|bing|yahoo|duckduck|baidu|yandex).*bot" 
}
$seoTraffic = $botTraffic.GetEnumerator() | Where-Object { 
    $_.Key -match "(ahrefs|semrush|moz|majestic|screaming)" 
}

$reportContent += "`n`n=== BOT CATEGORIES ===`n"
if ($aiTraffic.Count -gt 0) {
    $aiTotal = ($aiTraffic | Measure-Object -Property Value -Sum).Sum
    $reportContent += "AI Bots: $aiTotal hits ($([Math]::Round(($aiTotal / $botRequests) * 100, 2))%)`n"
}
if ($searchTraffic.Count -gt 0) {
    $searchTotal = ($searchTraffic | Measure-Object -Property Value -Sum).Sum
    $reportContent += "Search Engine Bots: $searchTotal hits ($([Math]::Round(($searchTotal / $botRequests) * 100, 2))%)`n"
}
if ($seoTraffic.Count -gt 0) {
    $seoTotal = ($seoTraffic | Measure-Object -Property Value -Sum).Sum
    $reportContent += "SEO/Marketing Bots: $seoTotal hits ($([Math]::Round(($seoTotal / $botRequests) * 100, 2))%)`n"
}

$reportContent += "`n=== PER-FILE BREAKDOWN ==="
foreach ($result in $fileResults | Sort-Object BotRequests -Descending) {
    $reportContent += "`n`nFile: $($result.FileName)"
    $reportContent += "`n  Format: $($result.LogFormat)"
    $reportContent += "`n  Total Requests: $($result.TotalRequests)"
    $reportContent += "`n  Bot Requests: $($result.BotRequests)"
    $reportContent += "`n  Bot Percentage: $($result.BotPercentage)%"
    $reportContent += "`n  Unique Bots: $($result.UniqueBots)"
    
    if ($result.TopBots.Count -gt 0) {
        $reportContent += "`n  Top Bots:"
        foreach ($bot in $result.TopBots) {
            $reportContent += "`n    - $($bot.Name) ($($bot.Value) hits)"
        }
    }
}

# Save report
$reportPath = Join-Path $LogDirectory $OutputReport
$reportContent | Out-File -FilePath $reportPath -Encoding UTF8

# Display summary
Write-Host "`n=== ANALYSIS COMPLETE ===" -ForegroundColor Green
Write-Host "Total Requests: $totalRequests" -ForegroundColor White
Write-Host "Bot Requests: $botRequests ($([Math]::Round(($botRequests / $totalRequests) * 100, 2))%)" -ForegroundColor Yellow
Write-Host "Unique Bots: $($botTraffic.Count)" -ForegroundColor White
Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan

# Show top 10 bots
Write-Host "`nTop 10 Bot User Agents:" -ForegroundColor Yellow
$topBotsToShow = [Math]::Min(10, $topBots.Count)
$topBots[0..($topBotsToShow-1)] | ForEach-Object {
    $percentage = [Math]::Round(($_.Value / $botRequests) * 100, 2)
    Write-Host "  $($_.Value) hits ($percentage%) - $($_.Key)" -ForegroundColor White
}