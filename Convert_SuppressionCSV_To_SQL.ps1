<#
.SYNOPSIS
    Converts an SES suppression CSV export into SQL INSERT statements.

.DESCRIPTION
    Reads a CSV with columns EmailAddress, Reason, LastUpdateTime and produces
    INSERT statements for a target table. Handles pagination-sized exports and
    normalizes dates to ISO 8601 (UTC) where possible.

.PARAMETER InputPath
    Path to the suppression CSV (default: ./SuppressedEmails.csv).

.PARAMETER OutputPath
    Path to write the generated SQL file (default: ./SuppressedEmails.sql).

.PARAMETER TableName
    Target table name (default: SuppressedEmails).

.PARAMETER Schema
    Optional schema name (default: dbo). If empty, only TableName is used.

.PARAMETER Collation
    Optional SQL collation name to apply to string literals (EmailAddress, Reason).
    Example: Latin1_General_CI_AI or SQL_Latin1_General_CP1_CI_AS.

.PARAMETER Append
    Append to OutputPath instead of overwriting it.

.EXAMPLE
    .\Convert_SuppressionCSV_To_SQL.ps1 -InputPath .\SuppressedEmails.csv -OutputPath .\SuppressedEmails.sql -TableName SuppressedEmails -Schema dbo

.EXAMPLE
    .\Convert_SuppressionCSV_To_SQL.ps1 -Append

.NOTES
    Assumes CSV headers: EmailAddress, Reason, LastUpdateTime
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$InputPath = "./SuppressedEmails.csv",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./SuppressedEmails.sql",

    [Parameter(Mandatory = $false)]
    [string]$TableName = "SuppressedEmails",

    [Parameter(Mandatory = $false)]
    [string]$Schema = "dbo",

    [Parameter(Mandatory = $false)]
    [string]$Collation,

    [Parameter(Mandatory = $false)]
    [switch]$Append
)

function Escape-SQLString {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    return $Value -replace "'", "''"
}

function Format-DateISO8601 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        # Try common formats we expect from AWS exports
        $trim = $Value.Trim()
        # Handle '... UTC' by converting to 'Z' so DateTimeOffset can parse reliably
        if ($trim -match "\sUTC$") { $trim = $trim -replace "\sUTC$", "Z" }

        # Try DateTimeOffset parse first (handles Z/offsets)
        $dto = $null
        if ([System.DateTimeOffset]::TryParse($trim, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
            return $dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")
        }

        # Fallback for dd/MM/yyyy HH:mm:ss style (Exported suppression list)
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")
        $dt = [DateTime]::Parse($Value, $culture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        return $dt.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch {
        return $null
    }
}

# Validate input
if (-not (Test-Path $InputPath)) {
    Write-Error "Input CSV not found: $InputPath"
    exit 1
}

# Resolve output path and ensure directory exists
$fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $fullOutputPath
if (-not (Test-Path $outDir)) {
    $null = New-Item -ItemType Directory -Path $outDir -Force
}

# Load CSV
try {
    $rows = Import-Csv -Path $InputPath
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 1
}

if (-not $rows -or $rows.Count -eq 0) {
    Write-Host "No rows found in CSV." -ForegroundColor Yellow
    exit 0
}

$first = $rows | Select-Object -First 1
$headers = @($first.PSObject.Properties.Name)

# Detect input format
$inputFormat = if ($headers -contains 'EmailAddress') {
    'SuppressionExport'
} elseif ($headers -contains 'destination' -and $headers -contains 'last_delivery_event') {
    'BounceExport'
} else {
    'Unknown'
}

$targetTable = if ([string]::IsNullOrWhiteSpace($Schema)) { $TableName } else { "$Schema.$TableName" }

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("-- Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine("-- Source: $InputPath")
[void]$sb.AppendLine("-- Target: $targetTable")
[void]$sb.AppendLine("-- DetectedFormat: $inputFormat")

switch ($inputFormat) {
    'SuppressionExport' {
        foreach ($row in $rows) {
            $email = Escape-SQLString $row.EmailAddress
            if ([string]::IsNullOrWhiteSpace($email)) { continue }
            $reason = Escape-SQLString $row.Reason
            $dt = Format-DateISO8601 $row.LastUpdateTime
            $dtValue = if ($dt) { "'$dt'" } else { "NULL" }
            $emailSql = if ([string]::IsNullOrWhiteSpace($Collation)) { "'$email'" } else { "'$email' COLLATE $Collation" }
            $reasonSql = if ([string]::IsNullOrWhiteSpace($Collation)) { "'$reason'" } else { "'$reason' COLLATE $Collation" }
            $stmt = "INSERT INTO $targetTable (EmailAddress, Reason, LastUpdateTime) VALUES ($emailSql, $reasonSql, $dtValue);"
            [void]$sb.AppendLine($stmt)
        }
    }
    'BounceExport' {
        foreach ($row in $rows) {
            $emailRaw = $row.destination
            $email = Escape-SQLString $emailRaw
            if ([string]::IsNullOrWhiteSpace($email)) { continue }

            # Determine reason
            $reasonComputed = 'BOUNCE'
            $complainedVal = ("" + $row.complained).Trim()
            $bouncedVal = ("" + $row.bounced).Trim()
            $lastDelivery = ("" + $row.last_delivery_event).Trim()
            $lastEngagement = ("" + $row.last_engagement_event).Trim()

            if ($complainedVal -match '^(1|true|TRUE|True)$' -or $lastDelivery -like '*COMPLAINT*' -or $lastEngagement -like '*COMPLAINT*') {
                $reasonComputed = 'COMPLAINT'
            } else {
                $reasonComputed = 'BOUNCE'
            }

            $reason = Escape-SQLString $reasonComputed

            # Choose best timestamp: last_delivery_event_timestamp, else sendtimestamp
            $dtCandidate = if ([string]::IsNullOrWhiteSpace($row.last_delivery_event_timestamp)) { $row.sendtimestamp } else { $row.last_delivery_event_timestamp }
            $dt = Format-DateISO8601 $dtCandidate
            $dtValue = if ($dt) { "'$dt'" } else { "NULL" }

            $emailSql = if ([string]::IsNullOrWhiteSpace($Collation)) { "'$email'" } else { "'$email' COLLATE $Collation" }
            $reasonSql = if ([string]::IsNullOrWhiteSpace($Collation)) { "'$reason'" } else { "'$reason' COLLATE $Collation" }

            $stmt = "INSERT INTO $targetTable (EmailAddress, Reason, LastUpdateTime) VALUES ($emailSql, $reasonSql, $dtValue);"
            [void]$sb.AppendLine($stmt)
        }
    }
    Default {
        Write-Error "Unrecognized CSV format. Expected headers like 'EmailAddress' or 'destination,last_delivery_event'."
        exit 1
    }
}

$encoding = New-Object System.Text.UTF8Encoding($false)
if ($Append) {
    [System.IO.File]::AppendAllText($fullOutputPath, $sb.ToString(), $encoding)
}
else {
    [System.IO.File]::WriteAllText($fullOutputPath, $sb.ToString(), $encoding)
}

Write-Host "Generated $($rows.Count) INSERT statements." -ForegroundColor Green
Write-Host "Saved to: $fullOutputPath" -ForegroundColor Green
