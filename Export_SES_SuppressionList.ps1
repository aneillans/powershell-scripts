<#
.SYNOPSIS
    Exports Amazon SES suppressed email addresses to a CSV file.

.DESCRIPTION
    Retrieves all suppressed destinations from Amazon SES (with optional reason filter)
    and writes them to a CSV file. Supports paging beyond the 1000-item API page size.

.PARAMETER Region
    The AWS region where your SES service is configured (e.g., us-east-1, eu-west-1).

.PARAMETER SuppressionReason
    Optional. Filter by suppression reason: BOUNCE, COMPLAINT, or ALL (default).

.PARAMETER PageSize
    Optional. Page size for AWS pagination (1-1000). Defaults to 1000.

.PARAMETER OutputPath
    Path to the CSV file to write. Defaults to ./SuppressedEmails.csv.

.PARAMETER Append
    If specified, append to the existing CSV instead of overwriting it.

.EXAMPLE
    .\Export_SES_SuppressionList.ps1 -Region us-east-1

.EXAMPLE
    .\Export_SES_SuppressionList.ps1 -Region eu-west-1 -SuppressionReason BOUNCE -OutputPath .\bounces.csv

.EXAMPLE
    .\Export_SES_SuppressionList.ps1 -Region eu-west-1 -Append -OutputPath .\all.csv

.NOTES
    Requires AWS CLI to be installed and configured with appropriate credentials.
    Required IAM permission: ses:ListSuppressedDestinations
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $false)]
    [ValidateSet("BOUNCE", "COMPLAINT", "ALL")]
    [string]$SuppressionReason = "ALL",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,1000)]
    [int]$PageSize = 1000,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./SuppressedEmails.csv",

    [Parameter(Mandatory = $false)]
    [switch]$Append
)

function Test-AWSCLIInstalled {
    try {
        $null = Get-Command aws -ErrorAction Stop
        return $true
    }
    catch {
        Write-Error "AWS CLI is not installed or not in PATH. Please install it from https://aws.amazon.com/cli/"
        return $false
    }
}

function Get-SuppressedEmails {
    param(
        [string]$Region,
        [string]$Reason,
        [int]$PageSize
    )

    Write-Host "Retrieving suppressed email addresses from region: $Region" -ForegroundColor Cyan

    $suppressedEmails = @()
    $nextToken = $null

    do {
        $awsCommand = "aws sesv2 list-suppressed-destinations --region $Region --output json --page-size $PageSize"
        
        if ($Reason -ne "ALL") {
            $awsCommand += " --reasons $Reason"
        }
        
        if ($nextToken) {
            $awsCommand += " --next-token $nextToken"
        }

        try {
            $result = Invoke-Expression $awsCommand | ConvertFrom-Json
            
            if ($result.SuppressedDestinationSummaries) {
                $suppressedEmails += $result.SuppressedDestinationSummaries
            }
            
            $nextToken = $result.NextToken
        }
        catch {
            Write-Error "Failed to retrieve suppressed emails: $_"
            return $null
        }

    } while ($nextToken)

    return $suppressedEmails
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "Amazon SES Suppression Export" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

if (-not (Test-AWSCLIInstalled)) {
    exit 1
}

$suppressedEmails = Get-SuppressedEmails -Region $Region -Reason $SuppressionReason -PageSize $PageSize

if ($null -eq $suppressedEmails -or $suppressedEmails.Count -eq 0) {
    Write-Host "No suppressed email addresses found." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($suppressedEmails.Count) suppressed email address(es)." -ForegroundColor Yellow

# Build output objects
$rows = foreach ($email in $suppressedEmails) {
    [pscustomobject]@{
        EmailAddress   = $email.EmailAddress
        Reason         = $email.Reason
        LastUpdateTime = $email.LastUpdateTime
    }
}

# Resolve output path and ensure directory exists
$fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $fullOutputPath
if (-not (Test-Path $outDir)) {
    $null = New-Item -ItemType Directory -Path $outDir -Force
}

$exportParams = @{ Path = $fullOutputPath; NoTypeInformation = $true }
if ($Append) { $exportParams["Append"] = $true }

$rows | Export-Csv @exportParams

Write-Host "Saved to: $fullOutputPath" -ForegroundColor Green
Write-Host "Export complete." -ForegroundColor Green
