<#
.SYNOPSIS
    Clears email addresses from the Amazon SES Suppression List.

.DESCRIPTION
    This script retrieves all suppressed email addresses from Amazon SES and removes them
    from the suppression list. It supports filtering by suppression reason (BOUNCE or COMPLAINT).

.PARAMETER Region
    The AWS region where your SES service is configured (e.g., us-east-1, eu-west-1).

.PARAMETER SuppressionReason
    Optional. Filter by suppression reason: BOUNCE, COMPLAINT, or ALL (default).

.PARAMETER PageSize
    Optional. Page size for AWS pagination (1-1000). Defaults to 1000 to process beyond the 1000 item limit.

.EXAMPLE
    .\Clear_SES_SuppressionList.ps1 -Region us-east-1
    Clears all suppressed emails in the us-east-1 region.

.EXAMPLE
    .\Clear_SES_SuppressionList.ps1 -Region eu-west-1 -SuppressionReason BOUNCE -WhatIf
    Shows what BOUNCE suppressed emails would be removed without actually removing them.

.NOTES
    Requires AWS CLI to be installed and configured with appropriate credentials.
    Required IAM permissions: ses:ListSuppressedDestinations, ses:DeleteSuppressedDestination
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $false)]
    [ValidateSet("BOUNCE", "COMPLAINT", "ALL")]
    [string]$SuppressionReason = "ALL",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1,1000)]
    [int]$PageSize = 1000
)

# Check if AWS CLI is installed
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

# Get suppressed email addresses from SES
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
        # Build the AWS CLI command; use --next-token to page beyond 1000 items
        $awsCommand = "aws sesv2 list-suppressed-destinations --region $Region --output json --page-size $PageSize"
        
        if ($Reason -ne "ALL") {
            $awsCommand += " --reasons $Reason"
        }
        
        if ($nextToken) {
            $awsCommand += " --next-token $nextToken"
        }

        # Execute the command
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

# Remove an email from the suppression list
function Remove-SuppressedEmail {
    param(
        [string]$EmailAddress,
        [string]$Region
    )

    try {
        $awsCommand = "aws sesv2 delete-suppressed-destination --email-address `"$EmailAddress`" --region $Region"
        $null = Invoke-Expression $awsCommand
        return $true
    }
    catch {
        Write-Error "Failed to remove $EmailAddress : $_"
        return $false
    }
}

# Main execution
Write-Host "========================================" -ForegroundColor Green
Write-Host "Amazon SES Suppression List Cleaner" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Verify AWS CLI is installed
if (-not (Test-AWSCLIInstalled)) {
    exit 1
}

# Get suppressed emails
$suppressedEmails = Get-SuppressedEmails -Region $Region -Reason $SuppressionReason -PageSize $PageSize

if ($null -eq $suppressedEmails -or $suppressedEmails.Count -eq 0) {
    Write-Host "No suppressed email addresses found." -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($suppressedEmails.Count) suppressed email address(es)." -ForegroundColor Yellow
Write-Host ""

# Display the emails
Write-Host "Suppressed Emails:" -ForegroundColor Cyan
foreach ($email in $suppressedEmails) {
    Write-Host "  - $($email.EmailAddress) (Reason: $($email.Reason), Last Update: $($email.LastUpdateTime))" -ForegroundColor Gray
}
Write-Host ""

# Confirm before proceeding (honors -WhatIf / -Confirm from SupportsShouldProcess)
if (-not $WhatIfPreference) {
    if ($PSCmdlet.ShouldProcess("All suppressed emails", "Remove from suppression list")) {
        $response = Read-Host "Do you want to remove all these email addresses from the suppression list? (y/n)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            exit 0
        }
    }
}

# Remove emails
$successCount = 0
$failCount = 0

Write-Host "Processing removals..." -ForegroundColor Cyan

foreach ($email in $suppressedEmails) {
    if ($WhatIfPreference) {
        Write-Host "[WHATIF] Would remove: $($email.EmailAddress)" -ForegroundColor Magenta
        $successCount++
    }
    else {
        if ($PSCmdlet.ShouldProcess($email.EmailAddress, "Remove from suppression list")) {
            Write-Host "Removing: $($email.EmailAddress)..." -NoNewline
            if (Remove-SuppressedEmail -EmailAddress $email.EmailAddress -Region $Region) {
                Write-Host " SUCCESS" -ForegroundColor Green
                $successCount++
            }
            else {
                Write-Host " FAILED" -ForegroundColor Red
                $failCount++
            }
        }
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Green
if ($WhatIfPreference) {
    Write-Host "  Would remove: $successCount email(s)" -ForegroundColor Magenta
}
else {
    Write-Host "  Successfully removed: $successCount email(s)" -ForegroundColor Green
    if ($failCount -gt 0) {
        Write-Host "  Failed: $failCount email(s)" -ForegroundColor Red
    }
}
Write-Host "========================================" -ForegroundColor Green
