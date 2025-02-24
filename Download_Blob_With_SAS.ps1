<#

Download the contents of a Blob Storage Container with a provided SAS token

#>


param(
    [Parameter(Mandatory=$true)]
    [string]$SASuri,
    [Parameter(Mandatory=$true)]
    [string]$DestinationPath,
    [Parameter(Mandatory=$true)]
    [string]$ContainerName
)

Install-Module Az -AllowClobber -Scope CurrentUser -Force

# Chop up the URI
$uri = New-Object System.Uri($SASuri)
$endpoint = "https://$($uri.host)"
# Storage Account
Write-Host "Storage Account: " $endpoint
Write-Host "Container:       " $ContainerName
# Token
Write-Host "SAS Token:       " $uri.Query.replace("?","")

$context = New-AzStorageContext -BlobEndpoint $endpoint -SasToken $uri.Query.replace("?","")

Get-AzStorageBlob -Container $ContainerName -Context $context | ForEach-Object {
    $blob = $_
    $blobName = $blob.Name
    $DestinationPath = $DestinationPath + "\" + $blobName
    Write-Host "Downloading: " $blobName
    Get-AzStorageBlobContent -Container $ContainerName -Blob $blobName -Context $context -Destination $DestinationPath -Force
}