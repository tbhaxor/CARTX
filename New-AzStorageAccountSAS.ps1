Remove-Item Function:/New-AzStorageAccountSAS -ErrorAction SilentlyContinue

function New-AzStorageAccountSAS
{
    <#
        .SYNOPSIS
        Generates a Shared Access Signature (SAS) token for an Azure Storage Account or a specific blob container.

        .DESCRIPTION
        This function uses the Azure Management REST API to generate either a service-level SAS token for a specified blob container or an account-level SAS token when no container is specified.
        It uses a bearer token obtained via `Get-AzAccessToken` unless one is explicitly provided via the `ARMAccessToken` parameter.

        .PARAMETER ResourceGroupName
        The name of the Azure resource group containing the storage account.

        .PARAMETER StorageAccountName
        The name of the Azure Storage Account for which to generate the SAS token.

        .PARAMETER SubscriptionId
        The Azure subscription ID under which the storage account resides.

        .PARAMETER Container
        (Optional) The name of a blob container. If specified, a service-level SAS token is generated for that container. If not specified, an account-level SAS token is generated.

        .PARAMETER ARMAccessToken
        (Optional) An Azure Resource Manager (ARM) access token. If not supplied, the function will attempt to obtain one using `Get-AzAccessToken`.

        .OUTPUTS
        System.String
        Returns the full URI with the generated SAS token appended for the blob container or storage account.

        .EXAMPLE
        PS> New-AzStorageAccountSAS -ResourceGroupName "myRG" -StorageAccountName "mystorage" -SubscriptionId "00000000-0000-0000-0000-000000000000"

        Generates an account-level SAS token for the specified storage account.

        .EXAMPLE
        PS> New-AzStorageAccountSAS -ResourceGroupName "myRG" -StorageAccountName "mystorage" -SubscriptionId "00000000-0000-0000-0000-000000000000" -Container "mycontainer"

        Generates a container-level SAS token for the specified blob container.

        .NOTES
        Author: @tbhaxor
        API Version: 2023-05-01
        Requires Azure PowerShell module with `Get-AzAccessToken` support.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $True)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $True)]
        [string]
        $SubscriptionId,

        [Parameter()]
        [string]
        $Container,

        [Parameter()]
        [string]
        $ARMAccessToken
    )

    if ( [string]::IsNullOrEmpty($ARMAccessToken))
    {
        $ARMAccessToken = (Get-AzAccessToken -ResourceTypeName Arm -WarningAction SilentlyContinue).Token
    }

    if (![string]::IsNullOrEmpty($Container))
    {
        Write-Verbose "Generting service SAS for $Container container"
        $RequestOptions = @{
            Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/ListServiceSas?api-version=2023-05-01"
            Method = 'POST'
            Headers = @{
                Authorization = "Bearer $ARMAccessToken"
                'Content-Type' = 'application/json'
            }
        }
        $Body = @{
            canonicalizedResource = "/blob/$StorageAccountName/$Container"
            signedResource = 'c'
            signedPermission = 'rl'
            signedIdentifier = (New-Guid).Guid
            signedExpiry = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
        }

        $Response = Invoke-RestMethod @RequestOptions -Body (ConvertTo-Json -InputObject $Body)

        return "https://$StorageAccountName.blob.core.windows.net/$($Container)?$($Response.serviceSasToken)"
    }
    else
    {
        Write-Verbose "Generting account SAS"
        $RequestOptions = @{
            Uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/ListAccountSas?api-version=2023-05-01"
            Method = 'POST'
            Headers = @{
                Authorization = "Bearer $ARMAccessToken"
                'Content-Type' = 'application/json'
            }
        }
        $Body = @{
            signedExpiry = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
            signedPermission = 'rl'
            signedResourceTypes = 'soc'
            signedServices = 'b'
            signedProtocol = 'https,http'
        }

        $Response = Invoke-RestMethod @RequestOptions -Body (ConvertTo-Json -InputObject $Body)

        return "https://$StorageAccountName.blob.core.windows.net?$($Response.accountSasToken)"
    }
}
