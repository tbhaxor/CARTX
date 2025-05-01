Remove-Item Function:/Get-AzResourcePermission -ErrorAction SilentlyContinue

function Get-AzResourcePermission {
    <#
        .SYNOPSIS
            Retrieves role-based access permissions for a specified Azure resource.

        .DESCRIPTION
            The Get-AzResourcePermission function queries the Microsoft Authorization provider for a given Azure Resource ID.
            It returns the allowed and denied control and data actions as reported by the ARM API. 
            An optional Azure Resource Manager (ARM) access token can be provided; otherwise, it uses the current context token.

        .PARAMETER ResourceId
            The full Azure Resource ID for the resource (e.g., /subscriptions/{subId}/resourceGroups/{rg}/providers/{provider}/{resourceType}/{resourceName}).
            This parameter is mandatory and accepts input from the pipeline.

        .PARAMETER ARMAccessToken
            Optional. A bearer token for authenticating against the Azure Management API. 
            If not provided, the function retrieves a token using Get-AzAccessToken from the Az.Accounts module.

        .INPUTS
            [string] - The ResourceId can be piped into the function.

        .OUTPUTS
            [PSCustomObject] - An object containing:
                - ControlAllowed : Allowed management actions.
                - ControlDenied  : Denied management actions.
                - DataAllowed    : Allowed data actions.
                - DataDenied     : Denied data actions.

        .EXAMPLE
            Get-AzResourcePermission -ResourceId "/subscriptions/xxxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/myaccount"

        .EXAMPLE
            "/subscriptions/xxxx/resourceGroups/rg/providers/Microsoft.Web/sites/myapp" | Get-AzResourcePermission

        .NOTES
            Requires the Az.Accounts module for Get-AzAccessToken.
            Uses API version 2022-04-01 of Microsoft.Authorization permissions API.

        .LINK
            https://learn.microsoft.com/en-us/rest/api/authorization/permissions/list-for-resource
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]
        $ResourceId,
        [Parameter()]
        [string]
        $ARMAccessToken
    )
    
    if ([string]::IsNullOrEmpty($ARMAccessToken)) {
        $ARMAccessToken = (Get-AzAccessToken).Token
    }
    
    $Response = Invoke-RestMethod -Method Get -Headers @{Authorization = "Bearer $ARMAccessToken" } `
        -Uri "https://management.azure.com$($ResourceId)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    
    return [PSCustomObject]@{
        ControlAllowed = $Response.value.actions
        ControlDenied  = $Response.value.notActions
        DataAllowed    = $Response.value.dataActions
        DataDenied     = $Response.value.dataNotActions
    }
}
