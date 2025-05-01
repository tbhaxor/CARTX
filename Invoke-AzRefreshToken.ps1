Remove-Item Function:/Invoke-AzRefreshToken -ErrorAction SilentlyContinue

function Invoke-AzRefreshToken {
    <#
        .SYNOPSIS
            Exchanges a refresh token for a new access token via Azure AD OAuth 2.0 v2 endpoint.

        .DESCRIPTION
            This function takes a refresh token and requests a new access token (and optionally a new refresh token and ID token) from Azure AD.
            It supports specifying the tenant domain (or tenant ID), resource, and optional client ID.
            By default, the client ID is set to that of Azure PowerShell ("1950a258-227b-4e31-a9cf-717495945fc2").

        .PARAMETER Domain
            The Azure AD tenant ID or domain name (e.g., contoso.onmicrosoft.com or a GUID).
            Used to construct the token endpoint URI.

        .PARAMETER RefreshToken
            The refresh token previously issued by Azure AD.

        .PARAMETER Resource
            The resource identifier for which the access token is requested (e.g., https://management.azure.com).

        .PARAMETER ClientID
            Optional. The application/client ID to use for the token request.
            Defaults to "1950a258-227b-4e31-a9cf-717495945fc2", which is used by Azure PowerShell.

        .INPUTS
            None. All parameters are explicit.

        .OUTPUTS
            [PSCustomObject] - An object containing:
                - AccessToken  : The OAuth 2.0 access token.
                - RefreshToken : The new refresh token (if issued).
                - IDToken      : The ID token (if issued).

        .EXAMPLE
            Invoke-AzRefreshToken -Domain "contoso.onmicrosoft.com" `
                -RefreshToken "0.ARwA..." `
                -Resource "https://graph.microsoft.com"

        .NOTES
            - Uses the v2.0 token endpoint: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
            - Requires no external modules.
            - Useful in custom token workflows, especially in automation scenarios.

        .LINK
            https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Domain,
        [Parameter(Mandatory)]
        [string]
        $RefreshToken,
        [Parameter(Mandatory)]
        [string]
        $Resource,
        [Parameter()]
        [string]
        $ClientID = "1950a258-227b-4e31-a9cf-717495945fc2" # looks like az powershell requesting
    )

    $body = @{
        client_id     = $ClientID
        grant_type    = "refresh_token"
        refresh_token = $RefreshToken
        scope         = "$Resource/.default"
    }
    
    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Domain/oauth2/v2.0/token" `
        -Method Post -Body $body -Headers @{"Content-Type" = "application/x-www-form-urlencoded" }

    return [PSCustomObject]@{
        AccessToken  = $response.access_token
        RefreshToken = $response.refresh_token
        IDToken      = $response.id_token 
    }
}
