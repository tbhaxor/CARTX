Remove-Item Function:/Invoke-AzDeviceCodeLogin -ErrorAction SilentlyContinue

function Invoke-AzDeviceCodeLogin {
    <#
        .SYNOPSIS
            Initiates the OAuth 2.0 Device Code Flow for Azure AD and returns an access token.

        .DESCRIPTION
            This function starts the device code authentication flow using the Microsoft identity platform (v2 endpoint). 
            It generates a device code and prompts the user to authenticate via a browser.
            Once authenticated, it polls the token endpoint until an access token is issued or the process fails.

        .PARAMETER ClientID
            The Azure AD application's client ID (app registration).
            This is mandatory and used to identify the requesting application.

        .INPUTS
            [string] - Accepts a Client ID string as input.

        .OUTPUTS
            [PSCustomObject] - An object containing:
                - AccessToken  : The OAuth 2.0 access token.
                - RefreshToken : The refresh token for long-lived sessions.
                - IDToken      : The OpenID Connect ID token.
                - ScopeList    : An array of granted scopes.

        .EXAMPLE
            Invoke-AzDeviceCodeLogin -ClientID "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

        .NOTES
            - This uses Microsoft’s v2 OAuth 2.0 device code endpoint: https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
            - Scopes are set to `.default offline_access`.
            - Requires no external modules. Useful for low-dependency login flows.
            - Handles polling and common OAuth errors like pending authorisation, code expiry, or user decline.

        .LINK
            https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ClientID
    )

    $device_code_form_body = @{
        client_id = $ClientID
        scope     = '.default offline_access'
    }
    
    $device_code_response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" `
        -Method Post `
        -Form $device_code_form_body `
        -Headers @{"Content-Type" = "application/x-www-form-urlencoded" }

    Write-Host -ForegroundColor Green '[!] ' -NoNewline
    Write-Host $device_code_response.message
    if (-not $PSBoundParameters.ContainsKey('Debug')) { 
        Write-Host -ForegroundColor Cyan '[~] ' -NoNewline
        Write-Host 'Waiting for user interaction' -NoNewline
    }

    while ($true) {
        $token_form_body = @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            device_code = $device_code_response.device_code
            client_id   = $ClientID
        }
            
        $token_response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
            -Method Post -SkipHttpErrorCheck `
            -Form $token_form_body `
            -Headers @{"Content-Type" = "application/x-www-form-urlencoded" } 
        switch ($token_response.error) {
            authorization_pending { 
                if (-not $PSBoundParameters.ContainsKey('Debug')) { 
                    Write-Host "." -NoNewline
                }
                else {
                    Write-Debug 'Authorization is pending...' 
                }
            
            }
            authorization_declined { throw 'User declined the authentication...' }
            bad_verification_code { throw 'Invalid device code...' }
            expired_token { throw 'Token is expired' }
            default {
                Write-Debug "Authorization completed, transforming and returning..."
                if ($token_response.foci -eq 1) {
                    if (-not $PSBoundParameters.ContainsKey('Debug')) { 
                        Write-Host
                    }
                    Write-Host -ForegroundColor Green '[!] ' -NoNewline
                    Write-Information -MessageData "FOCI flag is set" -InformationAction Continue
                }
                return [PSCustomObject]@{
                    AccessToken  = $token_response.access_token
                    RefreshToken = $token_response.refresh_token
                    IDToken      = $token_response.id_token
                    ScopeList    = $token_response.scope -split ' '
                }
            }
        }
        Start-Sleep -Seconds $device_code_response.interval
    }
}
