Remove-Item Function:/Connect-AzRedLab -ErrorAction SilentlyContinue

function Connect-AzRedLab {
    <#
        .SYNOPSIS
        Connects to Azure and Microsoft Graph using user credentials or a service principal.

        .DESCRIPTION
        The `Connect-AzRedLab` function authenticates to Azure using either:

        1. A colon-separated credential string in the format `username:password`
        2. Separate `Username` and `Password` parameters

        The password is converted into a SecureString and wrapped in a PSCredential
        object for use with `Connect-AzAccount`.

        Optionally, authentication can be performed as a Service Principal by
        specifying the `-AsServicePrincipal` switch along with a `-Tenant` ID.

        After successful Azure authentication, the function automatically retrieves
        an MS Graph access token via `Get-AzAccessToken` and connects to
        Microsoft Graph using `Connect-MgGraph`.

        Requires:
        - Az.Accounts module
        - Microsoft.Graph module

        .PARAMETER CredentialString
        A colon-separated string in the format:
            username:password

        Mandatory when using the `UserCredential` parameter set.

        .PARAMETER Username
        The username (or Application/Client ID when using Service Principal mode).

        Mandatory when using the `UserPassword` parameter set.

        .PARAMETER Password
        The password associated with the username
        (or Client Secret when using Service Principal mode).

        Mandatory when using the `UserPassword` parameter set.

        .PARAMETER AsServicePrincipal
        Switch indicating authentication should be performed as a Service Principal.
        When specified, the `Tenant` parameter becomes mandatory.

        .PARAMETER Tenant
        The Azure AD Tenant ID or domain name.
        Required when using `-AsServicePrincipal`.

        .PARAMETER ContextName
        Optional Azure context name to create or reuse.
        Defaults to "REDLABS".

        .EXAMPLE
        Connect-AzRedLab -CredentialString "user@example.com:Pa$$w0rd"

        Connects using a colon-separated username and password.

        .EXAMPLE
        Connect-AzRedLab -Username "user@example.com" -Password "Pa$$w0rd"

        Connects using separate username and password parameters.

        .EXAMPLE
        Connect-AzRedLab `
            -Username "00000000-0000-0000-0000-000000000000" `
            -Password "client-secret-value" `
            -AsServicePrincipal `
            -Tenant "11111111-1111-1111-1111-111111111111"

        Connects using a Service Principal (Client ID + Client Secret)
        within the specified Tenant.

        .EXAMPLE
        Connect-AzRedLab -CredentialString "appId:clientSecret" `
            -AsServicePrincipal `
            -Tenant "contoso.onmicrosoft.com"

        Connects as a Service Principal using a credential string
        and a tenant domain.

        .NOTES
        - Tenant is mandatory when using -AsServicePrincipal.
        - ContextName is passed directly to Connect-AzAccount.
        - The function also establishes a Microsoft Graph session.
    #>
    [CmdletBinding(DefaultParameterSetName = "UserCredential")]
    param (
        # Suppress PSScriptAnalyzer rule for this param
        [Parameter(Mandatory, ParameterSetName = "UserCredential")]
        [string]
        $CredentialString,
        [Parameter(Mandatory, ParameterSetName = "UserPassword")]
        [string]
        $Username,
        
        [Parameter(Mandatory, ParameterSetName = "UserPassword")]
        [string]
        $Password,

        [Parameter()]
        [switch]
        $AsServicePrincipal,

        [Parameter()]
        [string]
        $Tenant,

        [Parameter()]
        [string]
        $ContextName = "REDLABS"
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq "UserCredential") {
            $Username, $Password = $CredentialString.Trim().Split(':')
        }

        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

        $azConnectParams = @{
            Credential  = $Credential
            ContextName = $ContextName
            Force       = $true
        }
        if ($AsServicePrincipal) {
            if ([String]::IsNullOrEmpty($Tenant)) {
                throw "Tenant parameter is required."
            }

            $azConnectParams.ServicePrincipal = $true
            $azConnectParams.Tenant = $Tenant
        }
    }

    process {
        Connect-AzAccount @azConnectParams
        $MSGraphToken = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
        if ($MSGraphToken -isnot [System.Security.SecureString]) {
            $MSGraphToken = ConvertTo-SecureString $MSGraphToken -AsPlainText -Force
        }
        Connect-MgGraph -AccessToken $MSGraphToken -NoWelcome
    }
}
