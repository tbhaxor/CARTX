Remove-Item Function:/Connect-AzRedLab -ErrorAction SilentlyContinue

function Connect-AzRedLab {
    <#
        .SYNOPSIS
        Connects to an Azure account using either a colon-separated credential string or separate username and password.

        .DESCRIPTION
        The `Connect-AzRedLab` function facilitates connecting to an Azure account with either:
        - A single colon-separated string containing username and password (`username:password`)
        - Separate `Username` and `Password` parameters.

        It converts the plain password to a secure string and uses it to create a PSCredential object, which is then passed to `Connect-AzAccount`. The function also supports specifying a custom Azure context name.

        .PARAMETER CredentialString
        A colon-separated string of the format `username:password`. This parameter is mandatory if using the `UserCredential` parameter set.

        .PARAMETER Username
        The username used for Azure authentication. This is mandatory if using the `UserPassword` parameter set.

        .PARAMETER Password
        The corresponding password for the username. This is mandatory if using the `UserPassword` parameter set.

        .PARAMETER ContextName
        (Optional) The name of the Azure context to use or create. Defaults to `"REDLABS"`.

        .EXAMPLE
        Connect-AzRedLab -CredentialString "user@example.com:Pa$$w0rd"

        .EXAMPLE
        Connect-AzRedLab -Username "user@example.com" -Password "Pa$$w0rd"

        .NOTES
        - Requires the Az PowerShell module.
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
        [string]
        $ContextName = "REDLABS"
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq "UserCredential") {
            $Username, $Password = $CredentialString.Trim().Split(':')
        }

        $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
    }

    process {
        Connect-AzAccount -Credential $Credential -ContextName $ContextName -Force
        $MSGraphToken = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
        if ($MSGraphToken -isnot [System.Security.SecureString]) {
            $MSGraphToken = ConvertTo-SecureString $MSGraphToken -AsPlainText -Force
        }
        Connect-MgGraph -AccessToken $MSGraphToken
    }
}
