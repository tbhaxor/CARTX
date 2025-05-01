Remove-Item Function:/Test-AADUserLogin -ErrorAction SilentlyContinue

function Test-AADUserLogin {
    <#
    .SYNOPSIS
        Checks the validity of Azure AD user logins by testing if they exist.

    .DESCRIPTION
        This function validates the existence of Azure AD user logins. 
        It accepts email addresses either directly as a parameter or by reading them from a file.
        Each login is sent as a request to the Azure AD credential endpoint to check its existence.
        The function supports retrying failed requests for transient errors.

    .PARAMETER Logins
        A list of email logins to check. 
        If provided, this takes precedence over the Path parameter.

    .PARAMETER Path
        A file path containing email logins (one per line). 
        If Logins is not provided, the function will read email addresses from this file.

    .PARAMETER MaxRetries
        The maximum number of retry attempts for each login if a request fails due to transient errors.
        Default is 3 retries.

    .PARAMETER RetryDelay
        The delay (in seconds) between retry attempts for failed requests.
        Default is 2 seconds.

    .EXAMPLE
        Test-AADUserLogin -Logins "user1@example.com", "user2@example.com"
        Checks the validity of the provided email addresses.

    .EXAMPLE
        Test-AADUserLogin -Path "C:\emails.txt"
        Reads email addresses from the specified file and checks their validity.

    .EXAMPLE
        Test-AADUserLogin -Logins "user1@example.com" -MaxRetries 5 -RetryDelay 3
        Checks the validity of the email address with up to 5 retries for transient failures, with a delay of 3 seconds between retries.

    .OUTPUTS
        PSCustomObject
            - Login: The email address tested.
            - Valid: A boolean indicating whether the login exists (true) or not (false).

    .NOTES
        This function uses the Azure AD credential endpoint to validate user logins.
        Debug messages provide detailed information about the request process.

    .LINK
        https://learn.microsoft.com/en-us/azure/active-directory/
    #>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $false,
            HelpMessage = "A list of email logins to test for existence. If provided, this takes precedence over the Path parameter."
        )]
        [string[]]
        $Logins,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "A file path containing email logins (one per line). Used if the Logins parameter is not provided."
        )]
        [string]
        $Path,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "Maximum number of retry attempts for transient request failures. Default is 10."
        )]
        [int]
        $MaxRetries = 10,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "Delay in seconds between retry attempts for transient request failures. Default is 2 seconds."
        )]
        [int]
        $RetryDelay = 2
    )

    begin {
        if (-not $Logins -and -not $Path) {
            throw "You must provide either a value for the `-Logins` parameter or the `-Path` parameter."
        }
    }

    process {
        if ($Logins) {
            $Logins = $Logins | ForEach-Object { $_.Trim() } | Where-Object { ![System.String]::IsNullOrEmpty($_) } | Select-Object -Unique
        }
        elseif ($Path) {
            if (Test-Path -Path $Path) {
                $Logins = Get-Content -Path $Path | ForEach-Object { $_.Trim() } | Where-Object { ![System.String]::IsNullOrEmpty($_) } | Select-Object -Unique
            }
            else {
                throw "The file at path '$Path' does not exist."
            }
        }

        $Results = @()
        foreach ($Login in $Logins) {
            Write-Debug "Starting login check for: $Login"
            
            $Attempt = 0
            $Success = $false
            $response = $null

            while (-not $Success -and $Attempt -lt $MaxRetries) {
                try {
                    $Attempt++
                    Write-Debug "Attempt $Attempt for $Login"
                    $response = Invoke-WebRequest -Method Post -Headers @{ 'Content-Type' = 'application/json' } `
                        -Body (@{ username = $Login } | ConvertTo-Json -Depth 1) `
                        -SkipHttpErrorCheck -Uri "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-GB"
                    if (($response.Content | ConvertFrom-Json).ThrottleStatus -eq 1) {
                        throw "Request throttled for $Login"
                    }
                    $Success = $true
                }
                catch {
                    Write-Warning "Attempt $Attempt for $Login failed: $_"
                    if ($Attempt -lt $MaxRetries) {
                        Write-Debug "Retrying in $RetryDelay seconds..."
                        Start-Sleep -Seconds $RetryDelay
                    }
                    else {
                        Write-Error "Maximum retries reached for $Login. Skipping..."
                    }
                }
            }

            if ($Success -and $response) {
                $body = ($response.Content | ConvertFrom-Json)
                $isValid = $body.IfExistsResult -eq 0
                Write-Debug "Completed login check for: $Login, Valid: $isValid"
                $Results += [PSCustomObject]@{
                    Login = $Login
                    Valid = $isValid
                }
            }
            else {
                Write-Debug "Skipping $Login due to repeated failures."
            }
        }

        return $Results
    }
}
