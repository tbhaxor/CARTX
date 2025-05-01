Remove-Item Function:/Invoke-EmailGenerator -ErrorAction SilentlyContinue

function Invoke-EmailGenerator {
    <#
        .SYNOPSIS
        Generates potential email addresses based on a list of names.

        .DESCRIPTION
        This function takes a path to a file containing a list of names and generates potential email addresses for each name.

        .PARAMETER Path
            - Required. 
            - Specifies the path to the file containing the list of names.
            - Positional parameter.

        .PARAMETER Domain
            - Optional. 
            - Specifies the domain name to use for the email addresses. 
            - Defaults to an empty string.

        .RETURNS
        A collection of generated email addresses.

        .EXAMPLE
            
            Invoke-EmailGenerator -Path "C:\Users\Admin\Documents\names.txt" 

        .EXAMPLE
            
            Invoke-EmailGenerator -Path "C:\Users\Admin\Documents\names.txt" -Domain "company.local"

        .NOTES
        * The function assumes that the input file contains a list of names, one name per line.
        * The function generates four variations of email addresses for each name with multiple parts:
            * First name [+ domain]
            * First name + last name [+ domain]
            * First name + first letter of last name [+ domain]
            * First letter of first name + last name [+ domain]
            * First name + admin [+ domain]
        * The function converts all names to lowercase before processing.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 1, Mandatory)]
        [string]
        $Path,
        [Parameter()]
        [string]
        $Domain
    )
    
    $Results = @()

    Get-Content -Path "$Path" | ForEach-Object {
        $nameParts = $_.ToLower() -split ' '
        if ($nameParts.Length -eq 1) {
            $Results += "$($nameParts[0])@$Domain".TrimEnd("@")
        }
        else {
            $Results += "$($nameParts[0])@$Domain".Trim("@")
            $Results += "$($nameParts[0]).$($nameParts[1])@$Domain".Trim("@")
            $Results += "$($nameParts[0]).$($nameParts[1][0])@$Domain".Trim("@")
            $Results += "$($nameParts[0][0]).$($nameParts[1])@$Domain".Trim("@")
            $Results += "$($nameParts[0]).admin@$Domain".Trim("@")
        }
    }

    $Results
}
