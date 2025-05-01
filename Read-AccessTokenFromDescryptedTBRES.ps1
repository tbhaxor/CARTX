Remove-Item Function:/Read-AccessTokenFromDescryptedTBRES -ErrorAction SilentlyContinue

function Read-AccessTokenFromDescryptedTBRES {
    <#
        .SYNOPSIS
        Extracts and optionally filters JWT access tokens from a decrypted token broker cache file (TBRES).

        .DESCRIPTION
        The Read-AccessTokenFromDescryptedTBRES function reads a text file containing access tokens,
        parses JWTs found within it, decodes the payloads, and returns relevant metadata such as audience,
        issue time, expiration, UPN, and OID.

        It supports filtering by audience and can optionally include expired tokens.

        .PARAMETER Path
        The file path to the decrypted token repository (TREB) text file that contains access tokens.

        .PARAMETER Audiences
        (Optional) An array of audience strings to filter tokens. Only tokens that contain one of the specified
        audiences in their 'aud' claim will be returned.

        .PARAMETER IncludeExpiredTokens
        (Optional) If specified, expired tokens will be included in the result. By default, expired tokens are excluded.

        .EXAMPLE
        PS> Read-AccessTokenFromDescryptedTBRES -Path 'tokens.txt'

        Returns all valid, non-expired access tokens from the file `tokens.txt`.

        .EXAMPLE
        PS> Read-AccessTokenFromDescryptedTBRES -Path 'tokens.txt' -Audiences 'https://graph.microsoft.com'

        Returns all valid, non-expired tokens that contain `https://graph.microsoft.com` in the audience claim.

        .EXAMPLE
        PS> Read-AccessTokenFromDescryptedTBRES -Path 'tokens.txt' -IncludeExpiredTokens

        Returns all access tokens from the file, including those that are expired.

        .NOTES
        - The function assumes that the file contains raw JWTs in plain text.
        - The JWT format is assumed to be base64url-encoded and follows the standard `header.payload.signature` structure.
        - This function does not verify JWT signatures.

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Path,
        [Parameter()]
        [string[]]
        $Audiences,
        [Parameter()]
        [switch]
        $IncludeExpiredTokens
    )

    $Content = Get-Content -Path $Path -Raw
    $Pattern = 'eyJ0[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+'

    $Results = @()

    if ($content -match $pattern) {
        [regex]::Matches($Content, $pattern) | ForEach-Object {
            $Payload = $_.Value.Split('.')[1]
            $Payload = $Payload -replace '[^A-Za-z0-9+/=]', ''
            switch ($Payload.Length % 4) {
                2 { $Payload += "==" }
                3 { $Payload += "=" }
                1 { return } # skip invalid padding
            }

            try {
                $Decoded = [System.Convert]::FromBase64String($Payload)
                $Json = [System.Text.Encoding]::UTF8.GetString($Decoded) | ConvertFrom-Json
            }
            catch {
                Write-Debug "Faied to decode token: $($_.Value)"
                continue
            }

            $ExpiredAt = [DateTimeOffset]::FromUnixTimeSeconds($Json.exp).UtcDateTime
            $IssuedAt = [DateTimeOffset]::FromUnixTimeSeconds($Json.iat).UtcDateTime

            # Check audience if specified
            if ($Audiences.Count -gt 0) {
                $tokenAud = @()
                if ($Json.aud -is [string]) {
                    $tokenAud = @($Json.aud)
                }
                elseif ($Json.aud -is [System.Collections.IEnumerable]) {
                    $tokenAud = $Json.aud
                }

                if (-not ($Audiences | Where-Object { $tokenAud -contains $_ })) {
                    return
                }
            }

            # Filter out expired tokens unless explicitly allowed
            if ($ExpiredAt -lt [DateTime]::UtcNow -and -not $IncludeExpiredTokens) {
                return
            }

            $Results += [PSCustomObject]@{
                Audience    = $Json.aud
                IssuedAt    = $IssuedAt
                ExpireAt    = $ExpiredAt
                UPN         = $Json.upn
                OID         = $Json.oid
                AccessToken = $_.Value
            }
        }
    }

    return $Results
}
