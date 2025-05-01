Remove-Item -Path function:/Invoke-AzClientCredentialsFlow -ErrorAction SilentlyContinue

function Invoke-AzClientCredentialsFlow {
    <#
        .SYNOPSIS
        Authenticates against Azure AD using the OAuth2 client credentials flow.

        .DESCRIPTION
        This function obtains an access token from Azure AD using either a client secret or a certificate. 
        Supports both certificate-based JWT authentication (either local private key or via Azure Key Vault) and client secret authentication.

        .PARAMETER ClientID
        The Azure AD Application (client) ID.

        .PARAMETER TenantID
        The Azure AD tenant ID (also known as directory ID).

        .PARAMETER Scopes
        An array of scopes to request. Each scope typically ends in `/.default` to request application-level permissions.

        .PARAMETER ClientSecret
        [ClientSecret flow only] The secret string configured in the Azure AD app registration.

        .PARAMETER Certificate
        [Certificate flow only] A `X509Certificate2` object containing the public/private key pair used to sign the JWT.

        .PARAMETER CertificateKID
        [Azure Key Vault certificate flow only] The Key ID URL of the certificate stored in Azure Key Vault. Required when using Azure Key Vault for signing.

        .PARAMETER KeyVaultAccessToken
        [Azure Key Vault certificate flow only] A valid bearer token for accessing the Key Vault where the certificate resides.

        .INPUTS
        None. Accepts parameters only.

        .OUTPUTS
        System.String. The OAuth 2.0 access token.

        .EXAMPLE
        Invoke-AzClientCredentialsFlow -ClientID "00000000-0000-0000-0000-000000000000" `
                                    -TenantID "11111111-1111-1111-1111-111111111111" `
                                    -Scopes "https://graph.microsoft.com/.default" `
                                    -ClientSecret "your-client-secret"

        .EXAMPLE
        Invoke-AzClientCredentialsFlow -ClientID "00000000-0000-0000-0000-000000000000" `
                                    -TenantID "11111111-1111-1111-1111-111111111111" `
                                    -Scopes "https://graph.microsoft.com/.default" `
                                    -Certificate $certObject

        .EXAMPLE
        Invoke-AzClientCredentialsFlow -ClientID "00000000-0000-0000-0000-000000000000" `
                                    -TenantID "11111111-1111-1111-1111-111111111111" `
                                    -Scopes "https://graph.microsoft.com/.default" `
                                    -Certificate $certObject `
                                    -CertificateKID "https://yourvault.vault.azure.net/keys/certname/keyversion" `
                                    -KeyVaultAccessToken $accessToken

        .NOTES
        - If using Azure Key Vault to sign the JWT, the certificate in Key Vault must support signing (i.e., has private key usage).
        - Client assertion JWT tokens expire in 2 minutes. Clock skew must be minimal.
        - Follows Microsoft OAuth 2.0 client credentials flow:
        https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow

        .LINK
        https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

    #>

    [CmdletBinding(DefaultParameterSetName = "Certificate")]
    param (
        [Parameter(Mandatory)]
        [string]
        $ClientID,

        [Parameter(Mandatory)]
        [string]
        $TenantID,

        [Parameter(Mandatory)]
        [string[]]
        $Scopes,

        [Parameter(Mandatory, ParameterSetName = "ClientSecret")]
        [string]
        $ClientSecret,

        [Parameter(ParameterSetName = "Certificate")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(ParameterSetName = "Certificate")]
        [string]
        $CertificateKID,

        [Parameter(ParameterSetName = "Certificate")]
        [string]
        $KeyVaultAccessToken
    )

    begin {
        if ($PSCmdlet.ParameterSetName -eq "Certificate") {
            if ($Certificate -and -not $Certificate.HasPrivateKey -and [string]::IsNullOrEmpty($CertificateKID)) {
                throw "The provided certificate does not contain a private key. Please provide -CertificateKID and -KeyVaultAccessToken."
            }

            if (-not [string]::IsNullOrEmpty($CertificateKID) -and [string]::IsNullOrEmpty($KeyVaultAccessToken)) {
                throw "-KeyVaultAccessToken is required."
            }
        }
    }

    process {
        $FormBody = @{
            client_id  = $ClientID
            scope      = $Scopes -join " "
            grant_type = "client_credentials"
        }

        if ($PSCmdlet.ParameterSetName -eq "ClientSecret") {
            $FormBody.Add('client_secret', $ClientSecret)
        }
        elseif ($Certificate.HasPrivateKey) {
            # Create a base64 hash of the certificate. The Base64 encoded string must by urlencoded
            $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='

            $StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
            $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
            $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)

            # Create a NotBefore timestamp. 
            $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
            $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)

            # Create JWT header
            $jwtHeader = @{
                'alg' = "RS256"
                'typ' = "JWT"
                'x5t' = $CertificateBase64Hash
            }

            # Create the payload
            $jwtPayLoad = @{
                'aud' = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                'exp' = $JWTExpiration
                'iss' = $ClientID
                'jti' = [guid]::NewGuid()
                'nbf' = $NotBefore
                'sub' = $ClientID
            }

            # Convert header and payload to json and to base64
            $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
            $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
            $b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
            $b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)

            # Concat header and payload to create an unsigned JWT
            $unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
            $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)

            # Configure RSA padding and hashing algorithm, load private key of certificate and use it to sign the unsigned JWT
            $privateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))
            $padding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
            $hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
            $signedData = $privateKey.SignData($unsignedJwtBytes, $hashAlgorithm, $padding)

            # Create a signed JWT by adding the signature to the unsigned JWT
            $signature = [Convert]::ToBase64String($signedData) -replace '\+', '-' -replace '/', '_' -replace '='

            $FormBody.Add('client_assertion', $unsignedJwt + '.' + $signature)
            $FormBody.Add('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
        }
        else {
            $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='
            # JWT request should be valid for max 2 minutes.
            $StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
            $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
            $JWTExpiration = [math]::Round($JWTExpirationTimeSpan, 0)
            # Create a NotBefore timestamp.
            $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
            $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan, 0)


            # Create JWT header
            $jwtHeader = @{
                'alg' = "RS256"              # Use RSA encryption and SHA256 as hashing algorithm
                'typ' = "JWT"                # We want a JWT
                'x5t' = $CertificateBase64Hash  # The pubkey hash we received from Azure Key Vault
            }

            # Create the payload
            $jwtPayLoad = @{
                'aud' = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
                'exp' = $JWTExpiration      # Expiration of JWT request
                'iss' = $ClientID    # The AppID for which we request a token for
                'jti' = [guid]::NewGuid()   # Random GUID
                'nbf' = $NotBefore          # This should not be used before this timestamp
                'sub' = $ClientID    # Subject
            }

            # Convert header and payload to json and to base64
            $jwtHeaderBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
            $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
            $b64JwtHeader = [System.Convert]::ToBase64String($jwtHeaderBytes)
            $b64JwtPayload = [System.Convert]::ToBase64String($jwtPayloadBytes)

            # Concat header and payload to create an unsigned JWT and compute a Sha256 hash
            $unsignedJwt = $b64JwtHeader + "." + $b64JwtPayload
            $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
            $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
            $jwtSha256Hash = $hasher.ComputeHash($unsignedJwtBytes)
            $jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+', '-' -replace '/', '_' -replace '='

            $uri = "$($CertificateKID)/sign?api-version=7.3"
            $headers = @{
                'Authorization' = "Bearer $KeyVaultAccessToken"
                'Content-Type'  = 'application/json'
            }
            $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered]@{
                        'alg'   = 'RS256'
                        'value' = $jwtSha256HashB64
                    }) | ConvertTo-Json)

            $FormBody.Add('client_assertion', $unsignedJwt + '.' + $response.value)
            $FormBody.Add('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
        }

        $headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
        $response = Invoke-RestMethod -Uri  "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" -Method POST -Headers $headers -Body $FormBody

        return $response.access_token
    }
}
