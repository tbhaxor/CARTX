# CARTX

**CARTX** is a collection of PowerShell scripts created during the **CARTP** and **CARTE** exams to streamline assessments and enhance results in Azure and Entra ID environments.

## Included Functions

- `Connect-AzRedLab`  
  Connect to Azure RedLabs and Microsoft Graph.

- `Get-AzResourcePermission`  
  Retrieve permissions on Azure resources, even without Reader role.

- `Get-MgRoleAssignment`  
  Get role assignments of identities in Entra ID, with directory scope expansion.

- `Invoke-AzClientCredentialsFlow`  
  Obtain access tokens for enterprise applications using client ID and secret or certificate. Supports JWT signing via Azure Key Vault.

- `Invoke-AzDeviceCodeLogin`  
  Initiate the device code login flow. Waits for authentication and returns tokens upon success.

- `Invoke-AzRefreshToken`  
  Refresh tokens using FOCI abuse techniques.

- `Invoke-EmailGenerator`  
  Generate email addresses using a domain or display name wordlist.

- `New-AzStorageAccountSAS`  
  Generate SAS URLs for Azure Storage accounts or containers.

- `Read-AccessTokenFromDescryptedTBRES`  
  Extract JWT tokens from decrypted TBRES files. Expired tokens are filtered out by default.

- `Test-AADUserLogin`  
  Perform password spraying against AAD user accounts. Includes throttling bypass using the `Start-Sleep` cmdlet.

## Compatibility

✅ **Tested on**: PowerShell 7 (Linux)  
⚠️ **Partial PowerShell 5 support**: Some scripts work on PowerShell 5, but the full set has not been tested. PRs to improve compatibility are welcome.

## Contact

- 🐦 Twitter: [@tbhaxor](https://twitter.com/tbhaxor)  
- 💼 LinkedIn: [@tbhaxor](https://www.linkedin.com/in/tbhaxor)  
- 📧 Email: [info@tbhaxor.com](mailto:info@tbhaxor.com)
