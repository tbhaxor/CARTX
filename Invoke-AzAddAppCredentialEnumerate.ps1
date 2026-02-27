Remove-Item Function:/Invoke-AzAddAppCredentialEnumerate -ErrorAction SilentlyContinue

function Invoke-AzAddAppCredentialEnumerate {
    <#
        .SYNOPSIS
        Enumerates Microsoft Entra applications for which a principal can potentially add or update credentials.

        .DESCRIPTION
        Invoke-AzAddAppCredentialBruteforce inspects directory role assignments for a given
        principal and determines whether any assigned roles grant permission to:

        - microsoft.directory/applications/credentials/update
        - microsoft.directory/applications/create
        - microsoft.directory/applications/createAsOwner
        - microsoft.directory/applications.myOrganization/credentials/update

        If a role grants tenant-wide scope ("/"), the function returns all applications
        in the tenant.

        If a role is scoped to a specific application object, the function retrieves
        only those scoped applications.

        Additionally, the function enumerates applications owned by the current user
        and includes them in the final result.

        Results are deduplicated by application Id.

        This function relies on Microsoft Graph Role Management and Application APIs.

        References:
        Role permissions model
        https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference

        Unified role assignments
        https://learn.microsoft.com/graph/api/resources/unifiedroleassignment

        Application resource
        https://learn.microsoft.com/graph/api/resources/application
        
        Application registration permissions for custom roles in Microsoft Entra ID
        https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-available-permissions

        .PARAMETER PrincipalId
        The object ID of the user or service principal whose effective application
        credential permissions should be evaluated.

        If not specified, the currently authenticated Microsoft Graph user context
        is used.

        .OUTPUTS
        Microsoft.Graph.PowerShell.Models.IMicrosoftGraphApplication

        Returns a unique collection of application objects where the principal may
        be able to create or update credentials.

        .EXAMPLE
        Invoke-AzAddAppCredentialBruteforce

        Evaluates the currently signed-in user and returns applications where
        credential operations may be possible.

        .EXAMPLE
        Invoke-AzAddAppCredentialBruteforce -PrincipalId 11111111-2222-3333-4444-555555555555

        Evaluates a specific principal by object ID.

        .NOTES
        - Requires RoleManagement.Read.Directory or RoleManagement.ReadWrite.Directory.
        - Requires Application.Read.All or equivalent.
        - Object-scoped role assignments require Microsoft Entra ID P1 or P2 licensing.
        - The function performs multiple Graph calls and may be slow in large tenants.
        - The owned application check performs per-application owner lookups and is not optimised for scale.

        .LIMITATIONS
        - Does not evaluate Privileged Identity Management activation state.
        - Does not evaluate conditional access or runtime policy enforcement.
        - Behaviour in tenants without scoped role support is untested.
    #>

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $PrincipalId
    )
    
    begin {
        if ([string]::IsNullOrEmpty($PrincipalId)) {
            $account = (Get-MgContext).Account
            Write-Verbose "Using current logged in account ($account) as filter"
            $PrincipalId = (Get-MgUser -UserId $account).Id
        }
    }

    process {
        $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment `
            -Filter "principalId eq '$PrincipalId'" `
            -ExpandProperty RoleDefinition `
            -All
        $roleAssignments
        $secretCapableRoles = @()
        $roleBasedApps = @()

        foreach ($roleAssignment in $roleAssignments) {
            $hasSecretPermission = $false

            foreach ($rolePermission in $roleAssignment.RoleDefinition.RolePermissions) {
                if (
                    $rolePermission.AllowedResourceActions -contains "microsoft.directory/applications/credentials/update" -or
                    $rolePermission.AllowedResourceActions -contains "microsoft.directory/applications/create" -or
                    $rolePermission.AllowedResourceActions -contains "microsoft.directory/applications/createAsOwner" -or
                    $rolePermission.AllowedResourceActions -contains "microsoft.directory/applications.myOrganization/credentials/update"
                ) {
                    $hasSecretPermission = $true
                    break
                }
            }

            if (-not $hasSecretPermission) { continue }
            
            if ($roleAssignment.DirectoryScopeId -eq "/" -or [string]::IsNullOrEmpty($roleAssignment.DirectoryScopeId)) {
                return Get-MgApplication -All
            }

            $secretCapableRoles += $roleAssignment
        }

        # NOTE:
        # It has not been fully tested because the current tenant does not have a paid
        # Microsoft Entra ID (Azure AD) licence required for custom or scoped role assignments.
        # Validation should be performed in a tenant with appropriate licensing enabled.
        foreach ($role in $secretCapableRoles) {
            $app = Get-MgApplication -ApplicationId $role.DirectoryScopeId.TrimStart('/') -ErrorAction SilentlyContinue
            $roleBasedApps += $app
        }

        $ownedApps = Get-MgApplication -All | Where-Object {
            $owners = Get-MgApplicationOwner -ApplicationId $_.Id -All
            $owners.Id -contains $currentUserId
        }

        return @($roleBasedApps + $ownedApps) | Sort-Object -Property Id -Unique
    }
}
