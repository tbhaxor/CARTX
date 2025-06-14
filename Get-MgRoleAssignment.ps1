Remove-Item Function:/Get-MgRoleAssignment -ErrorAction SilentlyContinue

function Get-MgRoleAssignment {
    <#
      .SYNOPSIS
          Retrieves directory role assignments from Microsoft Graph.
  
      .DESCRIPTION
          This function retrieves role assignments from Microsoft Graph Role Management API.
          If a PrincipalId is specified, it filters assignments for that principal only.
          It expands related RoleDefinition and DirectoryScope properties for richer output.
  
      .PARAMETER PrincipalId
          (Optional) The object ID of the principal (user, group, or service principal) whose role assignments should be queried.
  
      .EXAMPLE
          Get-MgRoleAssignment -PrincipalId '12345678-90ab-cdef-1234-567890abcdef'
  
          Returns role assignments only for the specified principal.
  
      .NOTES
          Requires Microsoft Graph PowerShell SDK.
          Permissions: RoleManagement.Read.Directory or higher.
  
      .LINK
          https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.governance/get-mgrolemanagementdirectoryroleassignment
    #>

    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$PrincipalId
    )

    $filter = $null
    if (![string]::IsNullOrEmpty($PrincipalId)) {
        $filter = "principalId eq '$PrincipalId'"
    }

    Get-MgRoleManagementDirectoryRoleAssignment -Filter $filter -Expand roleDefinition | ForEach-Object {
        $expandedDirScope = (Get-MgRoleManagementDirectoryRoleAssignment -Filter "id eq '$($_.Id)'" -Expand directoryScope).DirectoryScope
        $expandedPrincipal = (Get-MgRoleManagementDirectoryRoleAssignment -Filter "id eq '$($_.Id)'" -Expand principal).Principal

        [PSCustomObject]@{
            Id                        = $_.Id
            RoleDefinition            = $_.RoleDefinition.DisplayName
            IsRoleDefinitionBuiltIn   = $_.RoleDefinition.IsBuiltIn
            DirectoryScopeId          = $expandedDirScope.Id
            DirectoryScopeType        = $expandedDirScope.AdditionalProperties['@odata.type']
            DirectoryScopeDisplayName = $expandedDirScope.AdditionalProperties['displayName']
            PrincipalId               = $expandedPrincipal.Id
            PrincipalType             = $expandedPrincipal.AdditionalProperties['@odata.type']
            PrincipalDisplayName      = $expandedPrincipal.AdditionalProperties['displayName']
        }
    }
}
