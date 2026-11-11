# Setup and walkthrough

This guide takes you from an empty folder to imported, assigned policies in a target
tenant, with a check after every step. Do the first run against a **test tenant**.

## 1. Prepare your workstation

```powershell
# PowerShell 7
$PSVersionTable.PSVersion          # 7.x

Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Get-Module Microsoft.Graph.Authentication -ListAvailable | Select-Object Name, Version
```

**Check:** PowerShell reports version 7 or later and the module is listed.

## 2. Accounts and permissions

The scripts sign in interactively (delegated permissions) with `Connect-MgGraph`. What the
script can do is the overlap of the Graph scopes and your own role in the tenant.

| Script | Graph scopes (delegated) | Intune role, at least |
|---|---|---|
| Export (source tenant) | `DeviceManagementConfiguration.Read.All`, `Group.Read.All` | Read Only Operator |
| Import (target tenant) | `DeviceManagementConfiguration.ReadWrite.All`, `Group.Read.All` | Policy and Profile Manager; for Endpoint Security policies also the matching permissions, for example Endpoint Security Manager |

Intune Administrator covers both. These scopes need admin consent for the Microsoft Graph
PowerShell app in each tenant. If your account cannot grant that, ask a Global
Administrator or Privileged Role Administrator to consent once.

**Check:** connect once by hand and look at the scopes:

```powershell
Connect-MgGraph -TenantId "<tenant ID>" -Scopes "DeviceManagementConfiguration.Read.All","Group.Read.All"
(Get-MgContext).Scopes
Disconnect-MgGraph
```

## 3. Export the source tenant

```powershell
.\Export-IntuneDeviceConfigurations.ps1 -TenantId "<source tenant ID>" -OutputPath "C:\Export\Contoso"
```

The script walks the four endpoints in order and writes two files per policy plus
`_manifest.json`. A policy that fails is reported and counted; the rest continues.

**Check:**

- The summary shows `Errors : 0`, or you know why a policy failed.
- There are no `[Graph ERROR]` warnings. Such a warning means a list (policies, settings
  or assignments) could not be read completely; the policy is then saved without that
  part. Run the export again.
- `_manifest.json` lists the policies you expect, with their assignments.
- Open one clean `.json` and search for the source tenant ID: it should only appear as
  `{{SOURCE_TENANT_ID}}`. The original value is in the matching `.meta.json`.

```powershell
Select-String -Path "C:\Export\Contoso\*.json" -Exclude "*.meta.json","*_manifest.json" -Pattern "<source tenant ID>"
```

No output means the tenant ID was replaced everywhere in the clean files.

Keep the export folder somewhere private: the meta files and the manifest hold the source
tenant ID and the group IDs and names.

## 4. Create and fill in the mapping file

```powershell
.\New-IntuneImportMapping.ps1 -SourcePath "C:\Export\Contoso" -OutputFile "C:\Export\Contoso\mapping-fabrikam.json"
```

Open the file and fill in:

1. `SOURCE_TENANT_ID`: the tenant ID of the **target** tenant.
2. `groupMappings`: for every source group, the display name of the group in the target
   tenant. The value is pre-filled with the same name. Create the target groups first if
   they do not exist.
3. `tokenOverrides` (only if you added your own tokens to the clean JSON): a value for
   every token. Example: [examples/mapping.example.json](../examples/mapping.example.json).

**Check:** every target group exists, and exactly once:

```powershell
Connect-MgGraph -TenantId "<target tenant ID>" -Scopes "Group.Read.All"
$map = Get-Content "C:\Export\Contoso\mapping-fabrikam.json" -Raw | ConvertFrom-Json
foreach ($name in $map.groupMappings.PSObject.Properties.Value) {
    $q = [Uri]::EscapeDataString($name.Replace("'", "''"))
    $found = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$q'&`$select=id"
    "{0,-50} {1}" -f $name, $found.value.Count
}
Disconnect-MgGraph
```

Every line should end in `1`. A `0` or a `2` and more means the import reports the group
and does not use it.

## 5. Dry run

```powershell
.\Import-IntuneDeviceConfigurations.ps1 -TenantId "<target tenant ID>" `
    -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" -WhatIf
```

**Check:**

- No `[UNREPLACED PLACEHOLDER]` warnings. If there are, add the missing value to the
  mapping file.
- The list of policies is what you want to create. Narrow it with `-Filter`, `-Exclude`
  or `-Interactive`.
- The target tenant does not already have these policies: the import does not check for
  existing policies and creates new ones on every run.

## 6. Import

Start small, for example with one kind or a handful of policies:

```powershell
.\Import-IntuneDeviceConfigurations.ps1 -TenantId "<target tenant ID>" `
    -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" `
    -Filter "SettingsCatalog_*"
```

Or pick in a window (Windows only):

```powershell
.\Import-IntuneDeviceConfigurations.ps1 -TenantId "<target tenant ID>" `
    -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" `
    -Interactive
```

Policies are assigned right after they are created. If you want to review before devices
receive anything, point the groups in `groupMappings` to a pilot group first.

**Check:**

- The summary shows the expected number of successes and `Errors : 0`.
- For Administrative Templates, every policy reports `Definitions: n ok, 0 failed`.
- No `[NOT ASSIGNED]` warnings. Such a policy was only partly created; fix or delete it,
  then assign it by hand or import it again.
- No `[ASSIGNMENT ERROR]`, `[GROUP NOT FOUND]` or `[EXCLUSION GROUP NOT FOUND]` warnings,
  or you know which assignment is missing. A missing exclusion group means the policy got
  no assignments at all.

## 7. After the import

In the Intune admin center, for each imported policy:

- [ ] The settings match the source (compare with the source tenant or the clean JSON).
- [ ] The assignments and exclusions are on the intended groups.
- [ ] Assignment filters are added again where the source used them (the scripts do not
      carry filters over).
- [ ] Certificate, Wi-Fi and VPN profiles point to the right trusted root, SCEP/PKCS
      connector and certificate in the target tenant. The scripts do not translate these
      references.
- [ ] Profiles with values that Intune stores encrypted (custom OMA-URI secrets,
      pre-shared keys) contain the right value.
- [ ] URLs, domain names and server names of the source organisation are replaced.
- [ ] Scope tags are set if the target tenant uses them (the export strips them).
- [ ] Devices in a pilot group report success before the policy goes wider.

## Running it again

The import creates new policies on every run. To add or redo a few policies, use
`-Filter`, `-Exclude` or `-Interactive`, and delete a failed attempt in the admin center
before you import it again.

## Undo

The scripts make no changes outside the policies they create. To undo an import, delete
the imported policies in the Intune admin center (Devices > Manage devices >
Configuration, and Endpoint security for Endpoint Security policies). Remove the admin
consent for the Graph scopes if you no longer need it.
