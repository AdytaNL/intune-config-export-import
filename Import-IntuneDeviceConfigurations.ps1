<#
.SYNOPSIS
    Imports device configuration policies from an export folder into a target tenant.

.DESCRIPTION
    Works together with Export-IntuneDeviceConfigurations.ps1.
    Per policy:
      1. Reads the clean .json
      2. Replaces all {{PLACEHOLDER}} tokens from the mapping file
      3. POSTs to the right Graph endpoint, based on the file name prefix
      4. Assigns the policy, resolving group names to object IDs in the target tenant

    Supported policy types (by file name prefix):
      DeviceConfig_*            -> deviceManagement/deviceConfigurations
      SettingsCatalog_*         -> deviceManagement/configurationPolicies (settings in the same request)
      AdminTemplate_*           -> deviceManagement/groupPolicyConfigurations + /definitionValues
      EndpointSecIntent_*       -> deviceManagement/intents + /updateSettings

    Existing policies are not checked: every run creates new policies.

.PARAMETER SourcePath
    Folder with the exported JSON files (output of Export-IntuneDeviceConfigurations.ps1).

.PARAMETER MappingFile
    Path to the mapping file with the tenant and group translations.
    Use New-IntuneImportMapping.ps1 to generate one from the export.

.PARAMETER TenantId
    Entra ID tenant ID of the target tenant.

.PARAMETER Filter
    Optional. One or more wildcard patterns on the file name.
    For example "SettingsCatalog_*" or "*Bitlocker*","*LAPS*".
    Default: all .json files (excluding .meta.json, _manifest.json and mapping*.json).

.PARAMETER Exclude
    Optional. One or more wildcard patterns for policies to skip.
    For example -Exclude "*Autopatch*" or -Exclude "*Autopatch*","*UpdatePolicy*".

.PARAMETER Interactive
    Shows a selection window (Out-GridView) with all policies found.
    Select the ones to import with Ctrl+Click, then OK. Windows only.

.PARAMETER WhatIf
    Dry run: shows what would be imported without creating anything.

.EXAMPLE
    # Import everything
    .\Import-IntuneDeviceConfigurations.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json"

.EXAMPLE
    # Pick interactively
    .\Import-IntuneDeviceConfigurations.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" -Interactive

.EXAMPLE
    # Settings Catalog only, skip Autopatch policies, dry run
    .\Import-IntuneDeviceConfigurations.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" -Filter "SettingsCatalog_*" -Exclude "*Autopatch*" -WhatIf

.EXAMPLE
    # Specific policies by name
    .\Import-IntuneDeviceConfigurations.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -SourcePath "C:\Export\Contoso" -MappingFile "C:\Export\Contoso\mapping-fabrikam.json" -Filter "*Bitlocker*","*LAPS*","*OneDrive*"

.NOTES
    Requires: Microsoft.Graph.Authentication module, PowerShell 7
    Scopes:   DeviceManagementConfiguration.ReadWrite.All, Group.Read.All
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]  [string]$SourcePath,
    [Parameter(Mandatory = $true)]  [string]$MappingFile,
    [Parameter(Mandatory = $true)]  [string]$TenantId,
    [Parameter(Mandatory = $false)] [string[]]$Filter  = @("*.json"),
    [Parameter(Mandatory = $false)] [string[]]$Exclude = @(),
    [Parameter(Mandatory = $false)] [switch]$Interactive
)

$ErrorActionPreference = "Stop"
$GRAPH_BASE = "https://graph.microsoft.com/beta"

#region ── Helpers ─────────────────────────────────────────────────────────────

function Repair-NullCollections {
    <#
    Graph does not accept null for non-nullable properties.
    Strategy: remove all null values from the body, recursively.
    Graph then uses its own server default (usually an empty list or 0).
    The type is NOT guessed: matching on a field name suffix also hits primitive properties.
    #>
    param ($Obj)

    if ($null -eq $Obj) { return $null }

    if ($Obj -is [System.Collections.IDictionary]) {
        $clean = [ordered]@{}
        foreach ($key in @($Obj.Keys)) {
            $val = $Obj[$key]
            if ($null -ne $val) {
                $repairedVal = Repair-NullCollections -Obj $val
                if ($null -ne $repairedVal) { $clean[$key] = $repairedVal }
            }
            # null values and empty lists are left out: Graph uses its server default
        }
        return $clean
    }

    if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Obj) {
            $repaired = Repair-NullCollections -Obj $item
            if ($null -ne $repaired) { $list.Add($repaired) }
        }
        if ($list.Count -eq 0) { return $null }
        # Unary comma: keep a one-element array an array
        return ,$list.ToArray()
    }

    return $Obj
}

function Invoke-GraphPost {
    param (
        [string]$Uri,
        [object]$Body
    )
    $cleaned = Repair-NullCollections -Obj $Body
    $json    = $cleaned | ConvertTo-Json -Depth 20 -Compress
    return Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $json `
        -ContentType "application/json" -ErrorAction Stop
}

function Invoke-GraphGetAll {
    param ([string]$Uri)
    $results  = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    do {
        $resp     = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
        if ($resp.Contains('value') -and $resp['value']) { $results.AddRange([object[]]$resp['value']) }
        $nextLink = if ($resp.Contains('@odata.nextLink')) { $resp['@odata.nextLink'] } else { $null }
    } while ($nextLink)
    return $results
}

# Group name -> object ID cache for the target tenant
$script:GroupCache = @{}

function Resolve-TargetGroupId {
    <# Looks up a group by name in the target tenant and returns its object ID #>
    param ([string]$GroupName)

    if ($script:GroupCache.Contains($GroupName)) { return $script:GroupCache[$GroupName] }

    try {
        # OData: double a single quote; then URL-encode for names with & # + and the like
        $encoded  = [Uri]::EscapeDataString($GroupName.Replace("'", "''"))
        $resp     = Invoke-MgGraphRequest -Method GET `
            -Uri "$GRAPH_BASE/groups?`$filter=displayName eq '$encoded'&`$select=id,displayName" `
            -ErrorAction Stop
        if ($resp['value'] -and $resp['value'].Count -gt 0) {
            $id = $resp['value'][0]['id']
            $script:GroupCache[$GroupName] = $id
            return $id
        }
    } catch { }

    Write-Warning "  [GROUP NOT FOUND] '$GroupName'"
    return $null
}

#endregion

#region ── Placeholder replacement ─────────────────────────────────────────────

function Invoke-ReplacePlaceholders {
    <#
    Replaces all {{TOKEN}} placeholders in a JSON string from the mapping.
    Returns the resulting JSON string.
    #>
    param (
        [string]$JsonString,
        [hashtable]$Mapping
    )

    foreach ($token in $Mapping.Keys) {
        $value = $Mapping[$token]
        if ($null -ne $value -and $value -ne '') {
            # Literal replace with a JSON-escaped value, so backslashes and quotes stay valid JSON
            $jsonValue  = ConvertTo-Json "$value"
            $JsonString = $JsonString.Replace("{{$token}}", $jsonValue.Substring(1, $jsonValue.Length - 2))
        }
    }

    # Report placeholders that are still open. Group tokens are skipped here:
    # assignments are resolved by group name in Set-PolicyAssignments.
    $remaining = [RegEx]::Matches($JsonString, '\{\{(?!(EXCL_)?GROUP_)[A-Z0-9_\-]+\}\}')
    foreach ($match in $remaining) {
        Write-Warning "  [UNREPLACED PLACEHOLDER] $($match.Value) - check the mapping file"
    }

    return $JsonString
}

#endregion

#region ── Mapping file ────────────────────────────────────────────────────────

function Read-MappingFile {
    param ([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Mapping file not found: $Path. Use New-IntuneImportMapping.ps1 to create one."
    }

    $raw     = Get-Content $Path -Raw -Encoding UTF8
    $parsed  = $raw | ConvertFrom-Json

    # Flat token -> value hashtable
    $mapping = @{}

    # SOURCE_TENANT_ID
    if ($parsed.SOURCE_TENANT_ID) {
        $mapping['SOURCE_TENANT_ID'] = $parsed.SOURCE_TENANT_ID
    }

    # Group tokens: groupMappings is an object { "source group name": "target group name" }.
    # The tokens in the JSON are GROUP_<NAME_IN_CAPS_WITH_UNDERSCORES> and EXCL_GROUP_<...>.
    # Here only token -> target group name is stored; the object ID is looked up
    # in the target tenant when the assignment is made.
    $script:PendingGroupMappings = @{}
    if ($parsed.groupMappings) {
        foreach ($prop in $parsed.groupMappings.PSObject.Properties) {
            $sourceName = $prop.Name
            $targetName = $prop.Value
            # Rebuild the token (same sanitising as the export)
            $safeSource = ($sourceName -replace '[^A-Za-z0-9_\-]', '_').ToUpper()
            $script:PendingGroupMappings["GROUP_${safeSource}"]      = $targetName
            $script:PendingGroupMappings["EXCL_GROUP_${safeSource}"] = $targetName
        }
    }

    # Optional extra token values
    if ($parsed.tokenOverrides) {
        foreach ($prop in $parsed.tokenOverrides.PSObject.Properties) {
            $mapping[$prop.Name] = $prop.Value
        }
    }

    return $mapping
}

#endregion

#region ── Assignments ─────────────────────────────────────────────────────────

function Set-PolicyAssignments {
    param (
        [string]$AssignmentsUri,
        [object[]]$CleanAssignments,
        [object[]]$MetaAssignments
    )

    $assignmentList = [System.Collections.Generic.List[object]]::new()

    :assignment for ($i = 0; $i -lt $CleanAssignments.Count; $i++) {
        $clean = $CleanAssignments[$i]
        $meta  = if ($i -lt $MetaAssignments.Count) { $MetaAssignments[$i] } else { $null }

        $targetType = $clean['target']['@odata.type']
        $target     = [ordered]@{ '@odata.type' = $targetType }

        switch -Wildcard ($targetType) {
            '*.groupAssignmentTarget' {
                # Group name from the meta file, then resolve the object ID in the target tenant
                $targetGroupName = $null
                if ($meta -and $meta.groupName) {
                    $sourceName = $meta.groupName
                    # Check groupMappings for a different name in the target tenant
                    $targetGroupName = if ($script:PendingGroupMappings.Contains("GROUP_$(($sourceName -replace '[^A-Za-z0-9_\-]','_').ToUpper())")) {
                        $script:PendingGroupMappings["GROUP_$(($sourceName -replace '[^A-Za-z0-9_\-]','_').ToUpper())"]
                    } else {
                        $sourceName  # Same name in the target tenant
                    }
                }
                if ($targetGroupName) {
                    $groupId = Resolve-TargetGroupId -GroupName $targetGroupName
                    if ($groupId) { $target['groupId'] = $groupId }
                    else          { continue assignment }
                }
            }
            '*.exclusionGroupAssignmentTarget' {
                $targetGroupName = $null
                if ($meta -and $meta.groupName) {
                    $sourceName = $meta.groupName
                    $targetGroupName = if ($script:PendingGroupMappings.Contains("EXCL_GROUP_$(($sourceName -replace '[^A-Za-z0-9_\-]','_').ToUpper())")) {
                        $script:PendingGroupMappings["EXCL_GROUP_$(($sourceName -replace '[^A-Za-z0-9_\-]','_').ToUpper())"]
                    } else {
                        $sourceName
                    }
                }
                if ($targetGroupName) {
                    $groupId = Resolve-TargetGroupId -GroupName $targetGroupName
                    if ($groupId) { $target['groupId'] = $groupId }
                    else {
                        # Without the exclusion the policy would reach more devices than in the source:
                        # assign nothing for this policy (fail closed)
                        Write-Warning "    [EXCLUSION GROUP NOT FOUND] '$targetGroupName' - no assignments made for this policy"
                        return
                    }
                }
            }
            # allDevices / allLicensedUsers: the target is already complete
        }

        $entry = [ordered]@{
            target = $target
        }
        if ($clean['intent']) { $entry['intent'] = $clean['intent'] }
        $assignmentList.Add($entry)
    }

    if ($assignmentList.Count -eq 0) { return }

    # Build the body explicitly so the array survives:
    # ConvertTo-Json unwraps a single item, Graph always expects a list
    $assignArray = [object[]]@($assignmentList)
    $bodyObj     = [PSCustomObject]@{ assignments = $assignArray }
    $bodyJson    = $bodyObj | ConvertTo-Json -Depth 20 -Compress
    # Force array notation for a single item
    if ($assignArray.Count -eq 1) {
        $singleItem = ($assignArray[0] | ConvertTo-Json -Depth 20 -Compress)
        $bodyJson   = '{"assignments":[' + $singleItem + ']}'
    }
    try {
        Invoke-MgGraphRequest -Method POST -Uri $AssignmentsUri -Body $bodyJson `
            -ContentType "application/json" -ErrorAction Stop | Out-Null
        Write-Host "    Assignments: $($assignArray.Count) assigned" -ForegroundColor DarkGreen
    } catch {
        Write-Warning "    [ASSIGNMENT ERROR] Policy created but assignment failed: $_"
    }
}

#endregion

#region ── Import handlers per type ────────────────────────────────────────────

function Import-DeviceConfig {
    param ([object]$Policy, [object[]]$CleanAsgn, [object[]]$MetaAsgn, [bool]$DryRun)

    # Remove fields that are not allowed in the POST body
    $body = [ordered]@{}
    $skipFields = @('_assignments', 'id', 'createdDateTime', 'lastModifiedDateTime', 'version')
    foreach ($key in @($Policy.Keys)) {
        if ($key -notin $skipFields) { $body[$key] = $Policy[$key] }
    }

    if ($DryRun) { Write-Host "    [WhatIf] POST deviceManagement/deviceConfigurations" -ForegroundColor DarkCyan; return }

    $created = Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/deviceConfigurations" -Body $body
    Write-Host "    Created: $($created['id'])" -ForegroundColor DarkGreen

    if ($CleanAsgn.Count -gt 0) {
        Set-PolicyAssignments `
            -AssignmentsUri "$GRAPH_BASE/deviceManagement/deviceConfigurations/$($created['id'])/assign" `
            -CleanAssignments $CleanAsgn -MetaAssignments $MetaAsgn
    }
    return $true
}

function Import-SettingsCatalog {
    param ([object]$Policy, [object[]]$CleanAsgn, [object[]]$MetaAsgn, [bool]$DryRun)

    # Settings are stored separately in the JSON, but go inline in the POST
    $settings = $Policy['settings']

    $body = [ordered]@{}
    $skipFields = @('_assignments', 'id', 'createdDateTime', 'lastModifiedDateTime',
                    'version', 'settingCount', 'isAssigned', 'settings')
    foreach ($key in @($Policy.Keys)) {
        if ($key -notin $skipFields) { $body[$key] = $Policy[$key] }
    }

    # Settings Catalog: settings are part of the create body
    if ($settings) { $body['settings'] = $settings }

    if ($DryRun) { Write-Host "    [WhatIf] POST deviceManagement/configurationPolicies" -ForegroundColor DarkCyan; return }

    $created = Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/configurationPolicies" -Body $body
    Write-Host "    Created: $($created['id'])" -ForegroundColor DarkGreen

    if ($CleanAsgn.Count -gt 0) {
        Set-PolicyAssignments `
            -AssignmentsUri "$GRAPH_BASE/deviceManagement/configurationPolicies/$($created['id'])/assign" `
            -CleanAssignments $CleanAsgn -MetaAssignments $MetaAsgn
    }
    return $true
}

function Import-AdminTemplate {
    param ([object]$Policy, [object[]]$CleanAsgn, [object[]]$MetaAsgn, [bool]$DryRun)

    $definitionValues = $Policy['definitionValues']

    $body = [ordered]@{}
    $skipFields = @('_assignments', 'id', 'createdDateTime', 'lastModifiedDateTime',
                    'version', 'definitionValues', 'roleScopeTagIds')
    foreach ($key in @($Policy.Keys)) {
        if ($key -notin $skipFields) { $body[$key] = $Policy[$key] }
    }

    if ($DryRun) { Write-Host "    [WhatIf] POST deviceManagement/groupPolicyConfigurations" -ForegroundColor DarkCyan; return }

    $created = Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations" -Body $body
    $newId   = $created['id']
    Write-Host "    Created: $newId" -ForegroundColor DarkGreen

    # Create the definition values one by one
    if ($definitionValues -and $definitionValues.Count -gt 0) {
        $defOk  = 0
        $defErr = 0
        foreach ($dv in $definitionValues) {
            # Strip the expanded and read-only fields; reference the definition and each
            # presentation with @odata.bind (navigation properties, not plain ID fields)
            $dvBody = [ordered]@{}
            $dvSkip = @('id', 'createdDateTime', 'lastModifiedDateTime', 'definition', 'definitionId', 'presentationValues')
            $defId  = $null
            if ($dv -is [System.Collections.IDictionary] -and $dv.Contains('definition') -and $dv['definition']) {
                $defId = $dv['definition']['id']
                $dvBody['definition@odata.bind'] = "$GRAPH_BASE/deviceManagement/groupPolicyDefinitions('$defId')"
            }
            foreach ($dvKey in @($dv.Keys)) {
                if ($dvKey -notin $dvSkip) { $dvBody[$dvKey] = $dv[$dvKey] }
            }
            $pvList = [System.Collections.Generic.List[object]]::new()
            foreach ($pv in @($dv['presentationValues'])) {
                if ($null -eq $pv) { continue }
                $pvBody = [ordered]@{}
                foreach ($pvKey in @($pv.Keys)) {
                    if ($pvKey -notin @('id', 'createdDateTime', 'lastModifiedDateTime', 'presentation')) { $pvBody[$pvKey] = $pv[$pvKey] }
                }
                if ($pv.Contains('presentation') -and $pv['presentation']) {
                    $pvBody['presentation@odata.bind'] = "$GRAPH_BASE/deviceManagement/groupPolicyDefinitions('$defId')/presentations('$($pv['presentation']['id'])')"
                }
                $pvList.Add($pvBody)
            }
            if ($pvList.Count -gt 0) { $dvBody['presentationValues'] = $pvList.ToArray() }
            try {
                Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$newId/definitionValues" -Body $dvBody | Out-Null
                $defOk++
            } catch {
                Write-Warning "    [DEFINITION ERROR] $defId : $_"
                $defErr++
            }
        }
        Write-Host "    Definitions: $defOk ok, $defErr failed" -ForegroundColor DarkGreen
    }

    if ($CleanAsgn.Count -gt 0) {
        Set-PolicyAssignments `
            -AssignmentsUri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$newId/assign" `
            -CleanAssignments $CleanAsgn -MetaAssignments $MetaAsgn
    }
    return $true
}

function Import-EndpointSecIntent {
    param ([object]$Policy, [object[]]$CleanAsgn, [object[]]$MetaAsgn, [bool]$DryRun)

    $settings = $Policy['settings']

    $body = [ordered]@{}
    $skipFields = @('_assignments', 'id', 'createdDateTime', 'lastModifiedDateTime',
                    'version', 'isAssigned', 'settings', '_templateDisplayName', '_templateSubtype')
    foreach ($key in @($Policy.Keys)) {
        if ($key -notin $skipFields) { $body[$key] = $Policy[$key] }
    }

    if ($DryRun) { Write-Host "    [WhatIf] POST deviceManagement/intents" -ForegroundColor DarkCyan; return }

    $created = Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/intents" -Body $body
    $newId   = $created['id']
    Write-Host "    Created: $newId" -ForegroundColor DarkGreen

    # Update the settings in one call
    if ($settings -and $settings.Count -gt 0) {
        $settingsBody = @{ settings = $settings }
        try {
            Invoke-GraphPost -Uri "$GRAPH_BASE/deviceManagement/intents/$newId/updateSettings" -Body $settingsBody | Out-Null
            Write-Host "    Settings: $($settings.Count) settings updated" -ForegroundColor DarkGreen
        } catch {
            Write-Warning "    [SETTINGS ERROR] $_"
        }
    }

    if ($CleanAsgn.Count -gt 0) {
        Set-PolicyAssignments `
            -AssignmentsUri "$GRAPH_BASE/deviceManagement/intents/$newId/assign" `
            -CleanAssignments $CleanAsgn -MetaAssignments $MetaAsgn
    }
    return $true
}

#endregion

#region ── Initialisation ──────────────────────────────────────────────────────

if (-not (Test-Path $SourcePath)) {
    throw "SourcePath not found: $SourcePath"
}

Write-Host "`nReading mapping file..." -ForegroundColor Cyan
$mapping = Read-MappingFile -Path $MappingFile
Write-Host "  Tokens loaded: $($mapping.Count + $script:PendingGroupMappings.Count)" -ForegroundColor Green

Write-Host "Connecting to Microsoft Graph (tenant: $TenantId)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId `
    -Scopes "DeviceManagementConfiguration.ReadWrite.All", "Group.Read.All" `
    -NoWelcome

# ── Select files ──────────────────────────────────────────────────────────────
# 1. All clean JSON files (no .meta.json, no _manifest.json, no mapping files)
$allFiles = Get-ChildItem -Path $SourcePath -Filter "*.json" |
    Where-Object { $_.Name -notmatch '\.meta\.json$' -and $_.Name -ne '_manifest.json' -and $_.Name -notlike 'mapping*.json' } |
    Sort-Object Name

# 2. Apply Filter (several patterns = OR)
$files = $allFiles | Where-Object {
    $name = $_.Name
    $match = $false
    foreach ($pattern in $Filter) {
        if ($name -like $pattern) { $match = $true; break }
    }
    $match
}

# 3. Apply Exclude
if ($Exclude.Count -gt 0) {
    $files = $files | Where-Object {
        $name = $_.Name
        $excluded = $false
        foreach ($pattern in $Exclude) {
            if ($name -like $pattern) { $excluded = $true; break }
        }
        -not $excluded
    }
}

# 4. Interactive selection with Out-GridView
if ($Interactive) {
    $pickList = $files | ForEach-Object {
        $metaPath  = Join-Path $SourcePath ($_.Name -replace '\.json$', '.meta.json')
        $policyName = $_.Name -replace '\.json$', ''
        $policyType = ($_.Name -split '_')[0]
        $assignments = ''
        if (Test-Path $metaPath) {
            $m = Get-Content $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $policyName  = $m.policyName
            $assignments = ($m.assignments | ForEach-Object {
                if ($_.groupName) { $_.groupName } elseif ($_.scope) { $_.scope }
            }) -join ', '
        }
        [PSCustomObject]@{
            Type        = $policyType
            Name        = $policyName
            Assignments = $assignments
            File        = $_.Name
            _file       = $_
        }
    }

    $selected = $pickList | Out-GridView -Title "Select the policies to import (Ctrl+Click for several)" -PassThru

    if (-not $selected -or $selected.Count -eq 0) {
        Write-Host "Nothing selected - import cancelled." -ForegroundColor Yellow
        exit 0
    }

    $files = $selected | ForEach-Object { $_._file }
    Write-Host "`n$($files.Count) policies selected in the window" -ForegroundColor Cyan
}

if ($files.Count -eq 0) {
    Write-Warning "No files found in $SourcePath with the given filters"
    exit 0
}

Write-Host "`n$($files.Count) policies selected for import" -ForegroundColor Cyan
if ($WhatIfPreference) { Write-Host "  [DRY RUN - nothing will be created]`n" -ForegroundColor DarkCyan }

$counters = @{ Success = 0; Skipped = 0; Errors = 0 }

#endregion

#region ── Main loop ───────────────────────────────────────────────────────────

foreach ($file in $files) {
    $baseName  = $file.Name -replace '\.json$', ''
    $metaPath  = Join-Path $SourcePath "${baseName}.meta.json"

    Write-Host "`n[$($counters.Success + $counters.Errors + $counters.Skipped + 1)/$($files.Count)] $($file.Name)" -ForegroundColor Yellow

    # Load the meta file for the assignments
    $meta          = $null
    $metaAsgn      = @()
    if (Test-Path $metaPath) {
        $meta     = Get-Content $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $metaAsgn = @($meta.assignments)
    } else {
        Write-Warning "  .meta.json not found - assignments are skipped"
    }

    # Load the clean JSON and replace the placeholders
    try {
        $rawJson     = Get-Content $file.FullName -Raw -Encoding UTF8
        $replacedJson = Invoke-ReplacePlaceholders -JsonString $rawJson -Mapping $mapping
        $policy      = $replacedJson | ConvertFrom-Json -AsHashtable
    } catch {
        Write-Warning "  [ERROR] Loading JSON failed: $_"
        $counters.Errors++
        continue
    }

    # Assignments from the clean JSON
    $cleanAsgn = @()
    if ($policy.Contains('_assignments') -and $policy['_assignments']) {
        $cleanAsgn = @($policy['_assignments'])
    }

    # Policy type from the file name prefix
    $prefix = ($file.Name -split '_')[0]

    try {
        $result = switch -Wildcard ($file.Name) {
            'DeviceConfig_*' {
                Import-DeviceConfig -Policy $policy -CleanAsgn $cleanAsgn -MetaAsgn $metaAsgn -DryRun:$WhatIfPreference
            }
            'SettingsCatalog_*' {
                Import-SettingsCatalog -Policy $policy -CleanAsgn $cleanAsgn -MetaAsgn $metaAsgn -DryRun:$WhatIfPreference
            }
            'AdminTemplate_*' {
                Import-AdminTemplate -Policy $policy -CleanAsgn $cleanAsgn -MetaAsgn $metaAsgn -DryRun:$WhatIfPreference
            }
            'EndpointSecIntent_*' {
                Import-EndpointSecIntent -Policy $policy -CleanAsgn $cleanAsgn -MetaAsgn $metaAsgn -DryRun:$WhatIfPreference
            }
            default {
                Write-Warning "  [UNKNOWN TYPE] Prefix '$prefix' not recognised - skipped"
                $counters.Skipped++
                $null
            }
        }
        # Counts as success when the import function returned $true (policy created).
        # Assignment errors are caught as warnings in Set-PolicyAssignments.
        if ($result -eq $true -or $WhatIfPreference) { $counters.Success++ }
    } catch {
        Write-Warning "  [ERROR] Import failed: $_"
        $counters.Errors++
    }
}

#endregion

#region ── Summary ─────────────────────────────────────────────────────────────

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Import $(if ($WhatIfPreference) { '(DRY RUN) ' })finished." -ForegroundColor Cyan
Write-Host "  Succeeded   : $($counters.Success)"  -ForegroundColor Green
Write-Host "  Skipped     : $($counters.Skipped)"  -ForegroundColor Yellow
Write-Host "  Errors      : $($counters.Errors)"   -ForegroundColor $(if ($counters.Errors -gt 0) { 'Red' } else { 'Green' })
Write-Host "========================================`n" -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null

#endregion
