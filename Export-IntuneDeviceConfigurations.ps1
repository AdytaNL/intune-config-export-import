<#
.SYNOPSIS
    Exports all Intune device configuration policies to JSON files with placeholders.

.DESCRIPTION
    For every policy two files are written:
      <Type>_<PolicyName>_<PolicyId>.json       <- Clean template with placeholders for tenant-specific values
      <Type>_<PolicyName>_<PolicyId>.meta.json  <- Source values, assignment group names and the placeholder mapping

    Stripped fields (always removed from the clean JSON):
      id, createdDateTime, lastModifiedDateTime, version, roleScopeTagIds,
      supportsScopeTags, deviceEnrollmentConfigurationType

    Placeholder tokens written by the export:
      {{SOURCE_TENANT_ID}}        The source tenant ID, also when it is embedded in a longer value
      {{GROUP_<NAME>}}            Entra group object IDs in included assignments
      {{EXCL_GROUP_<NAME>}}       Entra group object IDs in excluded assignments
                                  (both resolved by group name on import)

    Other tenant-specific references (for example certificate profiles that point to a
    trusted root or a SCEP connector) are not tokenised automatically. Put your own
    {{TOKEN}} in the clean JSON and give it a value under tokenOverrides in the mapping file.

    Supported endpoints:
      deviceManagement/deviceConfigurations       (classic profiles)
      deviceManagement/configurationPolicies      (Settings Catalog, LAPS, newer Endpoint Security)
      deviceManagement/groupPolicyConfigurations  (Administrative Templates / ADMX)
      deviceManagement/intents                    (legacy Endpoint Security intents)

.PARAMETER TenantId
    Entra ID tenant ID of the source tenant.

.PARAMETER OutputPath
    Folder for the JSON files. Created if it does not exist.

.EXAMPLE
    .\Export-IntuneDeviceConfigurations.ps1 -TenantId "00000000-0000-0000-0000-000000000000" -OutputPath "C:\Export\Contoso"

.NOTES
    Requires: Microsoft.Graph.Authentication module, PowerShell 7
    Scopes:   DeviceManagementConfiguration.Read.All, Group.Read.All (to resolve group names)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

#region ── Constants ───────────────────────────────────────────────────────────

$GRAPH_BASE   = "https://graph.microsoft.com/beta"

# Fields that are always stripped from the clean JSON
$STRIP_FIELDS = @(
    'id', 'createdDateTime', 'lastModifiedDateTime',
    'version', 'roleScopeTagIds', 'supportsScopeTags',
    'deviceEnrollmentConfigurationType'
)

# Known setting names that can contain a tenant ID (reference list)
$TENANT_ID_SETTING_NAMES = @(
    'tenantId',
    'silentAccountConfig',       # OneDrive KFM / silent sign-in
    'oneDriveKnownFolderMove',
    'allowTenantList',
    'blockedTenantList'
)

# GUID pattern
$GUID_PATTERN = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

#endregion

#region ── Helpers ─────────────────────────────────────────────────────────────

function Invoke-GraphGetAll {
    param ([string]$Uri)
    $results  = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    do {
        try   { $resp = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop }
        catch { Write-Warning "  [Graph ERROR] GET $nextLink`n  $_"; break }
        if ($resp.Contains('value') -and $resp['value']) { $results.AddRange([object[]]$resp['value']) }
        $nextLink = if ($resp.Contains('@odata.nextLink')) { $resp['@odata.nextLink'] } else { $null }
    } while ($nextLink)
    # Unary comma: return the array as one object, so a single result stays a list
    return ,$results.ToArray()
}

function Sanitize-FileName {
    param ([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re      = "[{0}]" -f [RegEx]::Escape($invalid)
    return ($Name -replace $re, '_').Trim()
}

# Cache group names to limit Graph calls
$script:GroupCache = @{}

function Resolve-GroupName {
    param ([string]$GroupId)
    if ($script:GroupCache.Contains($GroupId)) { return $script:GroupCache[$GroupId] }
    try {
        $grp = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/groups/$GroupId`?`$select=displayName,groupTypes" -ErrorAction Stop
        $name = $grp['displayName']
    } catch {
        $name = "UNKNOWN_GROUP"
    }
    $script:GroupCache[$GroupId] = $name
    return $name
}

#endregion

#region ── Placeholder engine ──────────────────────────────────────────────────

function New-PlaceholderContext {
    <# Returns a new context object that records which replacements were made #>
    return [PSCustomObject]@{
        Mappings    = [System.Collections.Generic.Dictionary[string,string]]::new()  # token -> source value
        GroupTokens = [System.Collections.Generic.Dictionary[string,string]]::new()  # groupId -> token
    }
}

function Register-Placeholder {
    <# Registers a placeholder and returns the token #>
    param (
        [PSCustomObject]$Ctx,
        [string]$Token,
        [string]$OriginalValue
    )
    if (-not $Ctx.Mappings.ContainsKey($Token)) {
        $Ctx.Mappings[$Token] = $OriginalValue
    }
    return "{{$Token}}"
}

function ConvertTo-SafeGroupToken {
    <#
    Turns a group object ID into a readable token.
    The same group always gets the same token within one policy export.
    #>
    param (
        [PSCustomObject]$Ctx,
        [string]$GroupId,
        [string]$GroupName,
        [string]$GroupType   # "GROUP" | "EXCL_GROUP"
    )

    if ($Ctx.GroupTokens.ContainsKey($GroupId)) {
        return "{{$($Ctx.GroupTokens[$GroupId])}}"
    }

    # Sanitise the name for use in a token
    $safeName = ($GroupName -replace '[^A-Za-z0-9_\-]', '_').ToUpper()
    $token    = if ($GroupType -eq 'GROUP') { "GROUP_${safeName}" } else { "${GroupType}_${safeName}" }
    $Ctx.GroupTokens[$GroupId] = $token
    $Ctx.Mappings[$token]      = $GroupId
    return "{{$token}}"
}

function Invoke-SanitizeObject {
    <#
    Walks an object (PSCustomObject, hashtable, array) recursively and:
    - replaces the source tenant ID with {{SOURCE_TENANT_ID}}, also inside longer strings
    - applies the Settings Catalog check for known OneDrive tenant ID settings
    Returns the sanitised object and fills $Ctx.
    #>
    param (
        $Obj,
        [string]$SourceTenantId,
        [PSCustomObject]$Ctx
    )

    if ($null -eq $Obj) { return $null }

    # Array (but not strings, hashtables or ordered dictionaries)
    if ($Obj -is [System.Collections.IEnumerable] -and
        $Obj -isnot [string] -and
        $Obj -isnot [System.Collections.IDictionary]) {
        $newList = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Obj) {
            $newList.Add((Invoke-SanitizeObject -Obj $item -SourceTenantId $SourceTenantId -Ctx $Ctx))
        }
        # Unary comma: keep a one-element array an array
        return ,$newList.ToArray()
    }

    # Hashtable / OrderedDictionary
    if ($Obj -is [System.Collections.IDictionary]) {
        $newObj = [ordered]@{}
        foreach ($key in @($Obj.Keys)) {
            $val = $Obj[$key]
            if ($key -in $STRIP_FIELDS) { $newObj[$key] = $val; continue }
            $newObj[$key] = Invoke-SanitizeObject -Obj $val -SourceTenantId $SourceTenantId -Ctx $Ctx
        }

        # Detect the Settings Catalog setting structure
        if ($newObj.Contains('settingDefinitionId') -and $newObj.Contains('settingInstance')) {
            $newObj = Invoke-SanitizeSettingsCatalogEntry -Entry $newObj -SourceTenantId $SourceTenantId -Ctx $Ctx
        }

        return $newObj
    }

    if ($Obj -is [PSCustomObject]) {
        $newObj = [ordered]@{}
        foreach ($prop in $Obj.PSObject.Properties) {
            $key = $prop.Name
            $val = $prop.Value
            if ($key -in $STRIP_FIELDS) { $newObj[$key] = $val; continue }
            $newObj[$key] = Invoke-SanitizeObject -Obj $val -SourceTenantId $SourceTenantId -Ctx $Ctx
        }
        return $newObj
    }

    # String values
    if ($Obj -is [string]) {
        return Invoke-SanitizeString -Val $Obj -SourceTenantId $SourceTenantId -Ctx $Ctx
    }

    # Primitive (int, bool, etc.): returned unchanged
    return $Obj
}

function Invoke-SanitizeString {
    param ([string]$Val, [string]$SourceTenantId, [PSCustomObject]$Ctx)

    if ([string]::IsNullOrEmpty($Val)) { return $Val }

    # 1. The value is exactly the tenant ID
    if ($Val -eq $SourceTenantId) {
        return Register-Placeholder -Ctx $Ctx -Token "SOURCE_TENANT_ID" -OriginalValue $SourceTenantId
    }

    # 2. Tenant ID embedded in a longer string (e.g. an OMA-URI value or a JSON/XML blob)
    if ($Val -match $GUID_PATTERN -and $Val -like "*$SourceTenantId*") {
        $replaced = $Val -replace [RegEx]::Escape($SourceTenantId), "{{SOURCE_TENANT_ID}}"
        $null     = Register-Placeholder -Ctx $Ctx -Token "SOURCE_TENANT_ID" -OriginalValue $SourceTenantId
        return $replaced
    }

    return $Val
}

function Invoke-SanitizeSettingsCatalogEntry {
    <#
    Extra check for Settings Catalog entries with known setting definitions that hold a tenant ID.
    Works on a single setting object.
    #>
    param ($Entry, [string]$SourceTenantId, [PSCustomObject]$Ctx)

    $defId = $Entry['settingDefinitionId']
    if (-not $defId) { return $Entry }

    # OneDrive tenant ID settings, recognised by settingDefinitionId
    $knownTenantIdDefs = @(
        'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_tenantid',
        'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig',
        'device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard',
        'user_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_tenantid'
    )

    foreach ($knownDef in $knownTenantIdDefs) {
        if ($defId -like "*$knownDef*") {
            # The value is in settingInstance -> simpleSettingValue -> value
            $si = $Entry['settingInstance']
            if ($si -and $si.simpleSettingValue -and $si.simpleSettingValue.value) {
                $orig = $si.simpleSettingValue.value
                if ($orig -match "^$GUID_PATTERN$") {
                    # A GUID in a tenant ID setting: replace it
                    $si.simpleSettingValue.value = Register-Placeholder -Ctx $Ctx -Token "SOURCE_TENANT_ID" -OriginalValue $orig
                }
            }
        }
    }

    return $Entry
}

#endregion

#region ── Assignments ─────────────────────────────────────────────────────────

function ConvertTo-CleanAssignments {
    <#
    Processes an array of assignments:
    - returns a clean array with tokens instead of group IDs
    - fills $Ctx with the mapping token -> original group ID
    - also returns a readable overview for the meta JSON
    #>
    param (
        [object[]]$Assignments,
        [PSCustomObject]$Ctx
    )

    $cleanAssignments = [System.Collections.Generic.List[object]]::new()
    $metaAssignments  = [System.Collections.Generic.List[object]]::new()

    foreach ($asgn in $Assignments) {
        $target     = $asgn['target']
        $targetType = $target['@odata.type']
        $groupId    = $target['groupId']

        $metaEntry = [ordered]@{
            intent     = $asgn.intent
            targetType = $targetType
        }

        $cleanTarget = [ordered]@{
            '@odata.type' = $targetType
        }

        switch -Wildcard ($targetType) {
            '*.groupAssignmentTarget' {
                $groupName  = Resolve-GroupName -GroupId $groupId
                $groupToken = ConvertTo-SafeGroupToken -Ctx $Ctx -GroupId $groupId -GroupName $groupName -GroupType "GROUP"
                $cleanTarget['groupId'] = $groupToken
                $metaEntry['groupId']   = $groupId
                $metaEntry['groupName'] = $groupName
            }
            '*.exclusionGroupAssignmentTarget' {
                $groupName  = Resolve-GroupName -GroupId $groupId
                $groupToken = ConvertTo-SafeGroupToken -Ctx $Ctx -GroupId $groupId -GroupName $groupName -GroupType "EXCL_GROUP"
                $cleanTarget['groupId'] = $groupToken
                $metaEntry['groupId']   = $groupId
                $metaEntry['groupName'] = $groupName
            }
            '*allDevicesAssignmentTarget*' {
                # No token needed: universal
                $metaEntry['scope'] = 'All Devices'
            }
            '*allLicensedUsersAssignmentTarget*' {
                $metaEntry['scope'] = 'All Users'
            }
        }

        $cleanEntry = [ordered]@{
            intent = $asgn.intent
            target = [PSCustomObject]$cleanTarget
        }

        $cleanAssignments.Add([PSCustomObject]$cleanEntry)
        $metaAssignments.Add([PSCustomObject]$metaEntry)
    }

    return @{
        Clean = $cleanAssignments.ToArray()
        Meta  = $metaAssignments.ToArray()
    }
}

#endregion

#region ── Save ────────────────────────────────────────────────────────────────

function Save-PolicyFiles {
    param (
        [string]$Type,
        [string]$PolicyName,
        [string]$PolicyId,
        [object]$CleanData,
        [object]$MetaData,
        [string]$Folder
    )

    $safeName = Sanitize-FileName -Name $PolicyName
    $safeType = Sanitize-FileName -Name $Type
    $base     = "${safeType}_${safeName}_${PolicyId}"

    $cleanPath = Join-Path $Folder "${base}.json"
    $metaPath  = Join-Path $Folder "${base}.meta.json"

    [System.IO.File]::WriteAllText($cleanPath, ($CleanData | ConvertTo-Json -Depth 20), [System.Text.Encoding]::UTF8)
    [System.IO.File]::WriteAllText($metaPath,  ($MetaData  | ConvertTo-Json -Depth 20), [System.Text.Encoding]::UTF8)

    Write-Host "  [OK] $base" -ForegroundColor Green
}

#endregion

#region ── Policy processing ───────────────────────────────────────────────────

function Invoke-ProcessPolicy {
    <#
    Central processing for every policy:
    1. Strip the fixed fields
    2. Replace embedded tenant-specific values with placeholders
    3. Turn assignments into tokens
    4. Save .json and .meta.json
    #>
    param (
        [string]$Type,
        [string]$PolicyName,
        [string]$PolicyId,
        [object]$RawDetail,
        [object[]]$RawAssignments,
        [string]$SourceTenantId,
        [string]$Folder
    )

    $ctx = New-PlaceholderContext

    # ── Step 1: strip fixed fields ──
    # Invoke-MgGraphRequest returns hashtables
    $stripped = [ordered]@{}
    $keys = if ($RawDetail -is [System.Collections.IDictionary]) {
        @($RawDetail.Keys)
    } else {
        $RawDetail.PSObject.Properties | Select-Object -ExpandProperty Name
    }
    foreach ($key in $keys) {
        if ($key -notin $STRIP_FIELDS -and $key -ne '_assignments') {
            $stripped[$key] = $RawDetail[$key]
        }
    }

    # ── Step 2: placeholders for embedded values ──
    $cleanData = Invoke-SanitizeObject -Obj ([PSCustomObject]$stripped) -SourceTenantId $SourceTenantId -Ctx $ctx

    # ── Step 3: assignments ──
    $asgnResult = ConvertTo-CleanAssignments -Assignments $RawAssignments -Ctx $ctx
    $cleanData | Add-Member -NotePropertyName '_assignments' -NotePropertyValue $asgnResult.Clean -Force

    # ── Step 4: meta ──
    $meta = [ordered]@{
        exportedAt       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        sourceTenantId   = $SourceTenantId
        policyId         = $PolicyId
        policyName       = $PolicyName
        policyType       = $Type
        assignments      = $asgnResult.Meta
        placeholders     = $ctx.Mappings
        importInstructions = [ordered]@{
            description = "Replace every placeholder in the matching .json with the value for the target tenant."
            tokens      = @(
                "SOURCE_TENANT_ID  -> Tenant ID of the target tenant"
                "GROUP_*           -> Resolved by group name in the target tenant (groupMappings)"
                "Other tokens      -> tokenOverrides in the mapping file"
            )
        }
    }

    Save-PolicyFiles -Type $Type -PolicyName $PolicyName -PolicyId $PolicyId `
        -CleanData $cleanData -MetaData $meta -Folder $Folder
}

#endregion

#region ── Initialisation ──────────────────────────────────────────────────────

# Full path: [System.IO.File] resolves relative paths against the process directory, not $PWD
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "`nConnecting to Microsoft Graph (tenant: $TenantId)..." -ForegroundColor Cyan
Connect-MgGraph -TenantId $TenantId `
    -Scopes "DeviceManagementConfiguration.Read.All",
            "Group.Read.All" `
    -NoWelcome

$counters = @{ Success = 0; Skipped = 0; Errors = 0 }

#endregion

#region ── 1. Classic device configurations ────────────────────────────────────

Write-Host "`n[1/4] Classic device configurations..." -ForegroundColor Yellow

$configs = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/deviceConfigurations"

foreach ($cfg in $configs) {
    Write-Host "  -> $($cfg.displayName)" -NoNewline
    try {
        $detail      = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/deviceManagement/deviceConfigurations/$($cfg.id)" -ErrorAction Stop
        $assignments = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/deviceConfigurations/$($cfg.id)/assignments"

        # Type prefix from @odata.type
        $odataType = $cfg['@odata.type'] -replace '#microsoft.graph.', ''
        $prefix    = "DeviceConfig_$odataType"

        Invoke-ProcessPolicy -Type $prefix -PolicyName $cfg.displayName -PolicyId $cfg.id `
            -RawDetail $detail -RawAssignments $assignments `
            -SourceTenantId $TenantId -Folder $OutputPath
        $counters.Success++
    } catch {
        Write-Warning " -> ERROR: $_"
        $counters.Errors++
    }
}

#endregion

#region ── 2. Settings Catalog ─────────────────────────────────────────────────

Write-Host "`n[2/4] Settings Catalog policies..." -ForegroundColor Yellow

$catalogPolicies = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/configurationPolicies"

foreach ($pol in $catalogPolicies) {
    Write-Host "  -> $($pol.name)" -NoNewline
    try {
        $detail      = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/deviceManagement/configurationPolicies/$($pol.id)" -ErrorAction Stop
        $settings    = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/configurationPolicies/$($pol.id)/settings"
        $assignments = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/configurationPolicies/$($pol.id)/assignments"

        $detail['settings'] = $settings

        # Prefix from templateReference
        $prefix = "SettingsCatalog"
        $templateRef = $detail['templateReference']
        if ($templateRef -is [System.Collections.IDictionary] -and $templateRef.Contains('templateDisplayName') -and $templateRef['templateDisplayName']) {
            $safeTpl = $templateRef['templateDisplayName'] -replace '[^A-Za-z0-9]', ''
            $prefix  = "SettingsCatalog_$safeTpl"
        }

        Invoke-ProcessPolicy -Type $prefix -PolicyName $pol.name -PolicyId $pol.id `
            -RawDetail $detail -RawAssignments $assignments `
            -SourceTenantId $TenantId -Folder $OutputPath
        $counters.Success++
    } catch {
        Write-Warning " -> ERROR: $_"
        $counters.Errors++
    }
}

#endregion

#region ── 3. Administrative Templates ──────────────────────────────────────────

Write-Host "`n[3/4] Administrative Templates (ADMX)..." -ForegroundColor Yellow

$gpoConfigs = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations"

foreach ($gpo in $gpoConfigs) {
    Write-Host "  -> $($gpo.displayName)" -NoNewline
    try {
        $detail          = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$($gpo.id)" -ErrorAction Stop
        $definitionValues = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$($gpo.id)/definitionValues?`$expand=definition,presentationValues"
        $assignments     = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$($gpo.id)/assignments"

        # Presentation values with their presentation: the import needs the presentation ID to bind each value
        foreach ($dv in $definitionValues) {
            $dv['presentationValues'] = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/groupPolicyConfigurations/$($gpo.id)/definitionValues/$($dv['id'])/presentationValues?`$expand=presentation"
        }

        $detail['definitionValues'] = $definitionValues

        Invoke-ProcessPolicy -Type "AdminTemplate" -PolicyName $gpo.displayName -PolicyId $gpo.id `
            -RawDetail $detail -RawAssignments $assignments `
            -SourceTenantId $TenantId -Folder $OutputPath
        $counters.Success++
    } catch {
        Write-Warning " -> ERROR: $_"
        $counters.Errors++
    }
}

#endregion

#region ── 4. Legacy Endpoint Security intents ─────────────────────────────────

Write-Host "`n[4/4] Endpoint Security intents (legacy)..." -ForegroundColor Yellow

$intents = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/intents"

foreach ($intent in $intents) {
    Write-Host "  -> $($intent.displayName)" -NoNewline
    try {
        $detail      = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/deviceManagement/intents/$($intent.id)" -ErrorAction Stop
        $settings    = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/intents/$($intent.id)/settings"
        $assignments = Invoke-GraphGetAll -Uri "$GRAPH_BASE/deviceManagement/intents/$($intent.id)/assignments"

        $detail['settings'] = $settings

        # Template name for the prefix
        $prefix = "EndpointSecIntent"
        if ($intent['templateId']) {
            try {
                $tpl     = Invoke-MgGraphRequest -Method GET -Uri "$GRAPH_BASE/deviceManagement/templates/$($intent['templateId'])?`$select=displayName" -ErrorAction Stop
                $safeTpl = $tpl['displayName'] -replace '[^A-Za-z0-9]', ''
                $prefix  = "EndpointSecIntent_$safeTpl"
                $detail['_templateDisplayName'] = $tpl['displayName']
            } catch { <# Template not available, not a blocker #> }
        }

        Invoke-ProcessPolicy -Type $prefix -PolicyName $intent.displayName -PolicyId $intent.id `
            -RawDetail $detail -RawAssignments $assignments `
            -SourceTenantId $TenantId -Folder $OutputPath
        $counters.Success++
    } catch {
        Write-Warning " -> ERROR: $_"
        $counters.Errors++
    }
}

#endregion

#region ── Manifest ────────────────────────────────────────────────────────────

Write-Host "`nWriting manifest..." -ForegroundColor Cyan

$manifestEntries = [System.Collections.Generic.List[object]]::new()

Get-ChildItem -Path $OutputPath -Filter "*.meta.json" | ForEach-Object {
    $meta = Get-Content $_.FullName -Raw | ConvertFrom-Json
    $manifestEntries.Add([ordered]@{
        policyType   = $meta.policyType
        policyName   = $meta.policyName
        policyId     = $meta.policyId
        assignments  = @($meta.assignments | ForEach-Object {
            if ($_.groupName) { "$($_.intent): $($_.groupName)" }
            elseif ($_.scope) { "$($_.intent): $($_.scope)" }
        })
        placeholders = @($meta.placeholders.PSObject.Properties.Name)
        cleanFile    = ($_.Name -replace '\.meta\.json$', '.json')
        metaFile     = $_.Name
    })
}

$manifest = [ordered]@{
    generatedAt    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    sourceTenantId = $TenantId
    totalPolicies  = $manifestEntries.Count
    policies       = $manifestEntries
}

$manifestPath = Join-Path $OutputPath "_manifest.json"
[System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 10), [System.Text.Encoding]::UTF8)
Write-Host "  [OK] _manifest.json ($($manifestEntries.Count) policies)" -ForegroundColor Green

#endregion

#region ── Summary ─────────────────────────────────────────────────────────────

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Export finished." -ForegroundColor Cyan
Write-Host "  Succeeded   : $($counters.Success)"  -ForegroundColor Green
Write-Host "  Errors      : $($counters.Errors)"   -ForegroundColor $(if ($counters.Errors -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Output      : $OutputPath"            -ForegroundColor Cyan
Write-Host "  Files       : $(($counters.Success * 2) + 1) (2 JSON files per policy + manifest)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Disconnect-MgGraph | Out-Null

#endregion
