#Requires -Version 7.2
<#
.SYNOPSIS
    Reviews NSG rules from a JSON file: deterministic checks first, then Jev for what regex cannot answer.

.DESCRIPTION
    Blog illustration, offline: no Azure connection, only a JSON file with fake NSGs.
      1. Deterministic checks (no AI), always Critical: management ports or all ports open
         inbound from the internet.
      2. Jev, per rule: intent, compliance with the NSG standard, scope broader than needed,
         temporary rule, description mismatch, severity.
      3. The code turns the answers into an action per rule.

.PARAMETER Path
    JSON file with the NSGs (ARM shape) and a subnetPurpose map.

.PARAMETER Mock
    Use the Jev local mock (no API call).

.EXAMPLE
    ./Invoke-JevNsgReviewSimple.ps1 -Path ./nsg/fake-nsg.json | Where-Object -Property Action -NE -Value 'ok'
#>
[CmdletBinding()]
param(
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$Path = './nsg/fake-nsg.json',

    [switch]$Mock
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name Jev)) {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../Jev/Jev.psd1') -Force
}

$standard = @'
NSG STANDARD (sample)
- Management ports (22, 3389, 5985, 5986) are only allowed from the Azure Bastion subnet or the snet-mgmt subnet.
- No inbound allow rule may use source * or Internet, except on subnets explicitly marked as public-facing, and only for 80/443.
- Data subnets accept traffic only from the application subnets of the same landing zone, on the data ports they need.
- Use specific ports; port ranges wider than 10 ports need a documented reason in the rule description.
- Prefer Application Security Groups or specific subnet prefixes over the VirtualNetwork service tag.
- Every custom rule must have a description stating its purpose and owner.
- Temporary rules must include an expiry date in the description.
'@

$managementPorts = 22, 3389, 5985, 5986
$internetSources = '*', 'Internet', '0.0.0.0/0', 'Any'

# ------------------------------------------------------------------ helpers
function Get-RuleValue {
    <# NSG rules use either the singular or the plural property: merge both. #>
    param([object]$Single, [object]$Plural)
    @(@($Single) + @($Plural) | Where-Object -FilterScript { $_ })
}

function Test-PortMatch {
    param([string[]]$Range, [int[]]$Port)

    foreach ($r in $Range) {
        if ($r -eq '*') { return $true }
        if ($r -match '^(\d+)-(\d+)$') {
            $low, $high = [int]$Matches[1], [int]$Matches[2]
            if ($Port | Where-Object -FilterScript { $_ -ge $low -and $_ -le $high }) { return $true }
        }
        elseif ([int]$r -in $Port) { return $true }
    }
    $false
}

function Get-DeterministicFinding {
    param([Parameter(Mandatory)][pscustomobject]$Rule)

    if ($Rule.Direction -ne 'Inbound' -or $Rule.Access -ne 'Allow') { return @() }
    if (-not ($Rule.Source | Where-Object -FilterScript { $_ -in $internetSources })) { return @() }

    if ('*' -in $Rule.DestinationPort) { 'All ports open inbound from the internet' }
    elseif (Test-PortMatch -Range $Rule.DestinationPort -Port $managementPorts) { 'Management port open inbound from the internet' }
}

# ------------------------------------------------------------------ 1. Load and deterministic checks
$config = Get-Content -Path $Path -Raw | ConvertFrom-Json -AsHashtable

$rules = foreach ($nsg in $config.networkSecurityGroups) {
    $subnets = @($nsg.properties.subnets | ForEach-Object -Process { ($_.id -split '/')[-1] })
    $nics = @($nsg.properties.networkInterfaces | ForEach-Object -Process { ($_.id -split '/')[-1] })

    foreach ($r in $nsg.properties.securityRules) {
        $p = $r.properties
        $rule = [pscustomobject]@{
            Nsg             = $nsg.name
            Rule            = $r.name
            Priority        = $p.priority
            Direction       = $p.direction
            Access          = $p.access
            Protocol        = $p.protocol
            Source          = @(Get-RuleValue -Single $p.sourceAddressPrefix -Plural $p.sourceAddressPrefixes)
            Destination     = @(Get-RuleValue -Single $p.destinationAddressPrefix -Plural $p.destinationAddressPrefixes)
            DestinationPort = @(Get-RuleValue -Single $p.destinationPortRange -Plural $p.destinationPortRanges)
            Description     = $p.description
        }
        $rule | Add-Member -NotePropertyName HardFindings -NotePropertyValue @(Get-DeterministicFinding -Rule $rule)
        $rule | Add-Member -NotePropertyName State -NotePropertyValue ([ordered]@{
                nsg          = [ordered]@{
                    name               = $nsg.name
                    associated_subnets = @($subnets | ForEach-Object -Process {
                            [ordered]@{ name = $_; purpose = $config.subnetPurpose[$_] ?? 'unknown' } })
                    associated_nics    = $nics
                }
                rule         = [ordered]@{
                    name              = $rule.Rule
                    priority          = $rule.Priority
                    direction         = $rule.Direction
                    access            = $rule.Access
                    protocol          = $rule.Protocol
                    source            = $rule.Source
                    destination       = $rule.Destination
                    destination_ports = $rule.DestinationPort
                    description       = $rule.Description ?? '(none)'
                }
                nsg_standard = $standard
            })
        $rule
    }
}
Write-Verbose -Message "NSG rules to review: $(@($rules).Count)"

# ------------------------------------------------------------------ 2. Jev
$questions = @(
    New-JevQuestion -Name intent -Type Choice `
        -Instructions 'What is `rule` most likely for, given the purpose of the subnets in `nsg`?' `
        -Criteria ([ordered]@{
            app_traffic         = 'Application traffic between tiers or from clients'
            management_access   = 'Administrative access (SSH, RDP, WinRM, Bastion)'
            platform_dependency = 'Platform needs: DNS, identity, monitoring, backup, load balancer probes'
            vendor_or_partner   = 'Access for a third party, vendor or partner network'
            temporary_or_test   = 'Troubleshooting, test, migration or other temporary access'
            unclear             = 'Purpose cannot be determined from the rule and its context'
        })

    New-JevYesNoQuestion -Name compliant `
        -Question 'Does `rule` comply with every applicable point of `nsg_standard`?' `
        -TrueCriteria 'No point of the standard is violated by the rule as configured' `
        -FalseCriteria 'At least one point of the standard is violated'

    New-JevYesNoQuestion -Name broader_than_needed `
        -Question 'Is the source, destination or port scope of `rule` broader than its apparent purpose requires?' `
        -TrueCriteria 'All ports for a web tier, VirtualNetwork tag where one subnet would do, large CIDR, * source' `
        -FalseCriteria 'Specific ports, specific subnets or ASGs matching the purpose'

    New-JevYesNoQuestion -Name looks_temporary `
        -Question 'Does the name or description of `rule` suggest a temporary, test or troubleshooting rule?' `
        -TrueCriteria 'Words like temp, test, debug, troubleshoot, migration, POC, a ticket number, or a past date' `
        -FalseCriteria 'Name and description describe a permanent, owned purpose'

    New-JevYesNoQuestion -Name description_mismatch `
        -Question 'Is the description of `rule` missing, or does it contradict what the rule actually allows?' `
        -TrueCriteria 'No description, or the description names other ports, sources or purposes than configured' `
        -FalseCriteria 'The description accurately states what the rule allows and why'

    New-JevQuestion -Name severity -Type Score `
        -Instructions 'What is the security severity of `rule` as currently configured?' `
        -Criteria @(
            'None: correct and tightly scoped'
            'Low: hygiene or documentation issue'
            'Moderate: broader than needed, no internet exposure'
            'High: exposes a sensitive subnet or breaks segmentation'
            'Critical: direct internet exposure of sensitive services'
        )
)

# ------------------------------------------------------------------ 3. One Jev call per rule, the decision stays in code
foreach ($rule in $rules) {
    $a = (Invoke-Jev -State $rule.State -Question $questions -Mock:$Mock -Raw).answers

    $action = if ($rule.HardFindings.Count) { 'security-ticket-p1' }     # deterministic, never overridden
    elseif ($a.severity.score -ge 3) { 'security-review' }
    elseif ($a.intent.confidence -lt 0.5) { 'human-review' }
    elseif ($a.looks_temporary.noul -gt 0.7) { 'owner-confirm-or-remove' }
    elseif ($a.broader_than_needed.noul -gt 0.7) { 'tighten-rule' }
    elseif ($a.compliant.noul -lt 0.3) { 'non-compliant-owner-ticket' }
    elseif ($a.description_mismatch.noul -gt 0.7) { 'fix-description' }
    else { 'ok' }

    $findings = @(
        $rule.HardFindings
        if ($a.compliant.noul -lt 0.3) { 'Not compliant with NSG standard' }
        if ($a.broader_than_needed.noul -gt 0.7) { 'Scope broader than needed' }
        if ($a.looks_temporary.noul -gt 0.7) { 'Looks temporary' }
        if ($a.description_mismatch.noul -gt 0.7) { 'Description missing or misleading' }
    )

    [pscustomobject]@{
        Nsg       = $rule.Nsg
        Rule      = $rule.Rule
        Action    = $action
        Severity  = if ($rule.HardFindings.Count) { 4 } else { [math]::Round($a.severity.score, 2) }
        Findings  = $findings -join '; '
        Intent    = $a.intent.choice
        Compliant = [math]::Round($a.compliant.noul, 2)
        Ports     = $rule.DestinationPort -join ','
        Source    = $rule.Source -join ','
    }
}
