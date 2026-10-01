#Requires -Version 7.2
<#
.SYNOPSIS
    Reads a Bicep what-if result and asks Jev three questions: security, public IP and risk.

.DESCRIPTION
    Blog illustration. The what-if JSON comes from Get-RoutingApplianceWhatIf.ps1.
    Jev answers typed questions about the changes; the code turns the answers
    into a decision: Pass or Review.

.PARAMETER WhatIfFile
    What-if JSON file written by Get-RoutingApplianceWhatIf.ps1.

.PARAMETER Mock
    Use the Jev local mock (no API call).

.EXAMPLE
    ./Invoke-JevBicepWhatIfGate.ps1 -WhatIfFile C:\work\azure-routin-appliance-test\scripts\whatif2.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$WhatIfFile,

    [switch]$Mock
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name Jev)) {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../Jev/Jev.psd1') -Force
}

# 1. Load the what-if and keep only real changes
$whatIf = Get-Content -Path $WhatIfFile -Raw | ConvertFrom-Json
$changes = $whatIf.Changes | Where-Object -Property ChangeType -NotIn -Value @('NoChange', 'Ignore')

# 2. Turn the changes into a short text Jev can read
#    The raw what-if is too noisy to send as is:
#    - each change carries the full Before and After payload of the resource, so the few
#      properties that change are buried in ids, locations and unchanged settings;
#    - most of the content is the same on both sides, so the model must diff it itself.
#    The summary keeps only what Jev needs to answer: the change type, the resource
#    and the changed property paths. For a Create there is no delta, so the new
#    properties are kept: this is where the public IP and the password login show up.
#    On whatif2.json: about 33 KB of JSON for the changes, about 5 KB of summary.
$summary = foreach ($c in $changes) {
    $resource = if ($c.After) { $c.After } else { $c.Before }
    "$($c.ChangeType): $($resource.type) $($resource.name)"
    if ($c.ChangeType -eq 'Create') {
        '  properties: ' + ($resource.properties | ConvertTo-Json -Compress -Depth 10)
    }
    foreach ($d in $c.Delta) {
        "  $($d.PropertyChangeType) $($d.Path)"
    }
}

# 3. Ask Jev: security, public IP, risk
$questions = @(
    New-JevYesNoQuestion -Name security `
        -Question 'Do the changes in `whatif` weaken the security of the environment?' `
        -TrueCriteria 'Password login enabled on a VM, no NSG on a NIC or subnet, a security setting removed or relaxed' `
        -FalseCriteria 'Security settings are unchanged or stronger'

    New-JevYesNoQuestion -Name public_ip `
        -Question 'Do the changes in `whatif` expose a resource to the internet with a public IP?' `
        -TrueCriteria 'A public IP address is created or attached to a NIC, a VM or a load balancer' `
        -FalseCriteria 'No public IP is created or attached'

    New-JevQuestion -Name risk -Type Score `
        -Instructions 'How risky is it to deploy the changes in `whatif`?' `
        -Criteria @(
            'No risk: cosmetic or read-only property changes'
            'Low: new isolated resources'
            'Medium: changes to shared network resources (VNets, peerings, route tables)'
            'High: an outage or a security incident is likely'
        )
)

$state = @{ whatif = $summary -join "`n" }
$answers = (Invoke-Jev -State $state -Question $questions -Mock:$Mock -Raw).answers

# 4. The decision stays in code
$reasons = @(
    if ($answers.security.noul -gt 0.7) { 'Weakens security' }
    if ($answers.public_ip.noul -gt 0.7) { 'Exposes a public IP' }
    if ($answers.risk.score -ge 2) { "Risk level $($answers.risk.score)" }
)

[pscustomobject]@{
    Decision = if ($reasons) { 'Review' } else { 'Pass' }
    Reasons  = $reasons -join '; '
    Changes  = @($changes).Count
    Security = [math]::Round($answers.security.noul, 2)
    PublicIp = [math]::Round($answers.public_ip.noul, 2)
    Risk     = $answers.risk.score
}
