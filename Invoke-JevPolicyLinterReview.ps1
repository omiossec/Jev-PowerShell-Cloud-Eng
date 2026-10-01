#Requires -Version 7.2
<#
.SYNOPSIS
    Lints Azure Policy definitions with the Azure Policy Linter, then asks Jev what the linter cannot answer.

.DESCRIPTION
    Blog illustration, offline: no Azure connection, only the policy files.
      1. The linter finds rule-level issues (facts, never re-judged).
      2. Jev answers the questions a linter cannot: do the findings matter, does the
         description match the rule, does the policy weaken security.
      3. The code turns the answers into an action per policy.

.PARAMETER Path
    Folder containing the policy definition JSON files.

.PARAMETER Mock
    Use the Jev local mock (no API call).

.EXAMPLE
    ./Invoke-JevPolicyLinterReview.ps1 -Path ./policy
#>
[CmdletBinding()]
param(
    [ValidateScript({ Test-Path -Path $_ -PathType Container })]
    [string]$Path = './policy',

    [switch]$Mock
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -Name Jev)) {
    Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../Jev/Jev.psd1') -Force
}

# 1. Run the linter: policylinter .\policy1.json .\policy2.json ... -o PolicyResult.json
$resultFile = Join-Path -Path $Path -ChildPath 'PolicyResult.json'
$files = Get-ChildItem -Path $Path -Filter '*.json' -File | Where-Object -Property Name -NE -Value 'PolicyResult.json'

$null = policylinter $files.FullName -o $resultFile
if ($LASTEXITCODE -ne 0) { throw "policylinter failed with exit code $LASTEXITCODE" }

# { "<file>": [ { ruleIdentifier, title, severity, path, ... } ] }, keyed here by file name
$lint = @{}
(Get-Content -Path $resultFile -Raw | ConvertFrom-Json -AsHashtable).GetEnumerator() | ForEach-Object {
    $lint[(Split-Path -Path $_.Key -Leaf)] = @($_.Value)
}

# 2. The questions for Jev
$questions = @(
    New-JevYesNoQuestion -Name findings_matter `
        -Question 'Does at least one item in `linter_findings` mean `policy` may not evaluate or enforce as intended?' `
        -TrueCriteria 'A finding changes which resources match: wrong array logic, missing alias, broken condition' `
        -FalseCriteria 'Findings are style, old API versions, optional properties or best-practice hints, or there are no findings'

    New-JevYesNoQuestion -Name description_matches `
        -Question 'Do displayName and description of `policy` match what policyRule really evaluates and its default effect?' `
        -TrueCriteria 'Same resource types, same condition, same effect as the rule' `
        -FalseCriteria 'The text promises other resource types, another condition or a stronger effect than the rule'

    New-JevYesNoQuestion -Name weakens_security `
        -Question 'Could assigning `policy` weaken security?' `
        -TrueCriteria 'The remediation opens network access, uses hard-coded public IP ranges, or grants a broader role than needed (Owner, Contributor)' `
        -FalseCriteria 'The policy only audits or denies, or remediates with a least-privilege role'
)

# 3. One Jev call per policy, the decision stays in code
foreach ($file in $files) {
    $definition = (Get-Content -Path $file.FullName -Raw | ConvertFrom-Json).properties
    $findings = $lint[$file.Name]

    $state = [ordered]@{
        policy          = [ordered]@{
            displayName = $definition.displayName
            description = $definition.description
            parameters  = $definition.parameters
            policyRule  = $definition.policyRule
        }
        linter_findings = @($findings | ForEach-Object { "$($_.severity) $($_.ruleIdentifier) at $($_.path)" })
    }
    $a = (Invoke-Jev -State $state -Question $questions -Mock:$Mock -Raw).answers

    $action = if ($a.weakens_security.noul -gt 0.7) { 'Security review' }
    elseif ($a.findings_matter.noul -gt 0.7) { 'Fix the rule' }
    elseif ($a.description_matches.noul -lt 0.3) { 'Fix the description' }
    elseif ($findings.Count -gt 0) { 'Backlog' }
    else { 'OK' }

    [pscustomobject]@{
        Policy             = $file.Name
        Warnings           = @($findings | Where-Object -Property severity -EQ -Value 'Warning').Count
        Informational      = @($findings | Where-Object -Property severity -EQ -Value 'Informational').Count
        FindingsMatter     = [math]::Round($a.findings_matter.noul, 2)
        DescriptionMatches = [math]::Round($a.description_matches.noul, 2)
        WeakensSecurity    = [math]::Round($a.weakens_security.noul, 2)
        Action             = $action
    }
}
