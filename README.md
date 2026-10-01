# Decision model in action, Jev in Cloud operation with PowerShell

This repository host the source code of the [article](https://dev.to/omiossec/decision-model-in-action-jev-in-cloud-operation-with-powershell-367c)

To run all the script, you will have to download the the JEV PowerShell module from [Doug Finke](https://github.com/dfinke/Jev)

## scripts

- simpledemo.ps1 a Script to understand how Jev work
- Invoke-JevPolicyLinterReview.ps1 use [Azure Policy Linter](https://github.com/Azure/azure-policy-linter) to filtrate the result
- Invoke-JevNsgReviewSimple.ps1 control NSG rules with PowerShell and Jev
- Invoke-JevBicepWhatIfGate.ps1 Control the Bicep -whatif output for risky operation