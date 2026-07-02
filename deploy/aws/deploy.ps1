param(
    [Parameter(Mandatory = $true)]
    [string]$GitRepository,

    [Parameter(Mandatory = $true)]
    [string]$VpcId,

    [Parameter(Mandatory = $true)]
    [string]$PublicSubnetId,

    [string]$GitBranch = "main",
    [string]$StackName = "network-intrusion-detection",
    [string]$AllowedDashboardCidr = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    throw "AWS CLI is not installed. Install and configure AWS CLI v2 before deploying."
}

if (-not $AllowedDashboardCidr) {
    $publicIp = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
    $AllowedDashboardCidr = "$publicIp/32"
}

aws sts get-caller-identity | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "AWS CLI credentials are not configured or have expired."
}

aws cloudformation deploy `
    --stack-name $StackName `
    --template-file deploy/aws/cloudformation.yaml `
    --capabilities CAPABILITY_NAMED_IAM `
    --parameter-overrides `
        "GitRepository=$GitRepository" `
        "GitBranch=$GitBranch" `
        "AllowedDashboardCidr=$AllowedDashboardCidr" `
        "VpcId=$VpcId" `
        "PublicSubnetId=$PublicSubnetId"

if ($LASTEXITCODE -ne 0) {
    throw "CloudFormation deployment failed."
}

$dashboardUrl = aws cloudformation describe-stacks `
    --stack-name $StackName `
    --query "Stacks[0].Outputs[?OutputKey=='DashboardUrl'].OutputValue | [0]" `
    --output text

Write-Host "AWS deployment complete."
Write-Host "Dashboard: $dashboardUrl"
