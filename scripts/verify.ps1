[CmdletBinding()]
param(
    [switch]$SkipFrontendInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Invoke-VerifyStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Step
    )

    Write-Host "==> $Name"
    & $Step
}

Set-Location $RepoRoot

Invoke-VerifyStep "Sync Go workspace" {
    go work sync
}

Invoke-VerifyStep "Run Go tests" {
    go test ./apps/xso-idp/... ./apps/sample-client/... ./packages/xso-go/...
}

$FrontendDir = Join-Path $RepoRoot "frontend/xso-login"
$FrontendLockfile = Join-Path $FrontendDir "package-lock.json"
if (-not (Test-Path $FrontendLockfile)) {
    throw "Missing frontend lockfile: $FrontendLockfile"
}

Push-Location $FrontendDir
try {
    if (-not $SkipFrontendInstall) {
        Invoke-VerifyStep "Install frontend dependencies from lockfile" {
            npm ci
        }
    }

    Invoke-VerifyStep "Run frontend tests" {
        npm run test
    }

    Invoke-VerifyStep "Build frontend" {
        npm run build
    }
}
finally {
    Pop-Location
}

Write-Host "==> Generated asset checks"
Write-Host "No generated protobuf assets are configured yet."

Write-Host "Verification passed."
