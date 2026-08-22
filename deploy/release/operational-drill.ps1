[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OldBundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$NewBundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$Plan,

    [ValidateSet("contract", "release")]
    [string]$Profile = "release",

    [string[]]$TrustedKey = @(),

    [switch]$AllowTestKeys,

    [string]$Report
)

$ErrorActionPreference = "Stop"

# The Python runner constructs a minimal child environment with one ephemeral
# token key and one distinct external state-head authority per database. Caller
# CONTEXTDB_* custody variables are neither forwarded nor serialized.
$resolvedOldBundle = (Resolve-Path -LiteralPath $OldBundleRoot).Path
$resolvedNewBundle = (Resolve-Path -LiteralPath $NewBundleRoot).Path
$resolvedPlan = (Resolve-Path -LiteralPath $Plan).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$verifier = Join-Path $repositoryRoot "tools\contextdb-release\contextdb_release.py"

if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw "Release verifier not found: $verifier"
}

$arguments = @(
    $verifier,
    "operational-drill",
    "--old-bundle-root", $resolvedOldBundle,
    "--new-bundle-root", $resolvedNewBundle,
    "--plan", $resolvedPlan,
    "--profile", $Profile
)

foreach ($key in $TrustedKey) {
    $arguments += @("--trusted-key", $key)
}

if ($AllowTestKeys) {
    $arguments += "--allow-test-keys"
}

if ($Report) {
    $arguments += @("--report", $Report)
}

& python @arguments
exit $LASTEXITCODE
