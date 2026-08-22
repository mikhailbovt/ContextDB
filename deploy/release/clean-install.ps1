[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,

    [string]$Manifest = "release/artifact-manifest.json",

    [ValidateSet("contract", "release")]
    [string]$Profile = "release",

    [string[]]$TrustedKey = @(),

    [switch]$AllowTestKeys,

    [string]$Report
)

$ErrorActionPreference = "Stop"

# The verifier, not this wrapper, provisions child-only token-key input and a
# fresh platform state-head authority per destination. Do not forward caller
# CONTEXTDB_* custody variables or serialize them into the report.
$resolvedBundle = (Resolve-Path -LiteralPath $BundleRoot).Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$verifier = Join-Path $repositoryRoot "tools\contextdb-release\contextdb_release.py"

if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw "Release verifier not found: $verifier"
}

$arguments = @(
    $verifier,
    "clean-install",
    "--bundle-root", $resolvedBundle,
    "--manifest", $Manifest,
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
