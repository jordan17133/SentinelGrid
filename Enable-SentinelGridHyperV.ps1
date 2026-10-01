$ErrorActionPreference = "Stop"

$statusPath = "C:\Users\Jordan\Desktop\CTS2120 Templates\sentinelgrid-hyperv-status.txt"

try {
    "Starting Hyper-V enablement at $(Get-Date -Format o)" | Set-Content -LiteralPath $statusPath
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart |
        Out-String |
        Add-Content -LiteralPath $statusPath
    "RESULT=SUCCESS" | Add-Content -LiteralPath $statusPath
} catch {
    "RESULT=FAILED" | Add-Content -LiteralPath $statusPath
    $_ | Out-String | Add-Content -LiteralPath $statusPath
    exit 1
}
