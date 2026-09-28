# Проверка прав администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "Этот скрипт необходимо запускать от имени администратора."
    exit 1
}

$MyRules = @("Block_http_conn", "Allow_rdp_conn", "Block_ftp_conn", "Block_ping_conn")

# Путь к result.txt — в той же папке, где лежит скрипт
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$resultFile = Join-Path $scriptDir "result.txt"

# Получаем правила и выбираем нужные свойства
Get-NetFirewallRule |
    Where-Object { $MyRules -contains $_.DisplayName } |
    ForEach-Object {
        $Filter = $_ | Get-NetFirewallPortFilter
        [PSCustomObject]@{
            Name       = $_.DisplayName
            Enabled    = $_.Enabled
            Protocol   = $Filter.Protocol
            LocalPort  = $Filter.LocalPort
            RemotePort = $Filter.RemotePort
            Action     = $_.Action
            Profile    = $_.Profile
        }
    } |
    Out-File -FilePath $resultFile -Encoding UTF8

Write-Host "Success! Results saved to $resultFile" -ForegroundColor Cyan