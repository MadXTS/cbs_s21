$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "Этот скрипт необходимо запускать от имени администратора."
    exit 1
}

# 2. Файлы
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputFile = Join-Path $ScriptDir "secpol.txt"
$TempFile   = Join-Path $env:TEMP "temp_policy.inf"

# 3. Экспорт локальной политики безопасности
secedit /export /cfg $TempFile /quiet

if (-not (Test-Path $TempFile)) {
    Write-Error "Не удалось экспортировать политику безопасности (файл $TempFile не создан)."
    exit 1
}

# 4. Функция преобразования SID в имена
function Convert-SidToName {
    param(
        [string]$SidString
    )

    $sid = $SidString.TrimStart('*')

    try {
        $ntAccount = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $name = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value
        return $name
    }
    catch {
        return $SidString
    }
}

# 5. Чтение INF, преобразование SID в секции [Privilege Rights]
$lines = Get-Content $TempFile -Encoding Default

$resultLines = @()
$currentSection = ""
$inPrivilegeRights = $false

foreach ($line in $lines) {
    $trimmed = $line.Trim()

    # Определяем секцию
    if ($trimmed -match '^\[(.+)\]$') {
        $currentSection = $matches[1]
        $inPrivilegeRights = ($currentSection -eq "Privilege Rights")
        $resultLines += $line
        continue
    }

    # Обрабатываем только строки вида Key=Value в секции Privilege Rights
    if ($inPrivilegeRights -and ($trimmed -match '^([^=]+)=(.*)$')) {
        $key   = $matches[1].Trim()
        $value = $matches[2].Trim()

        # Разбиваем список SID через запятую
        $sids = $value -split ',' | ForEach-Object { $_.Trim() }
        $names = $sids | ForEach-Object { Convert-SidToName -SidString $_ }
        $newValue = $names -join ", "

        $resultLines += "$key=$newValue"
    }
    else {
        # Все остальные строки — как есть
        $resultLines += $line
    }
}

# 6. Сохранение в secpol.txt
$resultLines -join "`n" | Out-File -FilePath $OutputFile -Encoding UTF8

# 7. Очистка
Remove-Item $TempFile -Force -ErrorAction SilentlyContinue

Write-Host "Success! File $OutputFile created." -ForegroundColor Cyan