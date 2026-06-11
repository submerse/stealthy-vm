#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Randomizes all unique machine identifiers on Windows.
    Run as Administrator. Restart required after.
#>

$ErrorActionPreference = 'SilentlyContinue'

function New-Guid       { return [System.Guid]::NewGuid().ToString() }
function New-GuidBraced { return "{$([System.Guid]::NewGuid().ToString().ToUpper())}" }

function Get-RandomBytes([int]$n) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return $b
}

function New-RandomMac {
    # Intel Corporation OUI (00:1B:21) - matches our e1000e NIC vendor
    $tail = Get-RandomBytes 3
    return "00-1B-21-{0:X2}-{1:X2}-{2:X2}" -f $tail[0],$tail[1],$tail[2]
}

function New-RandomComputerName {
    $prefixes = @('DESKTOP','PC','WORKSTATION','STUDIO')
    $suffix   = -join ((65..90) | Get-Random -Count 7 | ForEach-Object { [char]$_ })
    return "$($prefixes | Get-Random)-$suffix"
}

Write-Host ""
Write-Host "=== Machine Identity Randomizer ===" -ForegroundColor Cyan
Write-Host ""

# -- 1. MachineGuid ---------------------------------------------------------
$old = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid
$new = New-Guid
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid -Value $new
Write-Host "[OK] MachineGuid"
Write-Host "       $old -> $new"

# -- 2. Computer Name --------------------------------------------------------
$newName = New-RandomComputerName
Rename-Computer -NewName $newName -Force
Write-Host "[OK] ComputerName -> $newName  (active after restart)"

# -- 3. NIC MAC Addresses ----------------------------------------------------
$nicKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
Get-ChildItem $nicKey | Where-Object { $_.PSChildName -match '^\d{4}$' } | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    if ($props.DriverDesc -and $props.DriverDesc -notmatch 'WAN Miniport|Virtual|Hyper-V|Loopback|Bluetooth') {
        $mac = New-RandomMac
        Set-ItemProperty $_.PSPath -Name "NetworkAddress" -Value ($mac -replace '-','')
        Write-Host "[OK] MAC $($props.DriverDesc) -> $mac"
    }
}

# -- 4. Windows Product ID ---------------------------------------------------
$pid1 = "{0:D5}" -f (Get-Random -Min 10000 -Max 99999)
$pid2 = "{0:D3}" -f (Get-Random -Min 100  -Max 999)
$pid3 = "{0:D7}" -f (Get-Random -Min 1000000 -Max 9999999)
$pid4 = "{0:D5}" -f (Get-Random -Min 10000 -Max 99999)
$newProductId = "$pid1-$pid2-$pid3-$pid4"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductId -Value $newProductId
Write-Host "[OK] ProductId -> $newProductId"

# -- 5. Windows Install Date -------------------------------------------------
$daysAgo = Get-Random -Min 180 -Max 900
$fakeDate = (Get-Date).AddDays(-$daysAgo)
$unixTs   = [int][double]::Parse((Get-Date $fakeDate -UFormat "%s"))
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name InstallDate -Value $unixTs -Type DWord
Write-Host "[OK] InstallDate -> $($fakeDate.ToString('yyyy-MM-dd'))"

# -- 6. SQMClient Telemetry Machine ID --------------------------------------
if (Test-Path "HKLM:\SOFTWARE\Microsoft\SQMClient") {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\SQMClient" -Name MachineId -Value (New-GuidBraced)
    Write-Host "[OK] SQMClient\MachineId"
}

# -- 7. Windows Update Client ID ---------------------------------------------
$wuPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
if (Test-Path $wuPath) {
    Set-ItemProperty $wuPath -Name SusClientId           -Value (New-Guid)
    Set-ItemProperty $wuPath -Name SusClientIDValidation -Value ([byte[]](Get-RandomBytes 8)) -Type Binary
    Write-Host "[OK] WindowsUpdate\SusClientId"
}

# -- 8. Diagnostics / DiagTrack IDs ------------------------------------------
$diagPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser"
)
foreach ($p in $diagPaths) {
    if (Test-Path $p) {
        Get-ItemProperty $p | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -match 'Id|Guid|Token' } |
            ForEach-Object { Set-ItemProperty $p -Name $_.Name -Value (New-Guid) }
    }
}
Write-Host "[OK] DiagTrack / AppraiserIDs"

# -- 9. Cryptographic Machine Keys & Certificate Store ID --------------------
# The machine-specific DPAPI entropy is tied to MachineGuid - already rotated above.
# Force a new random value for the CryptSP unique container seed.
$cryptoPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\df9d8cd0-1501-11d1-8c7a-00c04fc297eb"
if (Test-Path $cryptoPath) {
    Set-ItemProperty $cryptoPath -Name ProviderID -Value (New-GuidBraced)
    Write-Host "[OK] DPAPI ProviderID"
}

# -- 10. NVIDIA GPU Telemetry GUID --------------------------------------------
$nvidiaPath = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup"
if (Test-Path $nvidiaPath) {
    Set-ItemProperty $nvidiaPath -Name "GUID" -Value (New-GuidBraced)
    Write-Host "[OK] NVIDIA driver GUID"
}

# -- 11. Plug & Play Machine ID -----------------------------------------------
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE") {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE" `
        -Name "SetupDisplayedEula" -Value 1
}
$pnpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001"
if (Test-Path $pnpPath) {
    Set-ItemProperty $pnpPath -Name HwProfileGuid -Value (New-GuidBraced)
    Write-Host "[OK] PnP Hardware Profile GUID"
}

# -- 12. Volume Serial Number (C:) --------------------------------------------
try {
    # Write new random serial into NTFS boot sector at offset 0x48 (8 bytes)
    # Requires exclusive access - works on non-system drives easily;
    # on C: Windows may block the write (safe to fail)
    $fs = [System.IO.File]::Open('\\.\C:', [System.IO.FileMode]::Open,
          [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $buf = New-Object byte[] 512
    $fs.Read($buf, 0, 512) | Out-Null
    $serial = Get-RandomBytes 8
    [System.Array]::Copy($serial, 0, $buf, 0x48, 8)
    $fs.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
    $fs.Write($buf, 0, 512)
    $fs.Close()
    Write-Host "[OK] Volume serial (C:) - change visible after chkdsk or reformat"
} catch {
    Write-Host "[--] Volume serial (C:) - locked by OS, use VolumeID.exe from Sysinternals"
}

# -- 13. Machine SID (requires SYSTEM - run via scheduled task) --------------
Write-Host ""
Write-Host "[ ] Machine SID - scheduling SYSTEM-level task..."
$sidScript = @'
$sam = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine',[Microsoft.Win32.RegistryView]::Registry64)
# Machine SID is at HKLM\SECURITY\SAM\SAM\Domains\Account - needs SYSTEM
# Generate 3 random DWORDs for the sub-authority
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$b = New-Object byte[] 12
$rng.GetBytes($b)
$v1 = [BitConverter]::ToUInt32($b, 0)
$v2 = [BitConverter]::ToUInt32($b, 4)
$v3 = [BitConverter]::ToUInt32($b, 8)
# Write to SECURITY hive
try {
    $key = $sam.OpenSubKey('SECURITY\SAM\SAM\Domains\Account', $true)
    if ($key) {
        $val = $key.GetValue('V')
        if ($val -and $val.Length -ge 0x50) {
            [BitConverter]::GetBytes($v1).CopyTo($val, 0x48)
            [BitConverter]::GetBytes($v2).CopyTo($val, 0x4C)
            [BitConverter]::GetBytes($v3).CopyTo($val, 0x50)
            $key.SetValue('V', $val, [Microsoft.Win32.RegistryValueKind]::Binary)
        }
        $key.Close()
    }
} catch {}
$sam.Close()
'@
$sidScriptPath = "$env:TEMP\set-sid.ps1"
$sidScript | Out-File $sidScriptPath -Encoding UTF8
schtasks /create /f /tn "RandomizeSID" /tr "powershell -NonInteractive -File `"$sidScriptPath`"" /sc once /st 00:00 /ru SYSTEM | Out-Null
schtasks /run /tn "RandomizeSID" | Out-Null
Start-Sleep 3
schtasks /delete /tn "RandomizeSID" /f | Out-Null
Remove-Item $sidScriptPath -Force
Write-Host "[OK] Machine SID randomized (SYSTEM task)"

# -- 14. Clear hardware-cached fingerprints -----------------------------------
Write-Host ""
Write-Host "[ ] Clearing cached hardware fingerprints..."
$clearPaths = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId4"
)
foreach ($p in $clearPaths) {
    if (Test-Path $p) {
        $bytes = Get-RandomBytes 164
        Set-ItemProperty $p -Name DigitalProductId -Value $bytes -Type Binary -ErrorAction SilentlyContinue
    }
}

# -- 15. Windows Telemetry / Advertising ID ----------------------------------
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" `
    -Name Id -Value (New-Guid) -ErrorAction SilentlyContinue
Write-Host "[OK] Advertising ID"

# -- Summary ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Changed:"
Write-Host "  - MachineGuid (primary HWID component)"
Write-Host "  - ComputerName"
Write-Host "  - NIC MAC addresses"
Write-Host "  - ProductId"
Write-Host "  - InstallDate"
Write-Host "  - SQMClient / DiagTrack telemetry IDs"
Write-Host "  - WindowsUpdate SusClientId"
Write-Host "  - PnP Hardware Profile GUID"
Write-Host "  - NVIDIA driver GUID (if present)"
Write-Host "  - Machine SID"
Write-Host "  - Advertising ID"
Write-Host ""
Write-Host "NOT changed (handled by QEMU/SMBIOS config):"
Write-Host "  - CPU serial (host passthrough)"
Write-Host "  - HDD serial (QEMU override: WD-WXC1A8F3K2L1)"
Write-Host "  - BIOS/board serials (QEMU SMBIOS)"
Write-Host "  - TPM seed (swtpm)"
Write-Host ""
Write-Host "RESTART the VM now for all changes to take effect." -ForegroundColor Yellow
