# vm-cleaner.ps1
# Removes all VM artifacts and generates a fresh machine identity.
# Run as Administrator. Reboot after.

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Must run as Administrator"; exit 1
}

function Remove-RegKey($path) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [REG] Removed: $path" -ForegroundColor Green
    }
}

Write-Host "`n[1/9] Stopping and deleting VM services..." -ForegroundColor Cyan
$services = @(
    "QEMU-GA", "balloon", "vioserial", "vioser", "qemupciserial",
    "vioinput", "viorng", "vioscsi", "viostor", "netkvm",
    "vmictimesync", "vmicheartbeat", "vmicvss", "vmicrdv",
    "vmicguestinterface", "vmicshutdown", "vmickvpexchange"
)
foreach ($svc in $services) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) {
        Stop-Service $svc -Force -ErrorAction SilentlyContinue
        sc.exe delete $svc | Out-Null
        Write-Host "  [SVC] Deleted: $svc" -ForegroundColor Green
    }
}

Write-Host "`n[2/9] Cleaning registry..." -ForegroundColor Cyan

# VM identity keys
Remove-RegKey "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
Remove-RegKey "HKLM:\SOFTWARE\Red Hat"
Remove-RegKey "HKLM:\SOFTWARE\QEMU"
Remove-RegKey "HKCU:\SOFTWARE\QEMU"
Remove-RegKey "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"

# ACPI subkeys with QEMU/BOCHS names
foreach ($table in @("DSDT","FADT","RSDT","SSDT")) {
    $base = "HKLM:\HARDWARE\ACPI\$table"
    if (Test-Path $base) {
        Get-ChildItem $base -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match "QEMU|BOCHS|VBOX|VMWARE" } |
            ForEach-Object { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "  [REG] Removed ACPI key: $($_.PSChildName)" -ForegroundColor Green }
    }
}

# VirtIO service registry keys
foreach ($svc in @("balloon","vioserial","vioser","qemupciserial","vioinput","viorng","vioscsi","viostor","netkvm","VirtioInput","viogpudo")) {
    Remove-RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    Remove-RegKey "HKLM:\SYSTEM\ControlSet001\Services\$svc"
}

# PCI enum — VirtIO vendor 1AF4, QEMU vendor 1234
$pciBase = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
if (Test-Path $pciBase) {
    Get-ChildItem $pciBase -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match "VEN_1AF4|VEN_1234" } |
        ForEach-Object { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "  [REG] Removed PCI enum: $($_.PSChildName)" -ForegroundColor Green }
}

Write-Host "`n[3/9] Removing hidden VM devices from PnP..." -ForegroundColor Cyan
$env:DEVMGR_SHOW_NONPRESENT_DEVICES = "1"
$patterns = "VirtIO|QEMU|Red Hat|viostor|vioscsi|balloon|vioserial|vioinput"
Get-PnpDevice -PresentOnly:$false -ErrorAction SilentlyContinue |
    Where-Object { ($_.FriendlyName + $_.InstanceId) -match $patterns } |
    ForEach-Object {
        Write-Host "  [PNP] Removing: $($_.FriendlyName)" -ForegroundColor Green
        $_ | Remove-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue
    }

Write-Host "`n[4/9] Removing VM driver files..." -ForegroundColor Cyan
$files = @(
    "C:\Windows\System32\drivers\balloon.sys",
    "C:\Windows\System32\drivers\vioserial.sys",
    "C:\Windows\System32\drivers\vioser.sys",
    "C:\Windows\System32\drivers\viostor.sys",
    "C:\Windows\System32\drivers\vioscsi.sys",
    "C:\Windows\System32\drivers\netkvm.sys",
    "C:\Windows\System32\drivers\vioinput.sys",
    "C:\Windows\System32\drivers\viorng.sys",
    "C:\Windows\System32\drivers\viogpudo.sys",
    "C:\Windows\System32\drivers\vioser.sys",
    "C:\Program Files\QEMU guest agent",
    "C:\Program Files\Virtio-Win"
)
foreach ($f in $files) {
    if (Test-Path $f) {
        Remove-Item $f -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [FILE] Removed: $f" -ForegroundColor Green
    }
}

# Remove VirtIO from Windows driver store
Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match "Red Hat|VirtIO|QEMU" } |
    ForEach-Object {
        Write-Host "  [DRV] Removing from driver store: $($_.Driver)" -ForegroundColor Green
        pnputil /delete-driver $_.Driver /uninstall /force 2>$null | Out-Null
    }

Write-Host "`n[5/9] Generating fresh machine identity..." -ForegroundColor Cyan

# New MachineGUID
$newGuid = [System.Guid]::NewGuid().ToString()
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" "MachineGuid" $newGuid
Write-Host "  [ID] New MachineGuid: $newGuid" -ForegroundColor Green

# Randomize InstallDate (within last 6 months, as Unix timestamp)
$randomDays = Get-Random -Minimum 30 -Maximum 180
$newDate = [int][double]::Parse((Get-Date).AddDays(-$randomDays).Subtract((Get-Date "1970-01-01")).TotalSeconds)
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "InstallDate" $newDate
Write-Host "  [ID] New InstallDate offset: -$randomDays days" -ForegroundColor Green

# Reset network adapter binding to pick up the spoofed MAC
Write-Host "`n[6/9] Refreshing network adapter binding..." -ForegroundColor Cyan
Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  [NET] Recycling: $($_.Name)" -ForegroundColor Green
    Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
    Enable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Host "`n[7/9] Clearing event logs..." -ForegroundColor Cyan
foreach ($log in @("System","Application","Security","Setup","Microsoft-Windows-Kernel-PnP/Configuration")) {
    wevtutil cl "$log" 2>$null
    Write-Host "  [LOG] Cleared: $log" -ForegroundColor Green
}

Write-Host "`n[8/9] Cleaning prefetch..." -ForegroundColor Cyan
foreach ($pattern in @("QEMU*","VIRTIO*","BALLOON*","VIOSERIAL*")) {
    Get-ChildItem "C:\Windows\Prefetch" -Filter $pattern -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
Write-Host "  [FILE] Done" -ForegroundColor Green

Write-Host "`n[9/9] Disabling Hyper-V integration services..." -ForegroundColor Cyan
foreach ($svc in @("vmictimesync","vmicheartbeat","vmicvss","vmicrdv","vmicguestinterface","vmicshutdown","vmickvpexchange")) {
    sc.exe config $svc start= disabled 2>$null | Out-Null
}
# Disable hypervisor launch via bcdedit
bcdedit /set hypervisorlaunchtype off 2>$null | Out-Null
bcdedit /set vsmlaunchtype off 2>$null | Out-Null
Write-Host "  [BCD] Hyper-V launch disabled" -ForegroundColor Green

Write-Host "`n=== Complete. REBOOT NOW. ===" -ForegroundColor Cyan
Write-Host "New MachineGUID: $newGuid" -ForegroundColor White
