# VM Hardening Runbook

## Prerequisites

Get your VM's UUID and paste it into the script:
```bash
virsh domuuid win10
```
Open `vm_harden_host.py` and replace `YOUR-UUID-HERE` in the `-smbios type=1,...` line with that value.

Default XML path is `~/Downloads/win10_v2.xml`. Pass a different path as the first arg if needed.

---

## Step 1 — Host Script (Linux)

```bash
python3 ~/Downloads/vm_harden_host.py ~/Downloads/win10_v2.xml win10
```

Applies all 12 XML edits:
- CPUID hypervisor hidden, hyperv enlightenments stripped
- CPU host-passthrough, hypervisor feature disabled
- Clock/TSC native passthrough
- Full SMBIOS (bios/system/baseBoard/chassis/OEM strings)
- Intel MAC (00:1B:21) + e1000e NIC
- memballoon disabled
- Disk serial added
- RAM modules (SMBIOS type 17) added
- Disk model override (WDC WD40EZRZ)
- virtio-serial controller removed
- virtio-win ISO ejected
- USB controller changed to nec-xhci

Then runs `virsh define` automatically.

**Cold boot the VM after** (full shutdown → start, not reboot).

---

## Step 2 — Guest Script (Windows, as Administrator)

Copy `vm_harden_guest.bat` into the VM and run as Administrator.

Handles:
- `bcdedit` disabling Hyper-V and VBS
- QEMU Guest Agent service removed
- Hyper-V integration services disabled
- w32time fixed
- QEMU/virtio registry keys and service keys deleted

---

## Step 3 — Manual Steps Inside Windows

### Memory Integrity (GUI — cannot be scripted)
Windows Security → Device Security → Core Isolation Details → Memory Integrity → **Off**

### Device Manager cleanup
Show ghost devices first:
```cmd
set DEVMGR_SHOW_NONPRESENT_DEVICES=1
start devmgmt.msc
```
View → Show hidden devices → uninstall (with "delete driver" checked) anything named:
- `VirtIO *`
- `QEMU *`
- `Red Hat VirtIO *`

### Programs and Features
Open `appwiz.cpl` and uninstall QEMU Guest Agent if listed.

**Reboot**, then run the verification commands printed by the batch script.

### Verification (after reboot)
```cmd
msinfo32
wmic bios get manufacturer,smbiosbiosversion
wmic diskdrive get model,serialnumber
wmic nic get name,macaddress
```
All output should show ASUS/WDC/Intel — no QEMU, no VirtIO, no Red Hat.

---

## Step 4 — ACPI Table Patching (BOCHS → ALASKA)

Do this last, after all other steps are clean.

### Install tools on host
```bash
sudo pacman -S acpica
```

### Dump QEMU's DSDT

**Option A — from inside Windows (easier):**
Download acpidump from acpica.org, run as Administrator:
```cmd
acpidump.exe -o acpi_tables.dat
acpixtract.exe -a acpi_tables.dat
```
Copy `DSDT.dat` out to the host via shared folder.

**Option B — from host via QEMU monitor:**
```bash
virsh qemu-monitor-command win10 --hmp "acpi_extract_tables /tmp/vm_dsdt/"
```

### Decompile, patch, recompile
```bash
iasl -d DSDT.dat          # produces DSDT.dsl

# Patch OEM strings (keep 8-char padding with trailing spaces)
sed -i 's/BOCHS /ALASKA/g; s/BXPC    /A M I   /g' DSDT.dsl

iasl DSDT.dsl             # produces DSDT.aml — fix any compile errors manually
```

### Install the patched table
```bash
sudo mkdir -p /etc/libvirt/qemu/dsdt
sudo cp DSDT.aml /etc/libvirt/qemu/dsdt/win10_dsdt.aml
```

### Inject into VM XML
Add these two lines inside `<qemu:commandline>` in the XML:
```xml
<qemu:arg value='-acpitable'/>
<qemu:arg value='file=/etc/libvirt/qemu/dsdt/win10_dsdt.aml'/>
```
Then:
```bash
virsh define ~/Downloads/win10_v2.xml
```
Cold boot the VM.

### Verify
Inside the VM, open AIDA64 → Motherboard → ACPI.
OEM ID should show `ALASKA`, OEM Table ID should show `A M I` — not `BOCHS`/`BXPC`.

---

## Files

| File | Purpose |
|---|---|
| `vm_harden_host.py` | Host-side script — edits XML + runs virsh define |
| `vm_harden_guest.bat` | Guest-side script — run as Admin inside Windows |
| `vm_hardening_steps.md` | Original reference guide |
| `vm_hardening_runbook.md` | This file |
