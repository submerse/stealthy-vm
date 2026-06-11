#!/bin/bash

VM_NAME="win10"
export LIBVIRT_DEFAULT_URI=qemu:///system
export XDG_RUNTIME_DIR=/run/user/1000
export PULSE_SERVER=/run/user/1000/pulse/native

# Check VM exists
if ! virsh dominfo $VM_NAME &>/dev/null; then
    echo "ERROR: VM '$VM_NAME' not found"
    exit 1
fi

# Load vfio module if needed
if ! lsmod | grep -q vfio_pci; then
    sudo modprobe vfio-pci
fi

# Kill llama-server
killall llama-server 2>/dev/null
sleep 2

# Bind GPU to vfio (runs as root via sudoers)
echo "Binding 4090 to vfio..."
sudo /usr/local/bin/vfio-bind.sh bind

# Start VM as regular user (keeps PulseAudio access)
echo "Starting VM..."
virsh start $VM_NAME
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to start VM"
    sudo /usr/local/bin/vfio-bind.sh unbind
    exit 1
fi

# Patch FADT Preferred_PM_Profile (byte 45) from 0 to 1 while OVMF is still booting.
# Window: QEMU builds tables at init; Windows kernel caches them ~15s after start.
# We suspend, patch every FACP+ALASKA in QEMU memory, resume — all in <0.5s.
echo "Patching FADT pm_profile (5s delay to let QEMU fully init)..."
(sleep 5 && sudo /usr/local/bin/patch-fadt-pm-profile win10 2>&1 | sed 's/^/[fadt] /') &

echo "VM running — waiting for shutdown..."
while true; do
    STATE=$(virsh domstate $VM_NAME 2>/dev/null)
    if [ "$STATE" = "shut off" ] || [ "$STATE" = "crashed" ]; then
        break
    fi
    sleep 5
done

echo "VM stopped"
sudo /usr/local/bin/vfio-bind.sh unbind
echo "Done — 4090 returned to host"
