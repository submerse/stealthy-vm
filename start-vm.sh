#!/bin/bash
# /usr/local/bin/start-vm.sh

VM_NAME="windows-stealth"
GPU_IDS=("0000:01:00.0" "0000:01:00.1")
NVIDIA_DRIVER="nvidia"

# ── Bind GPU to vfio ──────────────────────────────────────────
bind_vfio() {
    echo "Unbinding GPU from nvidia driver..."
    for id in "${GPU_IDS[@]}"; do
        if [ -e /sys/bus/pci/devices/$id/driver ]; then
            echo $id > /sys/bus/pci/devices/$id/driver/unbind
        fi
        echo "vfio-pci" > /sys/bus/pci/devices/$id/driver_override
        echo $id > /sys/bus/pci/drivers/vfio-pci/bind
    done
    echo "GPU bound to vfio-pci"
}

# ── Return GPU to nvidia ──────────────────────────────────────
unbind_vfio() {
    echo "Returning GPU to nvidia driver..."
    for id in "${GPU_IDS[@]}"; do
        echo "" > /sys/bus/pci/devices/$id/driver_override
        if [ -e /sys/bus/pci/devices/$id/driver ]; then
            echo $id > /sys/bus/pci/devices/$id/driver/unbind
        fi
        echo $id > /sys/bus/pci/drivers/$NVIDIA_DRIVER/bind
    done
    echo "GPU returned to nvidia"
}

# ── Main ──────────────────────────────────────────────────────
echo "Starting VM: $VM_NAME"

# Check VM exists
if ! virsh dominfo $VM_NAME &>/dev/null; then
    echo "ERROR: VM '$VM_NAME' not found"
    exit 1
fi

# Bind GPU to vfio
bind_vfio

# Start the VM
virsh start $VM_NAME
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to start VM, returning GPU to host..."
    unbind_vfio
    exit 1
fi

echo "VM started, waiting for shutdown..."

# Wait for VM to stop
while true; do
    STATE=$(virsh domstate $VM_NAME 2>/dev/null)
    if [ "$STATE" = "shut off" ] || [ "$STATE" = "crashed" ]; then
        break
    fi
    sleep 5
done

echo "VM stopped"

# Return GPU to host
unbind_vfio

echo "Done"
