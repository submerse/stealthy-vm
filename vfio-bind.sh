#!/bin/bash
GPU_IDS=("0000:01:00.0" "0000:01:00.1")
NVIDIA_DRIVER="nvidia"

bind_vfio() {
    for id in "${GPU_IDS[@]}"; do
        if [ -e /sys/bus/pci/devices/$id/driver ]; then
            echo $id > /sys/bus/pci/devices/$id/driver/unbind
        fi
        echo "vfio-pci" > /sys/bus/pci/devices/$id/driver_override
        echo $id > /sys/bus/pci/drivers/vfio-pci/bind
    done
}

unbind_vfio() {
    for id in "${GPU_IDS[@]}"; do
        echo "" > /sys/bus/pci/devices/$id/driver_override
        if [ -e /sys/bus/pci/devices/$id/driver ]; then
            echo $id > /sys/bus/pci/devices/$id/driver/unbind
        fi
        # Reset the device before handing back to nvidia (avoids ENODEV after VFIO)
        if [ -e /sys/bus/pci/devices/$id/reset ]; then
            echo 1 > /sys/bus/pci/devices/$id/reset
        fi
        echo $id > /sys/bus/pci/drivers/$NVIDIA_DRIVER/bind
    done
}

case "$1" in
    bind)   bind_vfio ;;
    unbind) unbind_vfio ;;
esac
