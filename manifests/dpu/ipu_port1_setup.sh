# This script needs to be run on reboot each time in order for P1 to be used as the primary interface via enp0s1f0d5
echo "Configure enp0s1f0d5 as designated primary network interface to Microshift OVS"
echo "#Add to VSI Group 1 :  enp0s1f0d5 [vsi: 0x0C]"
devmem 0x20292002a0 64 0x800005000000000c
devmem 0x2029200388 64 0x1
devmem 0x20292002a0 64 0xa00005000000000c