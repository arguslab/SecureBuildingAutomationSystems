make clean
make c1_defconfig
make
arm-linux-gnueabi-objcopy --input-format=elf32-littlearm --output-format=binary -R.scratch images/sos-image-arm-imx6  ~/shared/sel4bins/c1.bin

make clean
make c2_defconfig
make
arm-linux-gnueabi-objcopy --input-format=elf32-littlearm --output-format=binary -R.scratch images/sos-image-arm-imx6  ~/shared/sel4bins/c2.bin

make clean
make c1_attack_defconfig
make
arm-linux-gnueabi-objcopy --input-format=elf32-littlearm --output-format=binary -R.scratch images/sos-image-arm-imx6  ~/shared/sel4bins/c1-attack.bin
