CURRENT_PATH := $(shell pwd)

#Hi3516
#ARCH := arm
#COMPILER := arm-himix100-linux-
#LINUX_KERNEL_PATH := /home/matt/Hi3516/Hi3516EV200_SDK_V1.0.0.1/osdrv/opensource/kernel/linux-4.9.y

#Hi3518
#ARCH := arm
#COMPILER := arm-hisiv300-linux-uclibcgnueabi-
#LINUX_KERNEL_PATH := /home/matt/Hi3518/hi3518/linux-3.4.y

#FH8852
#ARCH := arm
#COMPILER := arm-fullhan-linux-uclibcgnueabi-
#LINUX_KERNEL_PATH := $(CURRENT_PATH)/../linux-3.0.8
#CFLAGS += -DFH8852 -DCONFIG_USB_ZERO_PACKET

#Hi3536d
#ARCH := arm
#COMPILER := arm-hisiv510-linux-uclibcgnueabi-
#LINUX_KERNEL_PATH := /home/matt/Hi3536d/Hi3536DV100_SDK_V1.0.2.0/osdrv/opensource/kernel/linux-4.9.y

#OpenWRT MT7628
#ARCH := mips
#COMPILER := /home/matt/openwrt/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-7.3.0_musl/bin/mipsel-openwrt-linux-
#LINUX_KERNEL_PATH := /home/matt/openwrt/openwrt/build_dir/target-mipsel_24kc_musl/linux-ramips_mt76x8/linux-4.14.151
#export STAGING_DIR = $(COMPILER)

#MTK SDK
ARCH := mips
COMPILER := /opt/buildroot-gcc463/usr/bin/mipsel-linux-
LINUX_KERNEL_PATH := $(CURRENT_PATH)/../source/linux-3.10.14.x

#Raspberry Pi
#ARCH := arm
#LINUX_KERNEL := $(shell uname -r)
#LINUX_KERNEL_PATH := /usr/src/linux-headers-$(LINUX_KERNEL)

#################################################################################################
#CFLAGS += -DCONFIG_HGIC_AH
#export CONFIG_HGIC_AH = y

CFLAGS += -DCONFIG_HGIC_2G
export CONFIG_HGIC_2G = y

#CFLAGS += -DCONFIG_HGIC_STABR
#export CONFIG_HGIC_STABR = y

CFLAGS += -DCONFIG_SDIO_REINIT

#主控的DMA对齐要求: 4字节对齐或更多
#CFLAGS += -DSDIO_DMA_ALIGN=4 -DUSB_DMA_ALIGN=4

help: 
	@echo "--------------------------------------------------------------------------------------"
	@echo "usage:"
	@echo "    make smac     : compile SMAC driver. support sdio/usb interface.  generate hgics.ko"
	@echo "    make smac_usb : compile SMAC driver. only support usb interface.  generate hgics.ko"
	@echo "    make smac_sdio: compile SMAC driver. only support sdio interface. generate hgics.ko"
	@echo ""
	@echo "    make fmac     : compile FMAC driver. support sdio/usb interface.  generate hgicf.ko"
	@echo "    make fmac_usb : compile FMAC driver. only support usb interface.  generate hgicf.ko"
	@echo "    make fmac_sdio: compile FMAC driver. only support sdio interface. generate hgicf.ko"
	@echo ""
	@echo "    make clean"
	@echo "--------------------------------------------------------------------------------------"

prepare:
	mkdir -p ko

smac: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_smac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICS=m CONFIG_HGIC_USB=y CONFIG_HGIC_SDIO=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_SDIO  -DCONFIG_HGIC_USB" modules
	cp -f hgic_smac/hgics.ko ko/hgics.ko
	$(COMPILER)strip -g ko/hgics.ko

smac_usb: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_smac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICS=m CONFIG_HGIC_USB=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_USB" modules
	cp -f hgic_smac/hgics.ko ko/hgics.ko
	$(COMPILER)strip -g ko/hgics.ko	

smac_sdio: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_smac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICS=m CONFIG_HGIC_SDIO=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_SDIO" modules
	cp -f hgic_smac/hgics.ko ko/hgics.ko
	$(COMPILER)strip -g ko/hgics.ko

fmac: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_fmac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICF=m CONFIG_HGIC_USB=y CONFIG_HGIC_SDIO=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_SDIO  -DCONFIG_HGIC_USB" modules
	cp -f hgic_fmac/hgicf.ko ko/hgicf.ko
	$(COMPILER)strip -g ko/hgicf.ko

fmac_usb: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_fmac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICF=m CONFIG_HGIC_USB=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_USB" modules
	cp -f hgic_fmac/hgicf.ko ko/hgicf.ko
	$(COMPILER)strip -g ko/hgicf.ko

fmac_sdio: prepare
	$(MAKE) -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/hgic_fmac ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) CONFIG_HGICF=m CONFIG_HGIC_SDIO=y EXTRA_CFLAGS="$(CFLAGS) -DCONFIG_HGIC_SDIO" modules
	cp -f hgic_fmac/hgicf.ko ko/hgicf.ko
	$(COMPILER)strip -g ko/hgicf.ko

clean: 
	@find ./ -name "*.o" | xargs rm -fv
	@find ./ -name "*.ko" | xargs rm -fv
	@find ./ -name "*.cmd" | xargs rm -fv
	@find ./ -name "*.symvers" | xargs rm -fv
	@find ./ -name "*.markers" | xargs rm -fv
	@find ./ -name "*.order" | xargs rm -fv
	@find ./ -name "*.mod.c" | xargs rm -fv
	@rm -rf ko
