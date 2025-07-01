#! /bin/sh

###########################################################################
export PATH=$PATH:/opt/buildroot-gcc463/usr/bin
ARCH=mipsel-linux
COMPILER=/opt/buildroot-gcc463/usr/bin/mipsel-linux

###########################################################################

#
rm -rf bin
mkdir lib bin

# if [ ! -d  libnl-3.2.25 ]; then
	# tar xfz ../libnl-3.2.25.tar.gz
	# cd libnl-3.2.25
	# ./configure CFLAGS="-ffunction-sections -fdata-sections" --host=${ARCH} --prefix=$(pwd)/lib --enable-shared --enable-static CC=${COMPILER}-gcc
	# make clean;make;cd -
# fi
# cp -fv libnl-3.2.25/lib/.libs/libnl-3.a       lib/libnl-3.a
# cp -fv libnl-3.2.25/lib/.libs/libnl-genl-3.a  lib/libnl-genl-3.a

#
cd ../test_app;make clean;make CC=${COMPILER}-gcc all;cd -
mv -fv ../test_app/bin/*  bin/

#
# cd hostapd-2.6/hostapd
# make clean; make CC=${COMPILER}-gcc STRIP=${COMPILER}-strip; cd -
# cp -fv hostapd-2.6/hostapd/hostapd          bin/hostapd
# cp -fv hostapd-2.6/hostapd/hostapd_cli      bin/hostapd_cli

#
# cd wpa_supplicant-2.6/wpa_supplicant
# make clean; make CC=${COMPILER}-gcc STRIP=${COMPILER}-strip; cd -
# cp -fv wpa_supplicant-2.6/wpa_supplicant/wpa_supplicant bin/wpa_supplicant
# cp -fv wpa_supplicant-2.6/wpa_supplicant/wpa_passphrase bin/wpa_passphrase
# cp -fv wpa_supplicant-2.6/wpa_supplicant/wpa_cli        bin/wpa_cli
