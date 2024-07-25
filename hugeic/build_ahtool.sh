#! /bin/sh

rm -rf bin; mkdir bin
cd tools/ah_tool/;./build.sh;cd -
cp -fv tools/ah_tool/bin/* bin
