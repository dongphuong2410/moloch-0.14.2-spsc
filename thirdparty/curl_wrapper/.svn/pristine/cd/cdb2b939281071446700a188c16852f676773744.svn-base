#!/bin/sh
CURL_VER=7.37.1
CURL_DIR="curl-$CURL_VER"

pushd lib/$CURL_DIR
./configure && popd

make -C lib/$CURL_DIR
make -C src
