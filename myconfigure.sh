#!/bin/bash

#set -x

NETMAP="--enable-netmap --extra-cflags=-I/home/vmaffione/git/lettieri/netmap-release/sys"
E1000PARA="--enable-e1000-paravirt"

./configure --target-list=x86_64-softmmu --enable-kvm --enable-vhost-net --python=python2 --disable-werror --enable-debug ${NETMAP} ${E1000PARA}
