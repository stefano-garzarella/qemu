#!/bin/bash

set -x

# make a QEMU-PATCH

STARTCOMMIT="96fbd7de3656583d647c204c"
ENDCOMMIT="paravirt"
OUTPUT=patch.diff

EXCLUDED_FILES="e1000-paravirt-README patch.sh hw\/dma\/pl330 util\/hexdump.c util\/iov.c qemu-v1.5.0.diff.txt"
PATCHED_FILES=$(git diff --stat $STARTCOMMIT $ENDCOMMIT | awk '{print $1}' | sed '$d' |  sed '/BSD/d' | sed '/virtio/d' | tr "\n" " ")

# remove excluded files from "PATCHED_FILES"
for f in ${EXCLUDED_FILES}; do
    PATCHED_FILES=$(echo ${PATCHED_FILES} | sed "s/$f//")
done

# generate the patch
git diff $STARTCOMMIT $ENDCOMMIT -- ${PATCHED_FILES} > $OUTPUT
