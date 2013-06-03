#!/bin/bash

set -x


STARTCOMMIT="96fbd7de3656583d647c204c"
ENDCOMMIT="paravirt"
OUTPUT=patch.diff

PATCHED_FILES=$(git diff --stat $STARTCOMMIT $ENDCOMMIT | awk '{print $1}' | sed '/BSD/d' | tr "\n" " ")
git diff $STARTCOMMIT $ENDCOMMIT -- ${PATCHED_FILES} > $OUTPUT
