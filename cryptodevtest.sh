#!/bin/sh

FPC=fpc
FPC_OPTS=

GCC=gcc
GCC_OPTS=

# Some filenames
PAS_EXE="./crtest-pas"
C_EXE="./crtest-c"

PAS_RES="./crtest-pas.result"
C_RES="./crtest-c.result"

# Build and compare!
$FPC $FPC_OPTS cryptodevtest.pas -o$PAS_EXE
$GCC $GCC_OPTS cryptodevtest.c   -o$C_EXE

$PAS_EXE >$PAS_RES
$C_EXE >$C_RES

echo "======================================================="
DIFF=`diff $PAS_RES $C_RES`

if [ "$DIFF" != "" ]; then
    echo "Results differ!"
    echo "$DIFF"
    exit 1
fi
echo "Results identical, OK."

# Cleanup
rm $C_EXE $PAS_EXE $C_RES $PAS_RES
