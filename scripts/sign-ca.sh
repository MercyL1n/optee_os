#! /bin/sh
############################################################
SRC=$(cd $(dirname "$0"); pwd)

CROSS_COMPILE=~/optee/optee/toolchains/aarch64/bin/aarch64-linux-gnu-
CA_AUTH_KEY=~/optee/optee/optee_os/keys/default_ta.pem
DEMO_PASSCODE=~/optee/optee/optee_os/scripts/demo_passkey.txt

OBJCOPY=${CROSS_COMPILE}objcopy
OBJDUMP=${CROSS_COMPILE}objdump
SIGN_CA_PATH=${SRC}

InFile=$1
OutFile=$2


echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@ signing $1"

ca_signing_script=${SIGN_CA_PATH}/sign-ca.py

python $ca_signing_script --key $CA_AUTH_KEY --passcode $DEMO_PASSCODE \
	 --in $InFile --out $InFile.caauth
${OBJCOPY} --add-section .caauth_sec=$InFile.caauth \
	--set-section-flags .caauth_sec=noload,readonly $InFile $InFile.signed
mv $InFile.signed $OutFile
rm $InFile.caauth