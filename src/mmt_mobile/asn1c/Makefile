# Install ASN1C: https://github.com/vlm/asn1c/blob/master/INSTALL.md
# HN:
# asn1c -v
# ASN.1 Compiler, v0.9.29
# Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info> and contributors.


all: gen-s1ap gen-ngap
common:
	mkdir common

#2 steps:
# - Generate all files to ./common
# - Move sepcific (S1ap) files to ./s1ap
gen-s1ap: common
	asn1c -D ./common -gen-PER  -pdu=all -fcompound-names -fno-include-deps -no-gen-example ./support/s1ap-r10.5.0/S1AP-CommonDataTypes.asn ./support/s1ap-r10.5.0/S1AP-Constants.asn ./support/s1ap-r10.5.0/S1AP-IEs.asn ./support/s1ap-r10.5.0/S1AP-PDU.asn
	mkdir ./s1ap
	mv ./common/S1ap* ./common/Makefile* ./s1ap

gen-ngap:
	ASN1C_PREFIX=NGAP_ asn1c -D ./common  -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example ./support/ngap-r15.2.0/*.asn1
	mkdir ./ngap
	mv ./common/NGAP_* ./common/Makefile* ./ngap

clean:
	rm -rf common ngap s1ap
