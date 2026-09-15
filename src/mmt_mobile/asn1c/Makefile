# Install ASN1C: https://github.com/vlm/asn1c/blob/master/INSTALL.md
#
# The generator version is pinned in ./ASN1C_VERSION (machine-readable);
# .github/workflows/asn1c-regen.yml rebuilds that exact toolchain and
# re-runs the targets below on a weekly schedule, failing if the output
# drifts from this committed tree (issue #223). Never hand-edit the
# generated sources — bump the pin or change this recipe instead.
#
# asn1c -version
# ASN.1 Compiler, v0.9.29 (mouse07410/asn1c @ dbd0ed09, branch vlm_master)


all: gen-s1ap gen-ngap
common:
	mkdir -p common

#2 steps:
# - Generate all files to ./common
# - Move sepcific (S1ap) files to ./s1ap
gen-s1ap: common
	asn1c -D ./common -gen-PER  -pdu=all -fcompound-names -fno-include-deps -no-gen-example ./support/s1ap-r10.5.0/S1AP-CommonDataTypes.asn ./support/s1ap-r10.5.0/S1AP-Constants.asn ./support/s1ap-r10.5.0/S1AP-IEs.asn ./support/s1ap-r10.5.0/S1AP-PDU.asn
	mkdir -p ./s1ap
	mv -f ./common/S1ap* ./common/Makefile* ./s1ap

gen-ngap: common
	ASN1C_PREFIX=NGAP_ asn1c -D ./common  -gen-PER -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example ./support/ngap-r15.2.0/*.asn1
	mkdir -p ./ngap
	mv -f ./common/NGAP_* ./common/Makefile* ./ngap

clean:
	rm -rf common ngap s1ap
