# Install ASN1C: https://github.com/vlm/asn1c/blob/master/INSTALL.md
#
# The generator version is pinned in ./ASN1C_VERSION (machine-readable);
# .github/workflows/asn1c-regen.yml rebuilds that exact toolchain and
# re-runs the targets below on a weekly schedule, failing if the output
# drifts from this committed tree (issue #223). Never hand-edit the
# generated sources — bump the pin or change this recipe instead.
#
# The recipe applies no patch: the #513 runtime backports (GHSA-x882-jvjm-xxh9,
# GHSA-rcj5-gcvg-x796) are upstream fixes the pinned v1.5.3 skeletons carry,
# so they were dropped with the pin bump (issue #522).
#
# asn1c -version
# ASN.1 Compiler, v1.5.3-0-ge6c2799a-2026-10-07 (https://github.com/mouse07410/asn1c/issues)
# (mouse07410/asn1c @ e6c2799a, tag v1.5.3; the version string is stamped
# by the build recipe, see ./ASN1C_VERSION)
#
# Codec flags (issue #521): v1.5.x generates every codec by default and
# split the old -gen-PER into -gen-UPER/-gen-APER. The dissectors decode
# aligned PER only (aper_decode), so the recipe asks for -gen-APER and turns
# off the codecs nothing here uses: UPER (which 0.9.29's -gen-PER emitted
# alongside APER) and the new JER and CBOR. BER, XER (XER_FPRINT under
# DEBUG), OER, print and random-fill stay as before.
ASN1C_CODECS := -gen-APER -no-gen-UPER -no-gen-JER -no-gen-CBOR


all: gen-s1ap gen-ngap
common:
	mkdir -p common

#2 steps:
# - Generate all files to ./common
# - Move sepcific (S1ap) files to ./s1ap
gen-s1ap: common
	asn1c -D ./common $(ASN1C_CODECS) -pdu=all -fcompound-names -fno-include-deps -no-gen-example ./support/s1ap-r10.5.0/S1AP-CommonDataTypes.asn ./support/s1ap-r10.5.0/S1AP-Constants.asn ./support/s1ap-r10.5.0/S1AP-IEs.asn ./support/s1ap-r10.5.0/S1AP-PDU.asn
	mkdir -p ./s1ap
	mv -f ./common/S1ap* ./common/Makefile* ./s1ap

gen-ngap: common
	ASN1C_PREFIX=NGAP_ asn1c -D ./common $(ASN1C_CODECS) -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-example ./support/ngap-r15.2.0/*.asn1
	mkdir -p ./ngap
	mv -f ./common/NGAP_* ./common/Makefile* ./ngap

clean:
	rm -rf common ngap s1ap
