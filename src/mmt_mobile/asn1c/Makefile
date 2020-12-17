all: gen-ngap

gen-ngap:
	mkdir ./ngap
	ASN1C_PREFIX=NGAP_ asn1c -D ./ngap -pdu=all -fcompound-names -findirect-choice -no-gen-example ./support/ngap-r16.1.0/38413-g10.asn

common:
	mkdir $@
	
clean:
	rm -rf ngap