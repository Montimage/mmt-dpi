all: gen-s1ap gen-ngap

#we firstly output to common
# then move the S1AP_ files to ./s1ap
gen-s1ap: common
	ASN1C_PREFIX=S1AP_ asn1c -D ./common -pdu=all -fcompound-names -findirect-choice -no-gen-example ./support/s1ap-r16.1.0/36413-g10.asn
	mkdir ./s1ap
	mv ./common/S1AP_* ./s1ap

gen-ngap: common
	ASN1C_PREFIX=NGAP_ asn1c -D ./common -pdu=all -fcompound-names -findirect-choice -no-gen-example ./support/ngap-r16.1.0/38413-g10.asn
	mkdir ./ngap
	mv ./common/NGAP_* ./ngap

common:
	mkdir $@
	
clean:
	rm -rf common ngap s1ap