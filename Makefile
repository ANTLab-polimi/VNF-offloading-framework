all: srv6

srv6: srv6.p4
	p4c-bm2-ss --arch v1model -o srv6.json \
		--p4runtime-files srv6_p4info.txt \
		srv6.p4
