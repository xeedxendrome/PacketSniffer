execute: 
	gcc src/tcpsniffer.c functions/session_creation.c functions/payload_print.c functions/udp_processing.c functions/tcp_processing.c  -lpcap -o tcpsniffer
	./tcpsniffer