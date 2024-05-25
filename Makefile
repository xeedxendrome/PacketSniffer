execute: 
	gcc src/sniffermain.c functions/session_creation.c functions/payload_print.c functions/udp_processing.c functions/tcp_processing.c functions/hex_decimal_payload.c  -lpcap -o sniffer
	