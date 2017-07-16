all: pcap_test

pcap_test: main.o
	gcc -o pcap_test main.o -lpcap

clean:
	rm -f pcap_test
	rm -f *.o

