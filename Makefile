pcap: main.o
	gcc -o pcap main.o-lpcap

main.o: main.c 
	gcc -c -o main.o main.c -lpcap

clean: rm *.o pcap
