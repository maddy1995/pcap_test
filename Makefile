test: test.o
	gcc -o test test.o -lpcap

test.o: test1.c
	gcc -c -o test.o test1.c -lpcap

clean: rm *.o test
