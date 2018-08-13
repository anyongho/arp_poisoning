all : arp_spoofing

arp_spoofing : main.o
	gcc -o arp_spoofing main.o -lpcap

main.o : 
	gcc -c -o main.o main.c

clean :
	rm -f arp_spoofing
	rm -f *.o