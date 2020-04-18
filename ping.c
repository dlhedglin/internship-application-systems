/*
References used:
    https://courses.cs.vt.edu/cs4254/fall04/slides/raw_1.pdf
    https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
    http://squidarth.com/networking/systems/rc/2018/05/28/using-raw-sockets.html
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include<time.h>
#define SIZE 64

// taken from https://www.geeksforgeeks.org/ping-in-c/
// Calculating the Check Sum 
unsigned short checksum(void *b, int len) 
{    unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
}


struct icmpPacket {
    struct icmphdr hdr;
    char data[SIZE];
};


int main(int argc, char *argv[]){
    if (argc < 2) {
        printf("%s", "Usage: [host]\n");
        exit(1);
	}

    struct addrinfo *res, *p;
    struct sockaddr_in *addr;
    struct sockaddr_in *recvaddr;
    struct sockaddr_in source_socket_address, dest_socket_address;
    char ipstr[INET6_ADDRSTRLEN];
    int status;


    //Create a raw socket using ICMP and check for errors.
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(s < 0){
        printf("Socket file descriptor error\n");
        return 0;
    }


    int loss = 0;
    int seq = 0;
    struct timeval start,end;
    while(1){
        //Perform a DNS lookup on our hostname if given, else just give us the ip
        // stores a linked list to addrinfo structs in res
        if ((status = getaddrinfo(argv[1], NULL, 0, &res)) != 0) {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
            return 2;
        }
        //return a sockaddr_in with info about our given ip address
        for(p = res;p != NULL; p = p->ai_next) {
            if (p->ai_family == AF_INET) { // IPv4
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                addr = ipv4;
            } 
        }
        freeaddrinfo(res);

        //Create our ICMP packet and fill in the basic header info
        struct icmpPacket packet;
        packet.hdr.type = ICMP_ECHO;
        packet.hdr.un.echo.id = getpid();
        packet.hdr.un.echo.sequence = seq++;
        packet.hdr.code = 0;
        packet.hdr.checksum = 0;
        packet.hdr.checksum = checksum(&packet, sizeof(packet));

        //convert our sin_addr into an ip string and print it
        inet_ntop(AF_INET, &addr->sin_addr, ipstr, sizeof ipstr);
        printf("PING %s (%s) 64 bytes\n", argv[1], ipstr);

        //get a timestamp of when we sent our packet for RTT
        gettimeofday(&start,NULL);

        //Send packet to the ip inside our addr struct and check for errors.
        if(sendto(s, &packet, sizeof(packet), 0, (struct sockaddr*)addr, sizeof(struct sockaddr)) <= 0){
            printf("failed to send packet\n");
            perror("sendto Error");
            close(s);
            exit(EXIT_FAILURE);
            return 0;
        }

        //Create a buffer to hold the response packet
        unsigned char *buffer = (unsigned char *) malloc(65536);
        memset(buffer,0,65536);
        socklen_t fromlen = sizeof recvaddr;

        //Wait for either Destinaton unreachable packet or an echo reply and store it in buffer
        if(recvfrom(s, buffer, 65536, 0, (struct sockaddr*)recvaddr, &fromlen) <= 0){
                perror("recvfrom Error");
                close(s);
                exit(EXIT_FAILURE);
        }
        //create timestamp for RTT;
        gettimeofday(&end,NULL);
        double t1 = 0.0;
        double t2 = 0.0;
        t1+=start.tv_sec+(start.tv_usec/10000.0);
        t2+=end.tv_sec+(end.tv_usec/10000.0);


        //Extract ip header from our recieved packet
        struct iphdr *ip_packet = (struct iphdr *)buffer;

        //increment buffer pointer past size of ip header to extract ICMP header
        unsigned short iphdrlen = ip_packet->ihl*4;
        struct icmphdr *icmp_packet = (struct icmphdr*)(buffer + iphdrlen);

        //Store source and destination Adresses from ip header
        memset(&source_socket_address, 0, sizeof(source_socket_address));
        source_socket_address.sin_addr.s_addr = ip_packet->saddr;
        memset(&dest_socket_address, 0, sizeof(dest_socket_address));
        dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

        //if our recieved packet was a reply
        if(icmp_packet->type == ICMP_ECHOREPLY){
            printf("64 bytes From %s seq=%d ttl=%d rtt=%f ms loss=(%d/%d)\n", 
                (char *)inet_ntoa(source_socket_address.sin_addr), seq, ip_packet->ttl, (t2-t1), loss, seq);
            sleep(1);
        }
        else{
        //if our recieved packet was destination unreachable
            loss += 1;
            printf("From %s seq=%d Destination Host Unreachable loss=(%d/%d)\n", 
                (char *)inet_ntoa(source_socket_address.sin_addr), seq, loss, seq);
        }
    }
    close(s);
    return 0;
}