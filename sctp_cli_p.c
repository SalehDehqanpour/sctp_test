// sctp_cli.c
// Protocol Stack that is implemented : SCTP/M3UA/SCCP/TCAP/GSM_MAP
// Hint: The identifiers which are in upper CASE are data types.(like SCCP_party_addr). The lower ones are objects.(like sccp_called)
// To compile: gcc -O2 sctp_cli_p.c sctp_methods.c -lsctp -lpthread -o p.out
// To run: ./p.out <your dest IP e.g. 172.17.0.10> <your dest port e.g. 2905> <number of total checkIMEI> <number of parallel threads>
// for example: ./p.out 127.0.0.1 62324 10 2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "timer.h"  // It has GET_TIME macro.
#include "sctp_cli_p.h"

uint16_t swap_uint16( uint16_t val ) 
{
    return (val << 8) | (val >> 8 );
}

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

struct sockaddr_in servaddr;
unsigned int datalen = 0; 
unsigned long long n=0;
char tcap_msg[TCAP_MESSAGE_SIZE]= {0x57,0x62,0x55,0x48,0x04,0x8a,0x40,0x00,0x01,0x6b,0x39,0x28,0x37,0x06,0x07,0x00,0x11,0x86,0x05,0x01,0x01,
0x01,0xa0,0x2c,0x60,0x2a,0x80,0x02,0x07,0x80,0xa1,0x09,0x06,0x07,0x04,0x00,0x00,0x01,0x00,0x0d,0x02,0xbe,0x19,0x28,0x17,
0x06,0x07,0x04,0x00,0x00,0x01,0x01,0x01,0x01,0xa0,0x0c,0xa0,0x0a,0x80,0x08,0x86,0x48,0x63,0x18,0x29,0x93,0x19,0x83,0x6c,0x12,
0xa1,0x10,0x02,0x01,0x01,0x02,0x01,0x2b,0x04,0x08,0x42,0x11,0x27,0x38,0x03,0x68,0x76,0x89,0x00,0x00,0x00}; //padding zeros  
// first octet is length of TCAP (excluding itself)
// IMEI is last octets : 0x42,0x11,0x27,0x38,0x03,0x68,0x76,0x89

int main (int argc, char* argv[])
{
    if (argc != 5) {
        fprintf(stderr, "We need 4 positional parameter: IP, PORT, # of total checkIMEIs, # of threads\n");
        return 1;
        }
    char IP_dest[15];
    strcpy(IP_dest,argv[1]);
    int MY_PORT_NUM=atoi(argv[2]);
    unsigned long long N;
    unsigned long c;

    double t1,t2; // they store time values to measure performance
    N=atoi(argv[3]);
    c=atoi(argv[4]);
    n=N/c;


    datalen = sizeof(struct M3UA_common_header)+sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)
        + sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE;
    //initializing servaddr
    bzero ((void *) &servaddr, sizeof (servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons (MY_PORT_NUM);
    servaddr.sin_addr.s_addr = inet_addr (IP_dest);

    pthread_t* handles = (pthread_t*) malloc (c*sizeof(pthread_t));
    long j;
    GET_TIME(t1);
    for (j=0; j<c; j++)  {
        pthread_create( &handles[j], NULL, handle_client, (void*)j );  
    }
    for (j=0; j<c; j++) 
    pthread_join(handles[j], NULL); 

    GET_TIME(t2);
    printf("\nResult = %g #/sec \n", N/(t2-t1));      
            
} 


