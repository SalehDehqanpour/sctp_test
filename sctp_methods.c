// sctp_methods.c
// This file is associated with sctp_cli_p.c
// To compile: gcc -O2 sctp_cli_p.c sctp_methods.c -lsctp -lpthread -o p.out

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
#include "timer.h"
#include "sctp_cli_p.h"

extern struct sockaddr_in servaddr;
extern unsigned int datalen; 
extern unsigned long long n;
extern char* tcap_msg;


void M3UA_Set (struct M3UA_common_header* hdr, struct M3UA_param_header* payload_hdr, struct M3UA_protocol_data* proto_data, uint8_t sls){
   hdr->v = 1;
   hdr->reserved = 0;
   hdr->msg_class = M3UA_MSGC_TRANSFER;
   hdr->msg_type = M3UA_TRANSFER_DATA;
   hdr->len = swap_uint32(sizeof(struct M3UA_common_header)+sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);

   payload_hdr->tag = swap_uint16(M3UA_PARAM_PROTO_DATA);
   payload_hdr->len = swap_uint16(sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);
    
   proto_data->OPC = swap_uint32(110);
   proto_data->DPC = swap_uint32(100);
   proto_data->SIO = 3;
   proto_data->NI = 2;
   proto_data->MP = 0;
   proto_data ->  SLS = sls;
}



void SCCP_Set(struct SCCP_hdr* sccp_header,struct SCCP_party_addr* sccp_called,struct SCCP_party_addr* sccp_calling){
  sccp_header->msg_type = SCCP_MSG_TYPE_UDT;
  sccp_header->proto_class = SCCP_PROTO_CLASS;
  (sccp_header->ptr_to_var_mand)[0] = 3; // values of pointers obtained from PCAP which I have in hand.
  (sccp_header->ptr_to_var_mand)[1] = 10;// 10 = 2 + sizeof(struct SCCP_party_addr)
  (sccp_header->ptr_to_var_mand)[2] = 17; // 17 = 1 + 2* sizeof(struct SCCP_party_addr)
 
   sccp_called->addr_len = 7;
   sccp_called->reserved = 0;
   sccp_called->routing_indicator = 0;
   sccp_called->global_title_indicator = 4;
   sccp_called->ssn_indicator = 1;
   sccp_called->point_code_indicator = 0;
   sccp_called->sccp_subsystem_number = 9;
   sccp_called->sccp_translation_type = 0;
   sccp_called->NP = 1;
   sccp_called->ES = 2;
   sccp_called->NAI = 4;
   sccp_called->global_title_addr = swap_uint16(0x0110) ;  //WARNING: reverse nibbles in each octet to reach actual addr
  
   sccp_calling->addr_len = 7;
   sccp_calling->reserved = 0;
   sccp_calling->routing_indicator = 0;
   sccp_calling->global_title_indicator = 4;
   sccp_calling->ssn_indicator = 1;
   sccp_calling->point_code_indicator = 0;
   sccp_calling->sccp_subsystem_number= 8;
   sccp_calling->sccp_translation_type = 0;
   sccp_calling->NP = 1;
   sccp_calling->ES = 2;
   sccp_calling->NAI = 4;
   sccp_calling->global_title_addr = swap_uint16(0x1110);  //WARNING: reverse nibbles in each octet
}

void* handle_client(void* rank) {
    unsigned char sctpPayload[MAX_BUFFER + 1]; //sctpPayload is payload of SCTP
    unsigned char sls;
    unsigned int threadNum = *(unsigned int*)rank;  //Thread number which is between 0 to (c-1)

    //---------------------------  
    // M3UA: 
    struct M3UA_common_header* M3UA_hdr = (struct M3UA_common_header*) sctpPayload;
    struct M3UA_param_header* M3UA_payload_hdr = (struct M3UA_param_header*) ((char*)M3UA_hdr + sizeof(struct M3UA_common_header));
    struct M3UA_protocol_data* M3UA_proto_data =  (struct M3UA_protocol_data* )((char*) M3UA_payload_hdr + sizeof(struct M3UA_param_header));

    M3UA_Set(M3UA_hdr, M3UA_payload_hdr, M3UA_proto_data, (uint8_t)threadNum%16); //normally we have 16 links in a linkset so we use threadNum%16


    //  SCCP:
    struct SCCP_hdr* sccp_header=(struct SCCP_hdr *)((char *)M3UA_proto_data + sizeof(struct M3UA_protocol_data));
    struct SCCP_party_addr* sccp_called = (struct SCCP_party_addr*)((char *)sccp_header + sizeof(struct SCCP_hdr));
    struct SCCP_party_addr* sccp_calling = (struct SCCP_party_addr*)((char *)sccp_called + sizeof(struct SCCP_party_addr));

    SCCP_Set(sccp_header, sccp_called, sccp_calling);  


    // TCAP:  
    unsigned char *TCAP_start;
    TCAP_start = (char*) sccp_calling  + sizeof(struct SCCP_party_addr);
    memcpy(TCAP_start, tcap_msg, TCAP_MESSAGE_SIZE);


    // Socket_section:
    int connSock, ret, flags;
    struct sctp_status status;
    unsigned long long i;
    for(i=0; i < n; i++){
            
        // setting the imei value
        sctpPayload[80] = 0x42;
        sctpPayload[81] = 0x11;
        sctpPayload[82] = 0x27;
        sctpPayload[83] = 0x38;
        sctpPayload[84] = 0x03;
        sctpPayload[85] = 0x68;
        sctpPayload[86] = 0x76;
        sctpPayload[87] = 0x89;
        
        connSock = socket (AF_INET, SOCK_STREAM, IPPROTO_SCTP);
        
        if (connSock == -1)
            {
                printf("Socket creation failed\n");
                perror("socket()");
                exit(1);
            }
        
        
        ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));
        
        if (ret == -1)
            {
                printf("Connection failed\n");
                perror("connect()");
                close(connSock);
                exit(1);
            }
        
        ret = sctp_sendmsg (connSock, (void *) sctpPayload, (size_t) datalen, NULL, 0, swap_uint32(3), 0, 0, 0, 0);
        if(ret == -1 )
            {
                printf("Error in sctp_sendmsg\n");
                perror("sctp_sendmsg()");
            }
        else
                printf("Successfully sent %d bytes data to server\n", ret);
        
        struct sctp_sndrcvinfo sndrcvinfo;
        char rcv_buffer[MAX_BUFFER];
        int recv_in=-1;
        
        
        while (recv_in == -1) 
                recv_in = sctp_recvmsg (connSock, rcv_buffer, sizeof (rcv_buffer), (struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);

        sctpPayload[recv_in] = '\0';
        printf (" Length of Data received: %d\n", recv_in);
        int ii=0;
        for(; ii < recv_in; ii++) 
                printf("\nthread:%d\toctet no.:%d\t0x%02X",threadNum,ii,(unsigned char)rcv_buffer[ii]);

        close (connSock); 

    }

    return 0;
}
