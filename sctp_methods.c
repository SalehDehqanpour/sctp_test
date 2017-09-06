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
#include <time.h>
#include "timer.h"
#include "sctp_cli_p.h"

extern struct sockaddr_in servaddr;
extern unsigned int datalen;
extern unsigned long long n;
extern unsigned long c;
extern char* tcap_msg;
extern unsigned int reqs[MAX_THREADS]; 
extern unsigned int resps[MAX_THREADS];
extern unsigned int fails_total[MAX_THREADS];
extern unsigned int fails_timeout[MAX_THREADS];

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
   proto_data->SLS = sls;
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
//	reqs=(unsigned int*) malloc (MAX_THREADS * sizeof( int));
	int connSock, ret, flags;
	struct sctp_status status;
	unsigned long long i;

	unsigned char sctpPayload[MAX_BUFFER + 1]; //sctpPayload is payload of SCTP
	unsigned char sls;
	unsigned long threadNum = (unsigned long)rank;  //Thread number which is between 0 to (c-1)

	//---------------------------
	// M3UA:
	struct M3UA_common_header* M3UA_hdr = (struct M3UA_common_header*) sctpPayload;
	struct M3UA_param_header* M3UA_payload_hdr = (struct M3UA_param_header*) ((char*)M3UA_hdr + sizeof(struct M3UA_common_header));
	struct M3UA_protocol_data* M3UA_proto_data =  (struct M3UA_protocol_data* )((char*) M3UA_payload_hdr + sizeof(struct M3UA_param_header));

	M3UA_hdr->v = 1;
	M3UA_hdr->reserved = 0;
	M3UA_hdr->msg_class = M3UA_MSGC_TRANSFER;
	M3UA_hdr->msg_type = M3UA_TRANSFER_DATA;
	M3UA_hdr->len = swap_uint32(sizeof(struct M3UA_common_header)+sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);

	M3UA_payload_hdr->tag = swap_uint16(M3UA_PARAM_PROTO_DATA);
	M3UA_payload_hdr->len = swap_uint16(sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);

	M3UA_proto_data->OPC = swap_uint32(110);
	M3UA_proto_data->DPC = swap_uint32(100);
	M3UA_proto_data->SIO = 3;
	M3UA_proto_data->NI = 2;
	M3UA_proto_data->MP = 0;
	M3UA_proto_data->SLS = sls;

	//  SCCP:
	struct SCCP_hdr* sccp_header=(struct SCCP_hdr *)((char *)M3UA_proto_data + sizeof(struct M3UA_protocol_data));
	struct SCCP_party_addr* sccp_called = (struct SCCP_party_addr*)((char *)sccp_header + sizeof(struct SCCP_hdr));
	struct SCCP_party_addr* sccp_calling = (struct SCCP_party_addr*)((char *)sccp_called + sizeof(struct SCCP_party_addr));

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
    // TCAP:
	unsigned char *TCAP_start;//= (unsigned char *) malloc (TCAP_MESSAGE_SIZE * sizeof(char));
	TCAP_start=(char*)((char*) sccp_calling  + sizeof(struct SCCP_party_addr));
	initTCAP(TCAP_start);

    // Socket_section:
    for(i=0; i < n; i++){
		// setting the imei value
		TCAP_start[80] = 0x42;
		TCAP_start[81] = 0x11;
		TCAP_start[82] = 0x27;
		TCAP_start[83] = 0x38;
		TCAP_start[84] = 0x03;
		TCAP_start[85] = 0x68;
		TCAP_start[86] = 0x76;
		TCAP_start[87] = 0x89;

		connSock = socket (AF_INET, SOCK_STREAM, IPPROTO_SCTP);

		if (-1 == connSock)
			{
				printf("Socket creation failed\n");
				perror("socket()");
				continue;
			}


		ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

		if (-1 == ret)
			{
				printf("Connection failed\n");
				perror("connect()");
				close(connSock);
				continue;
			}

		ret = sctp_sendmsg (connSock, (void *) sctpPayload, (size_t) datalen, NULL, 0, swap_uint32(3), 0, 0, 0, 0);
		if(-1 == ret)
			{
				printf("Error in sctp_sendmsg\n");
				perror("sctp_sendmsg()");
			}
		else
			reqs[threadNum]++;
	
		struct sctp_sndrcvinfo sndrcvinfo;
		char rcv_buffer[MAX_BUFFER];
		int recv_in = -1;


		while (-1 == recv_in)
				recv_in = sctp_recvmsg (connSock, rcv_buffer, sizeof (rcv_buffer), (struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);

		sctpPayload[recv_in] = '\0';
		printf (" Length of Data received: %d\n", recv_in);
		close(connSock);
    }

    return 0;
}






void initTCAP (unsigned char* TCAP_start) {
	TCAP_start[0] = 0x57;
	TCAP_start[1] = 0x62;
	TCAP_start[2] = 0x55;
	TCAP_start[3] = 0x48;
	TCAP_start[4] = 0x04;
	TCAP_start[5] = 0x8a;
	TCAP_start[6] = 0x40;
	TCAP_start[7] = 0x00;
	TCAP_start[8] = 0x01;
	TCAP_start[9] = 0x6b;
	TCAP_start[10] = 0x39;
	TCAP_start[11] = 0x28;
	TCAP_start[12] = 0x37;
	TCAP_start[13] = 0x06;
	TCAP_start[14] = 0x07;
	TCAP_start[15] = 0x00;
	TCAP_start[16] = 0x11;
	TCAP_start[17] = 0x86;
	TCAP_start[18] = 0x05;
	TCAP_start[19] = 0x01;
	TCAP_start[20] = 0x01;
	TCAP_start[21] = 0x01;
	TCAP_start[22] = 0xa0;
	TCAP_start[23] = 0x2c;
	TCAP_start[24] = 0x60;
	TCAP_start[25] = 0x2a;
	TCAP_start[26] = 0x80;
	TCAP_start[27] = 0x02;
	TCAP_start[28] = 0x07;
	TCAP_start[29] = 0x80;
	TCAP_start[30] = 0xa1;
	TCAP_start[31] = 0x09;
	TCAP_start[32] = 0x06;
	TCAP_start[33] = 0x07;
	TCAP_start[34] = 0x04;
	TCAP_start[35] = 0x00;
	TCAP_start[36] = 0x00;
	TCAP_start[37] = 0x01;
	TCAP_start[38] = 0x00;
	TCAP_start[39] = 0x0d;
	TCAP_start[40] = 0x02;
	TCAP_start[41] = 0xbe;
	TCAP_start[42] = 0x19;
	TCAP_start[43] = 0x28;
	TCAP_start[44] = 0x17;
	TCAP_start[45] = 0x06;
	TCAP_start[46] = 0x07;
	TCAP_start[47] = 0x04;
	TCAP_start[48] = 0x00;
	TCAP_start[49] = 0x00;
	TCAP_start[50] = 0x01;
	TCAP_start[51] = 0x01;
	TCAP_start[52] = 0x01;
	TCAP_start[53] = 0x01;
	TCAP_start[54] = 0xa0;
	TCAP_start[55] = 0x0c;
	TCAP_start[56] = 0xa0;
	TCAP_start[57] = 0x0a;
	TCAP_start[58] = 0x80;
	TCAP_start[59] = 0x08;
	TCAP_start[60] = 0x86;
	TCAP_start[61] = 0x48;
	TCAP_start[62] = 0x63;
	TCAP_start[63] = 0x18;
	TCAP_start[64] = 0x29;
	TCAP_start[65] = 0x93;
	TCAP_start[66] = 0x19;
	TCAP_start[67] = 0x83;
	TCAP_start[68] = 0x6c;
	TCAP_start[69] = 0x12;
	TCAP_start[70] = 0xa1;
	TCAP_start[71] = 0x10;
	TCAP_start[72] = 0x02;
	TCAP_start[73] = 0x01;
	TCAP_start[74] = 0x01;
	TCAP_start[75] = 0x02;
	TCAP_start[76] = 0x01;
	TCAP_start[77] = 0x2b;
	TCAP_start[78] = 0x04;
	TCAP_start[79] = 0x08;
	TCAP_start[80] = 0x42;
	TCAP_start[81] = 0x11;
	TCAP_start[82] = 0x27;
	TCAP_start[83] = 0x38;
	TCAP_start[84] = 0x03;
	TCAP_start[85] = 0x68;
	TCAP_start[86] = 0x76;
	TCAP_start[87] = 0x89;
	TCAP_start[88] = 0x00;
	TCAP_start[89] = 0x00;
	TCAP_start[90] = 0x00;
}


void* req_handle(void* N) {
	memset(reqs,0,MAX_THREADS);
	memset(resps,0,MAX_THREADS);
	memset(fails_total,0,MAX_THREADS);
	memset(fails_timeout,0,MAX_THREADS);
 	struct timeval tv;
	unsigned int min=0,max=0,total=0,s_count=0;
	unsigned int i=0;
	int prev_reqs[MAX_THREADS];
	int current_reqs;
	memset(prev_reqs,0,MAX_THREADS);
	while ( total < (unsigned long long)N ) {
		sleep(1);
		for (i=0; i<c; i++)  {
			current_reqs += (reqs[i] - prev_reqs[i]);
			prev_reqs[i] = reqs[i];
		}
		if (current_reqs < min && current_reqs != 0) min = current_reqs;
		if (current_reqs > max  ) max = current_reqs;
		s_count++; // a counter for seconds
		total += current_reqs;
		if (!current_reqs) break;
		current_reqs=0;
	}
	double avg= total / s_count;
	printf ("\n\nTotal:\t\t\t%d\nAverage:\t%g\nmin:\t\t\t%d\nmax:\t\t\t%d\n",total,avg,min,max);
}