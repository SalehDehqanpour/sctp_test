// sctp_cli.c
// Protocol Stack that is implemented : SCTP/M3UA/SCCP/TCAP/GSM_MAP
// Hint: The identifiers which are in upper CASE are data types.(like SCCP_party_addr). The lower ones are objects.(like sccp_called)
// To compile: gcc sctp_cli.c -o client -lsctp
// To run: ./a.out <dest IP> <dest port>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#define MAX_BUFFER 4096

#define M3UA_MSGC_TRANSFER 1
#define M3UA_TRANSFER_DATA 1
#define M3UA_PARAM_PROTO_DATA 0x0210

#define SCCP_MSG_TYPE_UDT 9
#define SCCP_PROTO_CLASS 0x80 //0 0 0 0 class 0  || 1 0 0 0 return message on error
#define SCCP_SSN_EIC 9

#define TCAP_MESSAGE_SIZE 91 //including padding:91; not including: 88  (anyway including "0x57" (the length itself))

uint16_t swap_uint16( uint16_t val ) 
{
    return (val << 8) | (val >> 8 );
}

uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

struct M3UA_common_header {
  uint8_t  v;
  uint8_t  reserved;
  uint8_t  msg_class;
  uint8_t  msg_type;
  uint32_t len;
};

struct M3UA_param_header {
  uint16_t tag;
  uint16_t len;
};

struct M3UA_protocol_data {
  uint32_t  OPC;
  uint32_t  DPC;
  uint8_t  SIO;
  uint8_t  NI;
  uint8_t MP;
  uint8_t SLS;
};


struct SCCP_party_addr{//The sequence of bit fields is reversed intentionally to conform with standard
   	uint8_t addr_len;
    uint8_t	point_code_indicator : 1,
			ssn_indicator	     : 1,
			global_title_indicator : 4,
			routing_indicator    : 1,
			reserved	     : 1;// sccp_addr_ind;
    uint8_t sccp_subsystem_number;
    //global title: (maybe it could be better to encapsulate it in a struct)
    uint8_t sccp_translation_type;
    uint8_t ES:4,NP:4; //Numbering plan & encoding scheme. 
    uint8_t NAI; //Nature of address indicator
    uint16_t global_title_addr;    // WARNING: reverse nibbles in each octet
};

 struct SCCP_hdr { // Specific-purpose: Only for TCAP/GSM_MAP(checkIMEI) (It is not a general sccp header)
     uint8_t msg_type;
     uint8_t proto_class;
     uint8_t ptr_to_var_mand[3]; //Pointer to Mandatory Variable Parameters
      };

void M3UA_Set (struct M3UA_common_header*,struct M3UA_param_header* , struct M3UA_protocol_data*);
void SCCP_Set(struct SCCP_hdr*,struct SCCP_party_addr* ,struct SCCP_party_addr* );
 

int main (int argc, char* argv[])
{
	if (argc != 3) {
		fprintf(stderr, "We need two positional parameter: IP and PORT\n");
		return 1;
	}
	char IP_dest[15];
	strcpy(IP_dest,argv[1]);
	int MY_PORT_NUM=atoi(argv[2]);
	unsigned char sctpPayload[MAX_BUFFER + 1]; //sctpPayload is payload of SCTP
	int datalen = 0;


	//---------------------------  
	// M3UA: 
	struct M3UA_common_header* M3UA_hdr = (struct M3UA_common_header*) sctpPayload;
	struct M3UA_param_header* M3UA_payload_hdr = (struct M3UA_param_header*) ((char*)M3UA_hdr + sizeof(struct M3UA_common_header));
	struct M3UA_protocol_data* M3UA_proto_data =  (struct M3UA_protocol_data* )((char*) M3UA_payload_hdr + sizeof(struct M3UA_param_header));

	M3UA_Set(M3UA_hdr,M3UA_payload_hdr,M3UA_proto_data);

	//---------------------------
	//  SCCP:
	struct SCCP_hdr* sccp_header=(struct SCCP_hdr *)((char *)M3UA_proto_data + sizeof(struct M3UA_protocol_data));
	struct SCCP_party_addr* sccp_called = (struct SCCP_party_addr*)((char *)sccp_header + sizeof(struct SCCP_hdr ));
	struct SCCP_party_addr* sccp_calling = (struct SCCP_party_addr*)((char *)sccp_called + sizeof(struct SCCP_party_addr ));

	SCCP_Set(sccp_header,sccp_called,sccp_calling);  

	//---------------------------
	// TCAP:  
	char tempp[TCAP_MESSAGE_SIZE]= {0x57,0x62,0x55,0x48,0x04,0x8a,0x40,0x00,0x01,0x6b,0x39,0x28,0x37,0x06,0x07,0x00,0x11,0x86,0x05,0x01,0x01,
	0x01,0xa0,0x2c,0x60,0x2a,0x80,0x02,0x07,0x80,0xa1,0x09,0x06,0x07,0x04,0x00,0x00,0x01,0x00,0x0d,0x02,0xbe,0x19,0x28,0x17,
	0x06,0x07,0x04,0x00,0x00,0x01,0x01,0x01,0x01,0xa0,0x0c,0xa0,0x0a,0x80,0x08,0x86,0x48,0x63,0x18,0x29,0x93,0x19,0x83,0x6c,0x12,
	0xa1,0x10,0x02,0x01,0x01,0x02,0x01,0x2b,0x04,0x08,0x42,0x11,0x27,0x38,0x03,0x68,0x76,0x89,0x00,0x00,0x00}; //padding zeros  
	// first octet is length of TCAP (excluding itself)

	unsigned char *TCAP_start;
	TCAP_start = (char*) sccp_calling  + sizeof(struct SCCP_party_addr);
	memcpy(TCAP_start, tempp, TCAP_MESSAGE_SIZE);

	datalen = sizeof(struct M3UA_common_header)+sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)
			+ sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE;


	// Socket_section:
	int connSock, in, ret, flags;
	struct sockaddr_in servaddr;
	struct sctp_status status;
	connSock = socket (AF_INET, SOCK_STREAM, IPPROTO_SCTP);

	if (connSock == -1)
	{
		printf("Socket creation failed\n");
		perror("socket()");
		exit(1);
	}

	bzero ((void *) &servaddr, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons (MY_PORT_NUM);
	servaddr.sin_addr.s_addr = inet_addr (IP_dest);

	ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

	if (ret == -1)
	{
		printf("Connection failed\n");
		perror("connect()");
		close(connSock);
		exit(1);
	}

	ret = sctp_sendmsg (connSock, (void *) sctpPayload, (size_t) datalen, NULL, 0, 3, 0, 0, 0, 0);
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


	while (recv_in == -1) {
		recv_in = sctp_recvmsg (connSock, rcv_buffer, sizeof (rcv_buffer),(struct sockaddr *) NULL, 0, &sndrcvinfo, &flags);
		}
	sctpPayload[recv_in] = '\0';
	printf (" Length of Data received: %d\n", recv_in);
	int ii=0;
	for(;ii<recv_in;ii++) 
			printf("\n0x%02X", (unsigned char)rcv_buffer[ii]);

	close (connSock);

	return 0;
}



void M3UA_Set (struct M3UA_common_header* hdr, struct M3UA_param_header* payload_hdr, struct M3UA_protocol_data* proto_data){
   hdr->v=1;
   hdr->reserved=0;
   hdr->msg_class=M3UA_MSGC_TRANSFER;
   hdr->msg_type=M3UA_TRANSFER_DATA;
   hdr->len=swap_uint32(sizeof(struct M3UA_common_header)+sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);

   payload_hdr->tag = swap_uint16(M3UA_PARAM_PROTO_DATA);
   payload_hdr->len = swap_uint16(sizeof(struct M3UA_param_header)+sizeof(struct M3UA_protocol_data)+sizeof(struct SCCP_hdr)+2*sizeof(struct SCCP_party_addr)+ TCAP_MESSAGE_SIZE);
    
   proto_data->OPC = swap_uint32(110);
   proto_data->DPC = swap_uint32(100);
   proto_data->SIO = 3;
   proto_data->NI = 2;
   proto_data->MP = 0;
   proto_data->SLS = 11;
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