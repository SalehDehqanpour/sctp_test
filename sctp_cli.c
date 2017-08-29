//SCTPClient.C
// Protocol Stack that is implemented : SCTP/M3UA/SCCP/TCAP/GSM_MAP
//issues:  3 octet of zero padding at end of each TCAP message is not included yet (sometimes it's 2 octets or another)
//          sctp header (raw?)
//        
//
//
//
//           
// To compile - gcc sctpclt.c -o client -lsctp
#include <stdio.h>
//#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#define MAX_BUFFER 4096
#define MY_PORT_NUM 62324 /* This can be changed to suit the need and should be same in server and client */


//! Byte swap unsigned short
uint16_t swap_uint16( uint16_t val ) 
{
    return (val << 8) | (val >> 8 );
}

/* //! Byte swap short
int16_t swap_int16( int16_t val ) 
{
    return (val << 8) | ((val >> 8) & 0xFF);
}
 */
//! Byte swap unsigned int
uint32_t swap_uint32( uint32_t val )
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}

/* //! Byte swap int
int32_t swap_int32( int32_t val )
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | ((val >> 16) & 0xFFFF);
} */

struct m3ua_common_header {
  uint8_t  v;
  uint8_t  reserved;
  uint8_t  msg_class;
  uint8_t  msg_type;
  uint32_t len;
};

struct m3ua_param_header {
  uint16_t tag;
  uint16_t len;
};

struct m3ua_protocol_data {
  uint32_t  OPC;
  uint32_t  DPC;
  uint8_t  SIO;
  uint8_t  NI;
  uint8_t MP;
  uint8_t SLS;
};
#define M3UA_MSGC_TRANSFER 1

#define M3UA_TRANSFER_DATA 1

//#define M3UA_PARAM_NETWORK_APPEARANCE 0x0200
//#define M3UA_PARAM_ROUTING_CTX 0x0006
#define M3UA_PARAM_PROTO_DATA 0x0210
//#define M3UA_PARAM_CORR_ID 0x0013

////////////////////////////////////////////////
#define SCCP_MSG_TYPE_UDT 9
#define SCCP_PROTO_CLASS 0x80 //0 0 0 0 class 0  || 1 0 0 0 return message on error
#define SCCP_SSN_EIC 9

#define TCAP_MESSAGE_SIZE 88 //(including "57" len)
struct sccp_party_addr{//The sequence of bit fields is reversed intentionally to conform with standard
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

 struct sccp_hdr { // Specific-purpose: Only for TCAP/GSM_MAP(checkIMEI) (It is not a general sccp header)
     uint8_t msg_type;
     uint8_t proto_class;
     uint8_t ptr_to_var_mand[3]; //Pointer to Mandatory Variable Parameters
      };
 
 
 
 
 
int main (int argc, char* argv[])
{
  int connSock, in, i, ret, flags;
  struct sockaddr_in servaddr;
  struct sctp_status status;
unsigned  char buffer[MAX_BUFFER + 1]; //buffer is payload of SCTP
  int datalen = 0;

  /*Get the input from user*/
  //printf("Enter data to send: ");
  //fgets(buffer, MAX_BUFFER, stdin);
  /* Clear the newline or carriage return from the end*/
  //buffer[strcspn(buffer, "\r\n")] = 0;
  /* Sample input */
  
  
  //strncpy (buffer, "Hello Server", 12);
  //buffer[12] = '\0';
  
  //char datagram[4096]
  //  // M3UA: 
  struct m3ua_common_header* M3UA_hdr = (struct m3ua_common_header*) buffer;
  M3UA_hdr -> v=1;
  M3UA_hdr -> reserved=0;
  M3UA_hdr -> msg_class=M3UA_MSGC_TRANSFER;
  M3UA_hdr -> msg_type=M3UA_TRANSFER_DATA;
  M3UA_hdr -> len=swap_uint32(sizeof(struct m3ua_common_header)+sizeof(struct m3ua_param_header)+sizeof(struct m3ua_protocol_data)+sizeof(struct sccp_hdr)+2*sizeof(struct sccp_party_addr)+ TCAP_MESSAGE_SIZE);
  
  struct m3ua_param_header* M3UA_payload_hdr = (struct m3ua_param_header*) ((char*)M3UA_hdr + sizeof(struct m3ua_common_header));
   
  M3UA_payload_hdr -> tag = swap_uint16( M3UA_PARAM_PROTO_DATA);
  M3UA_payload_hdr -> len = swap_uint16(sizeof(struct m3ua_param_header)+sizeof(struct m3ua_protocol_data)+sizeof(struct sccp_hdr)+2*sizeof(struct sccp_party_addr)+ TCAP_MESSAGE_SIZE);
  
  struct m3ua_protocol_data* M3UA_proto_data =  (struct m3ua_protocol_data* )((char*) M3UA_payload_hdr + sizeof(struct m3ua_param_header));

  M3UA_proto_data ->  OPC = swap_uint32 (110);
  M3UA_proto_data ->  DPC = swap_uint32 (100);
  M3UA_proto_data ->  SIO = 3;
  M3UA_proto_data ->  NI = 2;
  M3UA_proto_data ->  MP = 0;
 /*Maybe required to change each transaction*/ M3UA_proto_data ->  SLS = 11;//Each link within a linkset is given a unique SLS code, which is used by routing to
//determine which links a message should be routed over. 
  
  
  
  //---------------------------
  //---------------------------
  
  // // SCCP:
  struct sccp_hdr * SCCP_header=(struct sccp_hdr *)((char *)M3UA_proto_data + sizeof(struct m3ua_protocol_data));
  
  SCCP_header -> msg_type = SCCP_MSG_TYPE_UDT;
  SCCP_header -> proto_class = SCCP_PROTO_CLASS;
  (SCCP_header -> ptr_to_var_mand)[0] = 3; // values of pointers obtained from PCAP which I have in hand.
  (SCCP_header -> ptr_to_var_mand)[1] = 10;
  (SCCP_header -> ptr_to_var_mand)[2] = 17;
  
  
  struct sccp_party_addr* sccp_called = (struct sccp_party_addr*)((char *)SCCP_header + sizeof(struct sccp_hdr ));
  
  struct sccp_party_addr* sccp_calling = (struct sccp_party_addr*)((char *)sccp_called + sizeof(struct sccp_party_addr ));
  
  
  
  
  
  
  
  
  // values of pointers obtained from PCAP which I have in hand.
   sccp_called ->addr_len=7;
   sccp_called ->reserved=0;
   sccp_called ->routing_indicator=0;
   sccp_called ->global_title_indicator=4;
   sccp_called ->ssn_indicator=1;
   sccp_called ->point_code_indicator=0;
   sccp_called ->sccp_subsystem_number/* is different in called & calling*/=9;
   sccp_called ->sccp_translation_type=0;
   sccp_called ->NP=1;
   sccp_called ->ES=2;
   sccp_called ->NAI=4;
   sccp_called ->global_title_addr/* is different in called & calling*/=swap_uint16(0x0110) ;  //WARNING: reverse nibbles in each octet to reach actual addr
  
   sccp_calling ->addr_len=7;
   sccp_calling ->reserved=0;
   sccp_calling ->routing_indicator=0;
   sccp_calling ->global_title_indicator=4;
   sccp_calling ->ssn_indicator=1;
   sccp_calling ->point_code_indicator=0;
   sccp_calling ->sccp_subsystem_number/* is different in called & calling*/=8;
   sccp_calling ->sccp_translation_type=0;
   sccp_calling ->NP=1;
   sccp_calling ->ES=2;
   sccp_calling ->NAI=4;
   sccp_calling ->global_title_addr/* is different in called & calling*/=swap_uint16(0x1110);  //WARNING: reverse nibbles in each octet


char tempp[TCAP_MESSAGE_SIZE]= {0x57,0x62,0x55,0x48,0x04,0x8a,0x40,0x00,0x01,0x6b,0x39,0x28,0x37,0x06,0x07,0x00,0x11,0x86,0x05,0x01,0x01,
0x01,0xa0,0x2c,0x60,0x2a,0x80,0x02,0x07,0x80,0xa1,0x09,0x06,0x07,0x04,0x00,0x00,0x01,0x00,0x0d,0x02,0xbe,0x19,0x28,0x17,
0x06,0x07,0x04,0x00,0x00,0x01,0x01,0x01,0x01,0xa0,0x0c,0xa0,0x0a,0x80,0x08,0x86,0x48,0x63,0x18,0x29,0x93,0x19,0x83,0x6c,0x12,
0xa1,0x10,0x02,0x01,0x01,0x02,0x01,0x2b,0x04,0x08,0x42,0x11,0x27,0x38,0x03,0x68,0x76,0x89};//,0x00,0x00,0x00,0x00}; padding zeros  
// first octet is length of TCAP (excluding itself)



unsigned char *TCAP_start;
TCAP_start = (char*) sccp_calling  + sizeof(struct sccp_party_addr);
//TCAP_start=(char*)malloc(TCAP_MESSAGE_SIZE); //  size of char is assumed to be one
memcpy(TCAP_start, tempp, TCAP_MESSAGE_SIZE);

datalen = sizeof(struct m3ua_common_header)+sizeof(struct m3ua_param_header)+sizeof(struct m3ua_protocol_data)+sizeof(struct sccp_hdr)+2*sizeof(struct sccp_party_addr)+ TCAP_MESSAGE_SIZE;

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
  servaddr.sin_addr.s_addr = inet_addr ("127.0.0.1");

  ret = connect (connSock, (struct sockaddr *) &servaddr, sizeof (servaddr));

  if (ret == -1)
  {
      printf("Connection failed\n");
      perror("connect()");
      close(connSock);
      exit(1);
  }

  ret = sctp_sendmsg (connSock, (void *) buffer, (size_t) datalen,
        NULL, 0, 0, 0, 0, 0, 0);
  if(ret == -1 )
  {
    printf("Error in sctp_sendmsg\n");
    perror("sctp_sendmsg()");
  }
  else
      printf("Successfully sent %d bytes data to server\n", ret);

  close (connSock);

  return 0;
}