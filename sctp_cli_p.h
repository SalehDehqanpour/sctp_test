#ifndef SCTP_CLI_P
#define SCTP_CLI_P

#define MAX_BUFFER 1024 // or 4096

#define M3UA_MSGC_TRANSFER 1
#define M3UA_TRANSFER_DATA 1
#define M3UA_PARAM_PROTO_DATA 0x0210

#define SCCP_MSG_TYPE_UDT 9
#define SCCP_PROTO_CLASS 0x80 //0 0 0 0 class 0  || 1 0 0 0 return message on error
#define SCCP_SSN_EIC 9

#define TCAP_MESSAGE_SIZE 91 //including padding:91; not including: 88  (anyway including "0x57" (the length itself))

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

void M3UA_Set (struct M3UA_common_header*,struct M3UA_param_header* , struct M3UA_protocol_data*, uint8_t);
void SCCP_Set(struct SCCP_hdr*,struct SCCP_party_addr* ,struct SCCP_party_addr* );
void* handle_client(void* );


#endif
