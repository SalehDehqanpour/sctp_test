#My system has run into an unknown problem which I can't enter into threads.(getting a 'segmentation fault').vSo I am not sure this codes have no errors. I am trying on another system and soon will find the solution.

List of files: sctp_cli.c  sctp_methods.c  sctp_cli.h

Protocol Stack that is implemented : SCTP/M3UA/SCCP/TCAP/GSM_MAP

Hint: The identifiers which are in upper CASE are data types.(like SCCP_party_addr). The lower ones are objects.(like sccp_called)

To compile: gcc -O2 sctp_cli_p.c sctp_methods.c -lsctp -lpthread -o p.out
