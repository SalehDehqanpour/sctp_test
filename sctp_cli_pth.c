//SCTPClient.C
// To compile - gcc sctpclt.c -o client -lsctp
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

#define MAX_BUFFER 1024
#define MY_PORT_NUM 62324 /* This can be changed to suit the need and should be same in server and client */

void* handle_client(void* );
struct sockaddr_in servaddr;
unsigned short n=0; 
char buffer[MAX_BUFFER + 1];
int datalen = 0;


int main (int argc, char* argv[])
{
		int N;
	if (argc != 3) 	{
		fprintf(stderr, "We need two positional parameter (n,c)");
		exit(0);
	}
  
	int  in, i, flags;
	struct sctp_status status;


	/*Get the input from user*/
	//printf("Enter data to send: ");
	//fgets(buffer, MAX_BUFFER, stdin);
	/* Clear the newline or carriage return from the end*/
	//buffer[strcspn(buffer, "\r\n")] = 0;
	/* Sample input */
	strncpy (buffer, "Hello Server", 12);
	//buffer[12] = '\0';
	datalen = strlen(buffer);

	unsigned short c;
	int j;
	double t1,t2;
	N=atoi(argv[1]);
	c=atoi(argv[2]);
	n=N/c;

	bzero ((void *) &servaddr, sizeof (servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons (MY_PORT_NUM);
	servaddr.sin_addr.s_addr = inet_addr ("127.0.0.1");
	
	
	
	
	pthread_t* handles = (pthread_t*) malloc (c*sizeof(pthread_t));
	
	GET_TIME(t1);
	for (j=0; j<c; j++)  
    pthread_create( &handles[j], NULL, handle_client, (void*)j );  

	for (j=0; j<c; j++) {
      pthread_join(handles[j], NULL); 

   }
	GET_TIME(t2);
	printf("\nResult = %g #/sec \n", n/(t2-t1));
	
	
}
	
	
	
	
	
	
	
	
	
	
	

void* handle_client(void* rank) {
  int connSock, ret;
  unsigned short i;
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

  
  for(i=0; i<n; i++){

  ret = sctp_sendmsg (connSock, (void *) buffer, (size_t) datalen,
        NULL, 0, 0, 0, 0, 0, 0);
  if(ret == -1 )
  {
    printf("Error in sctp_sendmsg\n");
    perror("sctp_sendmsg()");
  }
  //else
  //    printf("Successfully sent %d bytes data to server\n", ret);

	}
  
  
  
  close (connSock);

  return NULL;
}