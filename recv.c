#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/poll.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

#include "packets.h"

#define DEST_MAC0	0x00 || 0xff
#define DEST_MAC1	0x26 || 0xff
#define DEST_MAC2	0x6c || 0xff
#define DEST_MAC3	0x8c || 0xff
#define DEST_MAC4	0xe0 || 0xff
#define DEST_MAC5	0x62 || 0xff

#define ETHER_TYPE	0x1234
#define DEFAULT_IF	"enp2s0"
#define BUF_SIZ		1024
#define HEAD_SIZE 14
///////////////////////////////////////////////////////////

#define MY_NAME "okan"
#define MY_SURNAME "erdogan"

#define TARGET_NAME "cihan"
#define TARGET_SURNAME "alp"

//#define QUERIER_NAME  "cihan"
//#define QUERIER_SURNAME  "alp"
////////////////



char bcast [sizeof(struct query_bcast)];
char ucast [sizeof(struct query_ucast)];
char resp  [sizeof(struct hello_response)];
char chatt [sizeof(struct chat)];
char chatt_ack [sizeof(struct chat_ack)];
char exit_str[sizeof(struct exiting)];

struct query_ucast *packet_resp_name;
uint8_t chat_ID;

static void fill_query_bcast(struct query_bcast *q);

static void fill_query_ucast(struct query_ucast *q);

static void fill_hello_response(struct hello_response *q);

static char *hex_print(void *pack, size_t len);

static void fill_chat(struct chat *q);

static void fill_chat_ack(struct chat_ack *q);

unsigned char *hex_to_string(unsigned char *string);

/////////////////////////////////////////////////////////////7
static void decode_bcast();
static void decode_ucast();
static void decode_response();
static void decode_chat();
static void decode_chat_ack();
static void decode_exiting();




int main(int argc, char *argv[])
{
	
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i, rv;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
  uint8_t rec_mac [6];
  uint8_t trans_mac [6];
  uint8_t head_type [2];

	uint8_t data_type;
  struct query_bcast my_packet;

	struct pollfd *ufds;

	/////////////////////////////////////////////////////////////////////////
	int prot_type;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	int j;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	//struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char *packet_all;
	int packet_size;
	char dest_name [10];
	char dest_surname [10];
	char sender_name [10];
	char sender_surname [10]; 
	
	////////////////////////////////////////////////////////////////////////////////
	unsigned char *mac_file = malloc(sizeof(char)*12);
    unsigned char *name_file = malloc(sizeof(char)*10);
    unsigned char *surname_file = malloc(sizeof(char)*10);
    
	/* Get interface name */
		strcpy(ifName, DEFAULT_IF);

	/* Header structures */
	//****struct ether_header *eh = (struct ether_header *) buf;

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");
		return -1;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
			perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
			perror("SIOCGIFHWADDR");


	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags	 |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	while(1)
	{
	////
	 printf(" \n \n \nlistener: Waiting to recvfrom...\n");

	FILE *database;
	database = fopen("/home/okan/summerseed/proje_1/data.txt","a+");
	
	numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
	
	/* Check the packet is for me */
	if (eh->ether_dhost[0] == DEST_MAC0 &&
			eh->ether_dhost[1] == DEST_MAC1 &&
			eh->ether_dhost[2] == DEST_MAC2 &&
			eh->ether_dhost[3] == DEST_MAC3 &&
			eh->ether_dhost[4] == DEST_MAC4 &&
			eh->ether_dhost[5] == DEST_MAC5) {
		printf("Correct destination MAC address\n");
	} 
	else {
		printf("Wrong destination MAC");
		ret = -1;
		continue;
	}

  for(i = 0; i < HEAD_SIZE; i++){
    if(i < 6){
      rec_mac[i] = buf[i];
      if(i == 0) printf("rec_mac = " );
      printf("%02x:", rec_mac[i] );
    }
    else if(i<12){
      trans_mac[i-6] = buf[i];
      if(i == 6) printf("\ntrans_mac = " );
      printf("%02x:", trans_mac[i-6] );
      //fprintf(database, "%02x", trans_mac[i-6] );	
    }
    else{
      head_type[i] = buf[i];
      //printf("%02x:", head_type[i] );
    }
  }
	data_type = buf[HEAD_SIZE]; 

	switch (data_type) {
		case  QUERY_BROADCAST:{
			printf("\n\n\n--------------RECIEVED A BROADCAST QEURY PACKET----------\n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				
				bcast[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = bcast[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = bcast[i-HEAD_SIZE];
				}
				//printf("%02x:", bcast[i-HEAD_SIZE]);
			}
					
					/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 

			decode_bcast();

			struct hello_response hello_response;
		    
		    char *packet_resp = malloc(sizeof(struct hello_response));
		    packet_all = malloc(sizeof(hello_response));
		    memset(&hello_response, 0, sizeof(struct hello_response));
		    packet_size = 41;
		    packet_resp_name = (struct query_bcast*)bcast;
		    fill_hello_response(&hello_response);
		    packet_resp = hex_print((void*) &hello_response,sizeof(struct hello_response));
			
			
		    packet_all = packet_resp;

		    printf("packet_resp_name name::%s\n", packet_resp_name->name);
		    printf("packet_resp_name surname::%s\n", packet_resp_name->surname );

		   // fprintf(database,"%s %s\n", packet_resp_name->name, packet_resp_name->surname);

				memset(sendbuf, 0, BUF_SIZ);
		    /* Ethernet header */
		    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
		    eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
		    eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
		    eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
		    eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
		    eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
		    eh->ether_dhost[0] = 0xff;
		    eh->ether_dhost[1] = 0xff;
		    eh->ether_dhost[2] = 0xff;
		    eh->ether_dhost[3] = 0xff;
		    eh->ether_dhost[4] = 0xff;
		    eh->ether_dhost[5] = 0xff;
		    /* Ethertype field  ETH_P_IP */
		    eh->ether_type = htons(ETHER_TYPE);
		    tx_len += sizeof(struct ether_header);


				/* Packet data */
				for(j=0;j<packet_size;j++){
				  sendbuf[14+j] = packet_all[j];
				  tx_len++;
				  //printf("%d - %d\n",tx_len++,sendbuf[14+j]);

				}
				printf("hello response packet sended\n");

				/* Index of the network device */
				socket_address.sll_ifindex = if_idx.ifr_ifindex;
				/* Address length*/
				socket_address.sll_halen = ETH_ALEN;
				/* Destination MAC */
				socket_address.sll_addr[0] = 0xff;
				socket_address.sll_addr[1] = 0xff;
				socket_address.sll_addr[2] = 0xff;
				socket_address.sll_addr[3] = 0xff;
				socket_address.sll_addr[4] = 0xff;
				socket_address.sll_addr[5] = 0xff;

				//printf("%X\n",packet[6]);
				//printf("%s\n",sendbuf);
				/* Send packet */
				if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				//if (sendto(sockfd, packet, 4*strlen(packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				    printf("Send failed\n");

				break;
		}
		case  QUERY_UNICAST:{
			printf("\n\n\n--------------RECIEVED A UNICAST QEURY PACKET----------\n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				ucast[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = ucast[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = ucast[i-HEAD_SIZE];
				}
				//printf("%02x:", ucast[i-HEAD_SIZE]);
			}
					/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 

			decode_ucast();

			struct hello_response hello_response;
		    
		    char *packet_resp = malloc(sizeof(struct hello_response));
		    packet_all = malloc(sizeof(hello_response));
		    memset(&hello_response, 0, sizeof(struct hello_response));
		    packet_size = 41;
		    packet_resp_name = (struct query_ucast*)ucast;
		    fill_hello_response(&hello_response);
		    //fill_query_ucast(&packet_resp_name);
		    packet_resp = hex_print((void*) &hello_response,sizeof(struct hello_response));
			
			//if( packet_resp_name->target_name != MY_NAME || packet_resp_name->target_surname != MY_SURNAME)
			//	break;

		    packet_all = packet_resp;

		    printf("packet_resp_name name::%s\n", packet_resp_name->name);
		    printf("packet_resp_name surname::%s\n", packet_resp_name->surname );

		    
				memset(sendbuf, 0, BUF_SIZ);
		    /* Ethernet header */
		    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
		    eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
		    eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
		    eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
		    eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
		    eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
		    eh->ether_dhost[0] = 0xff;
		    eh->ether_dhost[1] = 0xff;
		    eh->ether_dhost[2] = 0xff;
		    eh->ether_dhost[3] = 0xff;
		    eh->ether_dhost[4] = 0xff;
		    eh->ether_dhost[5] = 0xff;
		    /* Ethertype field  ETH_P_IP */
		    eh->ether_type = htons(ETHER_TYPE);
		    tx_len += sizeof(struct ether_header);


				/* Packet data */
				for(j=0;j<packet_size;j++){
				  sendbuf[14+j] = packet_all[j];
				  tx_len++;
				  //printf("%d - %d\n",tx_len++,sendbuf[14+j]);

				}
				printf("hello response packet sended\n");

				/* Index of the network device */
				socket_address.sll_ifindex = if_idx.ifr_ifindex;
				/* Address length*/
				socket_address.sll_halen = ETH_ALEN;
				/* Destination MAC */
				socket_address.sll_addr[0] = 0xff;
				socket_address.sll_addr[1] = 0xff;
				socket_address.sll_addr[2] = 0xff;
				socket_address.sll_addr[3] = 0xff;
				socket_address.sll_addr[4] = 0xff;
				socket_address.sll_addr[5] = 0xff;

				//printf("%X\n",packet[6]);
				//printf("%s\n",sendbuf);
				/* Send packet */
				if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				//if (sendto(sockfd, packet, 4*strlen(packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				    printf("Send failed\n");


			break;
		}
		case  HELLO_RESPONSE:{
			printf("\n\n\n:::::hello response recieved:::::\n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				resp[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = resp[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = resp[i-HEAD_SIZE];
				}
				//printf("%02x:", resp[i-HEAD_SIZE]);
			}
			/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 		

			decode_response();

			break;
		}
		case CHAT:{
			printf("\n\n\n:::::chat message recieved:::::\n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				chatt[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = chatt[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = chatt[i-HEAD_SIZE];
				}
				//printf("%02x:", chatt[i-HEAD_SIZE]);
			}
			/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 
			decode_chat();

			struct chat_ack chat_ack;
		    
		    char *packet_ack = malloc(sizeof(struct chat_ack));
		    packet_all = malloc(sizeof(chat_ack));
		    memset(&chat_ack, 0, sizeof(struct chat_ack));
		    packet_size = 2;
		    chat_ID = chatt[3];
		    fill_chat_ack(&chat_ack);
		    packet_ack = hex_print((void*) &chat_ack,sizeof(struct chat_ack));
			
			
		    packet_all = packet_ack;


				memset(sendbuf, 0, BUF_SIZ);
		    /* Ethernet header */
		    eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
		    eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
		    eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
		    eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
		    eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
		    eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
		    eh->ether_dhost[0] = trans_mac[0];
		    eh->ether_dhost[1] = trans_mac[1];
		    eh->ether_dhost[2] = trans_mac[2];
		    eh->ether_dhost[3] = trans_mac[3];
		    eh->ether_dhost[4] = trans_mac[4];
		    eh->ether_dhost[5] = trans_mac[5];
		    /* Ethertype field  ETH_P_IP */
		    eh->ether_type = htons(ETHER_TYPE);
		    tx_len += sizeof(struct ether_header);


				/* Packet data */
				for(j=0;j<packet_size;j++){
				  sendbuf[14+j] = packet_all[j];
				  tx_len++;
				  //printf("%d - %d\n",tx_len++,sendbuf[14+j]);

				} printf("chat ACK sended\n");

				/* Index of the network device */
				socket_address.sll_ifindex = if_idx.ifr_ifindex;
				/* Address length*/
				socket_address.sll_halen = ETH_ALEN;
				/* Destination MAC */
				socket_address.sll_addr[0] = trans_mac[0];
				socket_address.sll_addr[1] = trans_mac[1];
				socket_address.sll_addr[2] = trans_mac[2];
				socket_address.sll_addr[3] = trans_mac[3];
				socket_address.sll_addr[4] = trans_mac[4];
				socket_address.sll_addr[5] = trans_mac[5];

				//printf("%X\n",packet[6]);
				//printf("%s\n",sendbuf);
				/* Send packet */
				if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				//if (sendto(sockfd, packet, 4*strlen(packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
				    printf("Send failed\n");
				
				break;

		}

		case CHAT_ACK: {
			printf("\n\n\n::::chat ack recieved:::: \n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				chatt_ack[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = chatt_ack[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = chatt_ack[i-HEAD_SIZE];
				}
				//printf("%02x:", chatt_ack[i-HEAD_SIZE]);
			}
			/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 		

			decode_chat_ack();
			break;

		}
		case EXITING: {
			printf("\n\n\n ::::exiting recieved::::\n");
			for (i = HEAD_SIZE; i < numbytes; i++){
				exit_str[i-HEAD_SIZE] = buf[i];
				if(i > HEAD_SIZE  && i < HEAD_SIZE + 11){ 
					
					sender_name[i-HEAD_SIZE-1] = exit_str[i-HEAD_SIZE];
					
				}
				if (i > HEAD_SIZE +10 && i < HEAD_SIZE + 21)
				{
					sender_surname[i-HEAD_SIZE-11] = exit_str[i-HEAD_SIZE];
				}
				//printf("%02x:", exit_str[i-HEAD_SIZE]);
			}
			/* mac check to write*/
			short int write_en = 0;
			while(!feof(database))
			{	
				fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
				if (strcmp((trans_mac),hex_to_string(mac_file)) == 0)
				{
					write_en = 0;
					//printf("\n--------------en setted 0 --------\n %s", mac_file);
					break;
				}
				else if(strcmp(trans_mac,hex_to_string(mac_file)) < 0 || strcmp(trans_mac,hex_to_string(mac_file)) > 0)
				{	
					write_en = 1;
					//printf("\n--------------en setted 1--------\n %s", mac_file);
				}
			}

			if(write_en == 1)
			{
				for(i = 0; i < 6; i++)
				{	
					//printf("\nmac writing\n");
					fprintf(database, "%02x", trans_mac[i] );			
				}
				//printf("\n names writing\n");
				fprintf(database," %s %s\n", sender_name, sender_surname);
			} 		

			decode_exiting();
			break;

		}
	}

	fclose(database);
	
	}
	
	close(sockfd);	
	return ret;

}

static void decode_bcast()
{
    struct query_bcast *q;
    q = (struct query_bcast*) bcast;

    fprintf(stdout, "* decoding broadcast query *\n");
    fprintf(stdout, "q->type: %d\n", q->type);

    fprintf(stdout, "q->name: %s\n", q->name);
    fprintf(stdout, "q->surname: %s\n", q->surname);
}

static void decode_ucast()
{
    struct query_ucast *q;
    q = (struct query_ucast*) ucast;

    fprintf(stdout, "* decoding unicast query *\n");
    fprintf(stdout, "q->type: %d\n", q->type);

    fprintf(stdout, "q->name: %s\n", q->name);
    fprintf(stdout, "q->surname: %s\n", q->surname);

    fprintf(stdout, "q->target_name: %s\n", q->target_name);
    fprintf(stdout, "q->target_surname: %s\n", q->target_surname);
}

static void decode_response()
{
    struct hello_response *q;
    q = (struct hello_response*) resp;

    fprintf(stdout, "* decoding HELLO RESPONSE *\n");
    fprintf(stdout, "q->type: %d\n", q->type);

    fprintf(stdout, "q->name: %s\n", q->name);
    fprintf(stdout, "q->surname: %s\n", q->surname);

    fprintf(stdout, "q->target_name: %s\n", q->query_name);
    fprintf(stdout, "q->target_surname: %s\n", q->query_surname);
}

static void decode_chat()
{
	struct chat *q;
	q = (struct chat*) chatt;
	fprintf(stdout, "q->type: %d\n", q->type);

    fprintf(stdout, "q->length: %s\n", q->length);
    fprintf(stdout, "q->ID: %d\n", q->ID);
    fprintf(stdout, "q->message: %s\n", q->message);
}

static void decode_chat_ack()
{
	struct chat_ack *q;
	q = (struct chat_ack *) chatt_ack;

	fprintf(stdout, "q->type: %d\n", q->type);
    fprintf(stdout, "q->ID: %d\n", q->ID);
}

static void decode_exiting()
{	
	struct exiting *q;
	q = (struct exiting*) exit_str;
	fprintf(stdout, "q->type: %d\n", q->type);
    fprintf(stdout, "q->name: %s\n", q->name);
    fprintf(stdout, "q->surname: %s\n", q->surname);
		
}

static void fill_query_bcast(struct query_bcast *q)
{
    q->type = QUERY_BROADCAST;
    snprintf(q->name, MAX_NAME_SIZE, "%s", MY_NAME);
    snprintf(q->surname, MAX_NAME_SIZE, "%s", MY_SURNAME);
}

/**
 * @brief
 *
 * @param[out] q
 */
static void fill_query_ucast(struct query_ucast *q)
{
    q->type = QUERY_UNICAST;
    snprintf(q->name, MAX_NAME_SIZE, "%s", MY_NAME);
    snprintf(q->surname, MAX_NAME_SIZE, "%s", MY_SURNAME);
    snprintf(q->target_name, MAX_NAME_SIZE, "%s", TARGET_NAME);
    snprintf(q->target_surname, MAX_NAME_SIZE, "%s", TARGET_SURNAME);
}

static void fill_hello_response(struct hello_response *q)
{
    q->type = HELLO_RESPONSE;
    snprintf(q->name, MAX_NAME_SIZE, "%s", MY_NAME);
    snprintf(q->surname, MAX_NAME_SIZE, "%s", MY_SURNAME);
    snprintf(q->query_name, MAX_NAME_SIZE, "%s", packet_resp_name->name);
    snprintf(q->query_surname,MAX_NAME_SIZE,"%s", packet_resp_name->surname);

}

static void fill_chat(struct chat *q)
{
	q->type = CHAT;

}

static void fill_chat_ack(struct chat_ack *q)
{
	q->type = CHAT_ACK;
	q->ID = chat_ID; 
}

/**
 * @brief generic print of struct in hexadecimal
 * format
 *
 * @param[in] pack
 * @param[in] len
 */
static char *hex_print(void *pack, size_t len)
{
    int i = 0;
    char *arr = malloc(sizeof(char)*len);
    for (i = 0; i < len; i++) {
        //fprintf(stdout, "%02x ", ((uint8_t *) pack)[i]);
        arr[i] = ((uint8_t *) pack)[i];
        //printf("%c\n", arr[i]);

    }
    //fprintf(stdout, "\n");
    return arr;
}


unsigned char *hex_to_string(unsigned char *string)
{
    unsigned char *pos = string;
    unsigned char *val = malloc(sizeof(string)*10);
    size_t count = 0;
    for(count = 0; count <= sizeof(val)/sizeof(val[0]); count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
    return val;
}
