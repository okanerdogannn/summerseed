#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>

#include "packets.h"
/*
#define MY_DEST_MAC0	0xff
#define MY_DEST_MAC1	0xff
#define MY_DEST_MAC2	0xff
#define MY_DEST_MAC3	0xff
#define MY_DEST_MAC4	0xff
#define MY_DEST_MAC5	0xff
*/
#define ETHER_TYPE 0x1234
#define DEFAULT_IF	"enp2s0"
#define BUF_SIZ	1024

#define MY_NAME "okan"
#define MY_SURNAME "erdogan"

/*#define TARGET_NAME "cihan"
#define TARGET_SURNAME "alp"

#define QUERIER_NAME "cihan"
#define QUERIER_SURNAME "alp"*/


static void fill_query_bcast(struct query_bcast *q);

static void fill_query_ucast(struct query_ucast *q);

static void fill_hello_response(struct hello_response *q);

static void fill_chat(struct chat *q);

static void fill_chat_ack(struct chat_ack *q);

static void fill_exiting(struct exiting *q);

static char *hex_print(void *pack, size_t len);

static char *chat_message;
static uint16_t *chat_message_L;
static uint8_t chat_ID = 3;
static char *dest_name;
static char *dest_surname;

unsigned char *hex_to_string(unsigned char *string);

int main(int argc, char *argv[])
{   
    int prot_type;
    int sockfd;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len = 0;
    int i,j;
    char sendbuf[BUF_SIZ];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    //struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
    struct sockaddr_ll socket_address;
    char ifName[IFNAMSIZ];
    char *packet_all;
    int packet_size;
    char *mac_filex= malloc(sizeof(char)*10);
    unsigned char *dest_mac;
    chat_message = malloc(sizeof(char)*MAX_MESSAGE_SIZE);
    chat_message_L = malloc(sizeof(char)*2);

    prot_type = atoi(argv[1]);

    FILE *database;
    database = fopen("/home/okan/summerseed/proje_1/data.txt","a+");
    
    unsigned char *mac_file = malloc(sizeof(char)*12);
    unsigned char *name_file = malloc(sizeof(char)*10);
    unsigned char *surname_file = malloc(sizeof(char)*10);
      
    dest_name = malloc(sizeof(char)*MAX_NAME_SIZE);
    dest_surname = malloc(sizeof(char)*MAX_NAME_SIZE);
    
    if(prot_type == 3)
    {    
        dest_name = argv[2];
        dest_surname =argv[3];
        for(i=4; i < argc; i++){
        strcat(chat_message, argv[i]);
        strcat(chat_message, " ");
        }
        chat_message_L = strlen(argv[2]);

    }
    if(prot_type == 1){
        dest_name = argv[2];
        dest_surname = argv[3];

    }
    if(prot_type == 2){
        dest_name = argv[2];
        dest_surname = argv[3];

    }
    dest_mac = malloc(sizeof(char)*12);
    if(prot_type == 1 || prot_type == 2 || prot_type == 3)
    {
        for(i = 0; i < 16; i++)
        {
            fscanf(database,"%s %s %s\n", mac_file , name_file ,surname_file);
            mac_filex = hex_to_string(mac_file);
            if((strcmp(dest_name,name_file) == 0 )&& (strcmp(dest_surname,surname_file) == 0))
            {
                dest_mac = mac_filex;
            }
        }
    }

    switch (prot_type) {
      case QUERY_BROADCAST: {
        struct query_bcast query_bcast;
        char *packet_bcast = malloc(sizeof(query_bcast)) ;
        packet_all = malloc(sizeof(query_bcast)) ;
        memset(&query_bcast, 0, sizeof(struct query_bcast));
        packet_size = 21;
        printf("////\n----%s---- %s\n///", dest_name, dest_surname );
        fill_query_bcast(&query_bcast);
        packet_bcast = hex_print((void *) &query_bcast, sizeof(struct query_bcast));
        packet_all =packet_bcast;
        for(i=0;i<6;i++)
            dest_mac[i] = 0xff;
        break;
      }
      
      case QUERY_UNICAST: {
        struct query_ucast query_ucast;
        char *packet_ucast = malloc(sizeof(query_ucast)) ;
        packet_all = malloc(sizeof(query_ucast)) ;
        memset(&query_ucast, 0, sizeof(struct query_ucast));
        packet_size = 41;
        printf("////\n----%s---- %s\n////", dest_name, dest_surname );
        fill_query_ucast(&query_ucast);
        packet_ucast = hex_print((void *) &query_ucast, sizeof(struct query_ucast));
        packet_all = packet_ucast;
        for(i=0;i<6;i++)
            dest_mac[i] = 0xff;
        break;
      }
      case HELLO_RESPONSE: {
        struct hello_response hello_response;
        char *packet_resp = malloc(sizeof(hello_response));
        packet_all = malloc(sizeof(hello_response));
        memset(&hello_response, 0, sizeof(struct hello_response));
        packet_size = 41;
        fill_hello_response(&hello_response);
        packet_resp = hex_print((void*) &hello_response,sizeof(struct hello_response));
        packet_all = packet_resp;
        break;
      }
      case CHAT:{
        struct chat chat;
        char *packet_chat = malloc(sizeof(chat));
        packet_all = malloc(sizeof(chat));
        memset(&chat, 0, sizeof(struct chat));
        packet_size = 500;
        fill_chat(&chat);
        packet_chat = hex_print((void*) &chat,sizeof(struct chat));
        packet_all = packet_chat;
        break;
      }
      case CHAT_ACK:{
        struct chat_ack chat_ack;
        char *packet_chat_ack = malloc(sizeof(chat_ack));
        packet_all = malloc(sizeof(chat_ack));
        memset(&chat_ack, 0, sizeof(struct chat_ack));
        packet_size = 2;
        fill_chat(&chat_ack);
        packet_chat_ack = hex_print((void*) &chat_ack,sizeof(struct chat_ack));
        packet_all = packet_chat_ack;
        break;
      }
      case EXITING: {
        struct exiting exiting;
        char *packet_exiting = malloc(sizeof(exiting));
        packet_all = malloc(sizeof(exiting));
        memset(&exiting, 0, sizeof(struct exiting));
        packet_size = 21;
        fill_exiting(&exiting);
        packet_exiting = hex_print((void*) &exiting,sizeof(struct exiting));
        packet_all = packet_exiting;
        for(i=0;i<6;i++)
            dest_mac[i] = 0xff;
        break; 
      }
    }

          strcpy(ifName, DEFAULT_IF);

        /* Open RAW socket to send on */
        if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
            perror("socket");
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

        /* Construct the Ethernet header */
        memset(sendbuf, 0, BUF_SIZ);
        /* Ethernet header */
        eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
        eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
        eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
        eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
        eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
        eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
        eh->ether_dhost[0] = dest_mac[0];
        eh->ether_dhost[1] = dest_mac[1];
        eh->ether_dhost[2] = dest_mac[2];
        eh->ether_dhost[3] = dest_mac[3];
        eh->ether_dhost[4] = dest_mac[4];
        eh->ether_dhost[5] = dest_mac[5];
        /* Ethertype field  ETH_P_IP */
        eh->ether_type = htons(ETHER_TYPE);
        tx_len += sizeof(struct ether_header);

        /* Packet data */
        for(j=0;j<packet_size;j++){
          sendbuf[14+j] = packet_all[j];

          printf("%d - %d\n",tx_len++,sendbuf[14+j]);

        }

        /* Index of the network device */
        socket_address.sll_ifindex = if_idx.ifr_ifindex;
        /* Address length*/
        socket_address.sll_halen = ETH_ALEN;
        /* Destination MAC */
        socket_address.sll_addr[0] = dest_mac[0];
        socket_address.sll_addr[1] = dest_mac[1];
        socket_address.sll_addr[2] = dest_mac[2];
        socket_address.sll_addr[3] = dest_mac[3];
        socket_address.sll_addr[4] = dest_mac[4];
        socket_address.sll_addr[5] = dest_mac[5];

        //printf("%X\n",packet[6]);
        //printf("%s\n",sendbuf);
        /* Send packet */
        if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
        //if (sendto(sockfd, packet, 4*strlen(packet), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
    
        return (1);
}

    /**
     * @brief
     *
     * @param[out] q
     */
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
        snprintf(q->target_name, MAX_NAME_SIZE, "%s", dest_name);
        snprintf(q->target_surname, MAX_NAME_SIZE, "%s", dest_surname);
    }

    static void fill_hello_response(struct hello_response *q)
    {
        q->type = HELLO_RESPONSE;
        snprintf(q->name, MAX_NAME_SIZE, "%s", MY_NAME);
        snprintf(q->surname, MAX_NAME_SIZE, "%s", MY_SURNAME);
        snprintf(q->query_name, MAX_NAME_SIZE, "%s", dest_name);
        snprintf(q->query_surname,MAX_NAME_SIZE,"%s", dest_surname);

    }


    static void fill_chat(struct chat *q)
    {
        // ID MASSAGE ekle
        q->type = CHAT;
        snprintf(q->length, 2, "%d", chat_message_L);
        q->ID = chat_ID;
        snprintf(q->message, MAX_MESSAGE_SIZE, "%s", chat_message);  
    }

    static void fill_chat_ack(struct chat_ack *q)
    {
        q->type = CHAT_ACK;
        q->ID = chat_ID; 
    }

    static void fill_exiting(struct exiting *q)
    {
        q->type = EXITING;
        snprintf(q->name, MAX_NAME_SIZE, "%s", MY_NAME);
        snprintf(q->surname, MAX_NAME_SIZE, "%s", MY_SURNAME);
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