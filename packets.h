#ifndef _PACKETS_H
#define _PACKETS_H

#define MAX_NAME_SIZE 10
#define MAX_MESSAGE_SIZE 255
enum {
   QUERY_BROADCAST,
   QUERY_UNICAST,
   HELLO_RESPONSE,
   CHAT,
   CHAT_ACK,
   EXITING,
} EN_PACKET;

struct query_bcast {
    uint8_t type;
    char name[MAX_NAME_SIZE];
    char surname[MAX_NAME_SIZE];
} __attribute__((packed));

struct query_ucast {
    uint8_t type;
    char name[MAX_NAME_SIZE];
    char surname[MAX_NAME_SIZE];
    char target_name[MAX_NAME_SIZE];
    char target_surname[MAX_NAME_SIZE]; 
}  __attribute__((packed));

struct hello_response {
    uint8_t type;
    char name[MAX_NAME_SIZE];
    char surname[MAX_NAME_SIZE];
    char query_name[MAX_NAME_SIZE];
    char query_surname[MAX_NAME_SIZE];
}  __attribute__((packed));

struct chat {
    uint8_t type;
    char length[2];
    uint8_t ID;
    char message[MAX_MESSAGE_SIZE];
}  __attribute__((packed)); 

struct chat_ack {
    uint8_t type;
    uint8_t ID;
}  __attribute__((packed)); 

struct exiting {
  uint8_t type;
  char name[MAX_NAME_SIZE];
  char surname[MAX_NAME_SIZE];
} __attribute__((packed));


#endif
