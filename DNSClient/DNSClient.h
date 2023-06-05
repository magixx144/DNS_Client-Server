//
// Created by minyu on 2023/5/18.
//

//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef DNSCLIENT_DNSCLIENT_H
#define DNSCLIENT_DNSCLIENT_H

#endif //DNSCLIENT_DNSCLIENT_H

#define TYPE_CNAME 0x05
#define TYPE_A 0x01
#define TYPE_MX 0x0F
#define TYPE_PTR 0x0C
#define MESSAGE_LEN 1024
#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "127.0.0.2"
#define NAME_LEN 1024
#define IP_LEN 20
#define NET_IP_LEN 4


struct DNS_Header {
    unsigned short id;
    unsigned short tag;
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
};
struct DNS_Query{
    char *name;
    unsigned short qtype;
    unsigned short qclass;
    int length;
};
struct DNS_RR {
    char name[NAME_LEN];
    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short data_len;
    char rdata[MESSAGE_LEN];
};
int DNS_header_create(struct DNS_Header *header);
int DNS_query_create(struct DNS_Query *query,const char *hostname,const char *type);
int DNS_build(struct DNS_Header *header,struct DNS_Query *query,char *request);
int DNS_udp(unsigned char *hostname,const char *type);
static void dns_parse_name(unsigned char* chunk, unsigned char *ptr, char *out, int *len);
int DNS_parse_process(char *response);
static int is_pointer(int in);

