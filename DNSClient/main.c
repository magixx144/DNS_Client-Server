
#include "DNSClient.h"

int main(int argc, char *argv[])
{
    if(argc != 3){
        printf("Input domain name and search type!\n");
        exit(-1);
    }
    char *suffix=".in-addr.arpa";
    if(strcmp(argv[2],"PTR")==0){
        char *ipdup=strdup(argv[1]);
        strcat(ipdup,suffix);
        DNS_udp(ipdup,argv[2]);
    }else{
        DNS_udp(argv[1],argv[2]);
    }
    return 0;
}
