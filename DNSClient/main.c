
#include "DNSClient.h"

int main(int argc, char *argv[])
{
    if(argc != 3){
        printf("Input domain name and search type!\n");
        exit(-1);
    }
    DNS_udp(argv[1],argv[2]);
    return 0;
}
