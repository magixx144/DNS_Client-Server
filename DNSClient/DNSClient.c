//
// Created by minyu on 2023/5/18.
//

#include "DNSClient.h"


int DNS_header_create(struct DNS_Header *header){
    if(header==NULL){
        printf("Header wrong!\n");
        return -1;
    }
    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL)); //linux下
    header->id = random();
    //srand(time(NULL)); //windows下
    //header->id = rand();
    header->tag=htons(0x0100);
    header->queryNum=htons(0x0001);
    header->answerNum=htons(0x0000);
    header->authorNum=htons(0x0000);
    header->addNum=htons(0x0000);
    return 0;
}
int DNS_query_create(struct DNS_Query *query,const char *hostname,const char *type){
    if(query==NULL||hostname==NULL){
        printf("query or hostname wrong.\n");
        return -1;
    }
    memset(query, 0x00, sizeof(struct DNS_Query));
    query->name=malloc(sizeof(hostname)+2);
    query->length=strlen(hostname)+2;
    char *ptr=query->name;
    int offset = 0;
    const char s[2]=".";
    char *hostname_dup= strdup(hostname);
    char *token=strtok(hostname_dup,s);
    while(token!=NULL){
        size_t len=strlen(token);

        *(ptr+offset)=len;
        offset++;
        strncpy(ptr+offset,token,len+1);
        offset+=len;
        token=strtok(NULL,s);
    }
    
    free(hostname_dup);
    if(strcmp(type,"A")==0){
        query->qtype= htons(TYPE_A);
    }else if(strcmp(type,"CNAME")==0){
        query->qtype=htons(TYPE_CNAME);
    }else if(strcmp(type,"MX")==0){
        query->qtype=htons(TYPE_MX);
    }else if(strcmp(type,"PTR")==0){
        query->qtype=htons(TYPE_PTR);
    }else{
        printf("No such type!!!\n");
        exit(-1);
    }
    // query->qtype= htons(0x0001);
    query->qclass= htons(0x0001);
    return offset;
}
int DNS_build(struct DNS_Header *header,struct DNS_Query *query,char *request){
    if(header==NULL||query==NULL||request==NULL){
        printf("DNS build failed.\n");
        return -1;
    }
    char *ptr=request;
    
    memset(request, 0x00, MESSAGE_LEN);
    int offset=0;
    memcpy(request+offset,header,sizeof (struct DNS_Header));offset+=sizeof (struct DNS_Header);
    memcpy(request+offset,query->name,query->length);offset+=query->length;
    memcpy(request+offset,&query->qtype,sizeof(unsigned short));offset+=sizeof(unsigned short);
    memcpy(request+offset,&query->qclass,sizeof(unsigned short));offset+=sizeof(unsigned short);

    return offset;
}
int DNS_udp(unsigned char *hostname,const char *type){
    //创建socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        return -1;
    }
    //结构体填充数据
    struct sockaddr_in servaddr;
    //bzero(&servaddr, sizeof(servaddr)); linux环境下
    memset(&servaddr,0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_SERVER_PORT);

    inet_pton(AF_INET, DNS_SERVER_IP, &servaddr.sin_addr.s_addr);
    //UDP不一定要connect，只是这样提高成功发送请求的可能性
    connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    //发送报文
    struct DNS_Header header={0};
    struct DNS_Query query={0};
    char request[MESSAGE_LEN]={0};
    DNS_header_create(&header);
    
    DNS_query_create(&query,hostname,type);
    int offset=DNS_build(&header,&query,request);
    sendto(sockfd,request,offset,0,(struct sockaddr *)&servaddr,sizeof(struct sockaddr));
    printf("send bytes:%d\n",offset);
    //接收报文
    char response[MESSAGE_LEN] = {0};
    struct sockaddr_in addr;
    size_t addr_len = sizeof(struct sockaddr_in);
    int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);
    printf("receive bytes:%d\n",n);
    DNS_parse_process(response);
    return 0;
}

static void dns_parse_name(unsigned char* chunk, unsigned char *ptr, char *out, int *len){
    int flag = 0, n = 0, alen = 0;
    //pos指向的内存用于存储解析得到的结果
    char *pos = out + (*len); // 传入的 *len = 0
    while(1){
        flag = (int)ptr[0];
        if(flag == 0) break;
        //如果为指针表明该Name重复出现过，这一字段只占2字节
        if(is_pointer(flag)){
            n = (int)ptr[1]; //获取第一次Name出现的偏移
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);

            break;
        }else //Address情况下，所得len为ip地址的第一位{
            ptr++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if((int)ptr[0] != 0){
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
}


static int is_pointer(int in){
    //0xC0 : 1100 0000
    return ((in & 0xC0) == 0xC0);
}

int DNS_parse_process(char *response){
    if(response==NULL){
        printf("No response");
        return -1;
    }
    char *ptr=response;
    //header
    struct DNS_Header header={0};
    header.id=ntohs(*(unsigned short *)ptr);ptr+=2;
    header.tag=ntohs(*(unsigned short *)ptr);ptr+=2;
    header.queryNum=ntohs(*(unsigned short *)ptr);ptr+=2;
    header.answerNum=ntohs(*(unsigned short *)ptr);ptr+=2;
    header.authorNum=ntohs(*(unsigned short *)ptr);ptr+=2;
    header.addNum=ntohs(*(unsigned short *)ptr);ptr+=2;


    //query
    struct DNS_Query *query=calloc(header.queryNum, sizeof(struct DNS_Query));
    for(int i=0;i<header.queryNum;i++){
        int len_q=0;
        dns_parse_name(response,ptr,&query[i].name,&len_q);ptr+=(len_q+2);
        
        query[i].qtype=htons(*(unsigned short *)ptr);ptr+=2;
        query[i].qclass=htons(*(unsigned short *)ptr);ptr+=2;
    }

    //answer
    char cname[NAME_LEN],aname[NAME_LEN],ip[IP_LEN],net_ip[NET_IP_LEN];
    struct DNS_RR *answer=calloc(header.answerNum, sizeof(struct DNS_RR));
    int len_r=0;
    for(int i=0;i<header.answerNum+header.addNum;i++){
        len_r=0;
        dns_parse_name(response,ptr,&answer[i].name,&len_r);ptr+=(len_r+2);
        answer[i].type=htons(*(unsigned short *)ptr);ptr+=2;
        answer[i].class=htons(*(unsigned short *)ptr);ptr+=2;
        answer[i].ttl=htons(*(unsigned int *)ptr);ptr+=4;
        answer[i].data_len=htons(*(unsigned short *)ptr);ptr+=2;
        len_r=0;
        
        //判断type
        if(answer[i].type==TYPE_CNAME){
            dns_parse_name(response,ptr,&answer[i].rdata,&len_r);
            ptr+=answer[i].data_len;
            printf("%s has a cname of %s\n",&answer[i].name,&answer[i].rdata);
        }else if(answer[i].type==TYPE_A){
            bzero(ip, sizeof(ip));
            memcpy(net_ip, ptr, 4);
            dns_parse_name(response,ptr,&answer[i].rdata,&len_r);
            ptr+=answer[i].data_len;
            inet_ntop(AF_INET, net_ip, ip, sizeof(struct sockaddr));
            printf("%s has an address of %s\n",&answer[i].name,ip);
        }else if(answer[i].type==TYPE_MX){
            ptr+=2;//跳过preference
            dns_parse_name(response,ptr,&answer[i].rdata,&len_r);
            ptr+=answer[i].data_len-2;
            printf("%s has a mail exchange name of %s\n",&answer[i].name,&answer[i].rdata);
        }else if(answer[i].type==TYPE_PTR){
            dns_parse_name(response,ptr,&answer[i].rdata,&len_r);
            ptr+=answer[i].data_len;
            printf("%s has a ptr of %s\n",&answer[i].name,&answer[i].rdata);
        }

    }
    return 0;
}
