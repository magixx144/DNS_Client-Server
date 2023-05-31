#include "DNSRootServer.h"
static char *path = "RootCache.txt";

static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len)
{
    int flag = 0, n = 0, alen = 0;
    // pos指向的内存用于存储解析得到的结果
    char *pos = out + (*len); // 传入的 *len = 0
    while (1)
    {
        flag = (int)ptr[0];
        if (flag == 0)
            break;
        // 如果为指针表明该Name重复出现过，这一字段只占2字节
        if (is_pointer(flag))
        {
            n = (int)ptr[1]; // 获取第一次Name出现的偏移
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        }
        else // Address情况下，所得len为ip地址的第一位{
            ptr++;
        memcpy(pos, ptr, flag);
        pos += flag;
        ptr += flag;

        *len += flag;
        if ((int)ptr[0] != 0)
        {
            memcpy(pos, ".", 1);
            pos += 1;
            (*len) += 1;
        }
    }
}

static int is_pointer(int in)
{
    // 0xC0 : 1100 0000
    return ((in & 0xC0) == 0xC0);
}

char *DNS_request_parse(char *request) // 这里要返回的应该是一个顶级域名
{
    if (request == NULL)
    {
        printf("No request\n");
        return -1;
    }
    char *ptr = request+2; // ptr指向request的开头
    // header
    struct DNS_Header header = {0};
    header.id = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.tag = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.queryNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.answerNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.authorNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    header.addNum = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    // query
    struct DNS_Query *query = calloc(header.queryNum, sizeof(struct DNS_Query)); // 先假定queryNum为1，后续完善
    int len_q = 0;
    //*query[0].name=malloc(NAME_LEN);
    dns_parse_name(request, ptr, &query[0].name, &len_q);
    ptr += (len_q + 2);
    query[0].qtype = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    query[0].qclass = ntohs(*(unsigned short *)ptr);
    ptr += 2;
    // printf("query %s\n", &query[0].name);
    //  printf("%X\n",query[0].qtype);

    // char *domain_ptr = &query[0].name; // ptr指向name
    // const char s[2] = ".";
    // char *domain_dup = strdup(&query[0].name); // 用于分割
    // char *token = strtok(domain_dup, s);
    // char *token_ptr;//为了获取最后一次token
    // while (token != NULL)
    // {
    //     token_ptr=token;
    //     token = strtok(NULL, s);
    // }
    // free(domain_dup);
    // return token_ptr;//返回的是顶级域名
    return &query[0].name;
}

char *DNS_parse_top_level(char *domain)
{
    char *domain_ptr = domain; // ptr指向name
    const char s[2] = ".";
    char *domain_dup = strdup(domain); // 用于分割
    char *token = strtok(domain_dup, s);
    char *token_ptr; // 为了获取最后一次token
    memset(token_ptr,0x00,NAME_LEN);
    while (token != NULL)
    {
        token_ptr = token;
        token = strtok(NULL, s);
        
    }
      
    return token_ptr; // 返回的是顶级域名
}

unsigned short DNS_table_init(struct DNS_RR *answer, char *path, char *domain) // 这时，传进来的domain是顶级域名
{
    char *buffer = malloc(MESSAGE_LEN);
    char *data_list[10]; // 存放buffer中读到的记录
    FILE *file = fopen(path, "ab+");
    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    int i = 0;
    memset(rr, 0x00, sizeof(struct DNS_RR));

    if (!file)
    {
        printf("No file!\n");
        return -1;
    }
    while (i < 10)
    {
        int query_state = 0;      // 表明查询状态，查到为1
        int query_name_state = 0; // 查name

        data_list[i] = (char *)malloc(sizeof(char) * 200);
        if (fgets(data_list[i], 1000, file) == NULL)
        { // 如果错误或者读到结束符，就返回NULL；
            // printf("%X num.\n",answerNum);
            break;
        }
        else
        {
            char *ret = strchr(data_list[i], '\n');
            *ret = '\0'; // 替换行末尾换行符
            char *p = strtok(data_list[i], " ");
            strncpy(rr->name, p, MESSAGE_LEN);
            if (strcmp(rr->name, domain) == 0)
            {
                // printf("Yes name.\n");   //查询到
                // printf("init request%s\n",rr->name);
                query_name_state = 1;
            }

            p = strtok(NULL, " ");
            rr->ttl = atoi(p);
            // printf("%X\n",rr->ttl);

            p = strtok(NULL, " ");
            rr->rclass = *(unsigned short *)p;
            if (rr->rclass == IN_ASCII) // 0x4E49对应class IN
                rr->rclass = CLASS_IN;
            // printf("%X\n",rr->rclass);

            p = strtok(NULL, " ");
            rr->type = *(unsigned short *)p;
            if (rr->type == A_ASCII)
            { // 0x41对应type A
                rr->type = TYPE_A;
            }
            rr->data_len = 4;

            p = strtok(NULL, " ");
            strncpy(rr->rdata, p, MESSAGE_LEN);
            // printf("%s\n",rr->rdata);

            if (query_name_state)
            { // 查询到，break
                // answer的name段
                char *ptr = &answer[0].name; // ptr指向name,&不确定
                *ptr = strlen(rr->name);
                strncpy(ptr + 1, rr->name, strlen(rr->name) + 1);
                // type字段
                answer[0].type = htons(rr->type);
                // class字段
                answer[0].rclass = htons(rr->rclass);
                // ttl字段
                answer[0].ttl = htons(rr->ttl);
                // data length字段

                if (rr->type == TYPE_A)
                {
                    answer[0].data_len = htons((unsigned short)4);
                    // address字段
                    struct in_addr netip = {0};
                    inet_aton(rr->rdata, &netip);
                    memcpy(&answer[0].rdata, (char *)&netip.s_addr, sizeof((char *)&netip.s_addr));
                }
            }
        }
    }
    fclose(file);
    return 0;
}

int DNS_header_create(struct DNS_Header *header)
{
    if (header == NULL)
    {
        printf("Header wrong!\n");
        return -1;
    }

    memset(header, 0x00, sizeof(struct DNS_Header));
    srandom(time(NULL)); // linux下
    header->id = random();
    // srand(time(NULL)); //windows下
    // header->id = rand();
    header->tag = htons(0x8000);
    header->queryNum = htons(0x0001);  // 假定只有一条记录
    header->answerNum = htons(0x0000); // root服务器给出authority RR
    header->authorNum = htons(0x0001);
    header->addNum = htons(0x0000);

    return 0;
}

int DNS_query_create(struct DNS_Query *query, char *domain, unsigned short type) // 这里传的domain是damain本身，不是顶级域名
{
    if (query == NULL || domain == NULL)
    {
        printf("Fail to create query.\n");
        return -1;
    }
    memset(query, 0x00, sizeof(struct DNS_Query));
    // query->name=malloc(sizeof(domain)+2);
    query->length = strlen(domain) + 2;
    char *ptr = query->name; // ptr指向name
    const char s[2] = ".";
    char *domain_dup = strdup(domain); // 用于分割
    char *token = strtok(domain_dup, s);
    while (token != NULL)
    {
        size_t len = strlen(token);
        *ptr = len;
        ptr++;
        strncpy(ptr, token, len + 1);
        ptr += len;
        token = strtok(NULL, s);
    }
    free(domain_dup);
    query->qtype = htons(type);
    query->qclass = htons(0x0001);
    return strlen(domain);
}

int DNS_build(struct DNS_Header *header, struct DNS_Query *query, struct DNS_RR *answer, char *response) // tcp比udp多了一个字节用于记录报文长度
{
    if (header == NULL || query == NULL || answer == NULL || response == NULL)
    {
        printf("DNS build failed.\n");
        return -1;
    }

    int offset = 2; // response前两位存长度
    memset(response, 0x00, MESSAGE_LEN);

    memcpy(response + offset, header, sizeof(struct DNS_Header));
    offset += sizeof(struct DNS_Header);

    memcpy(response + offset, query->name, query->length);
    offset += query->length;

    memcpy(response + offset, &query->qtype, sizeof(query->qtype));
    offset += sizeof(query->qtype);
    memcpy(response + offset, &query->qclass, sizeof(query->qclass));
    offset += sizeof(query->qclass);

    int num = ntohs(header->authorNum);
    for (int i = 0; i < num; i++)
    {
        memcpy(response + offset, &answer[i].name, strlen(&answer[i].name) + 1);
        offset += (strlen(&answer[i].name) + 1);
        memcpy(response + offset, &answer[i].type, sizeof(answer[i].type));
        offset += sizeof(answer[i].type);
        memcpy(response + offset, &answer[i].rclass, sizeof(answer[i].rclass));
        offset += sizeof(answer[i].rclass);

        memcpy(response + offset, &answer[i].ttl, sizeof(answer[i].ttl));
        offset += sizeof(answer[i].ttl);

        memcpy(response + offset, &answer[i].data_len, sizeof(answer[i].data_len));
        offset += sizeof(answer[i].data_len);

        memcpy(response + offset, &answer[i].rdata, ntohs(answer[i].data_len));
        offset += ntohs(answer[i].data_len);
        
    }
    unsigned short data_len=htons((unsigned short)(offset-2));
    memcpy(response, &data_len, 2);
    return offset;
}
int DNS_tcp()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0); // 若成功则返回一个sockfd (套接字描述符)

    struct sockaddr_in server_sockaddr; // 一般是储存地址和端口，用于信息的显示及存储作用
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(DNS_SERVER_PORT);              // 将一个无符号短整型数值转换为网络字节序，即大端模式
    //server_sockaddr.sin_addr.s_addr =htonl(INADDR_ANY);
    server_sockaddr.sin_addr.s_addr = inet_addr(DNS_ROOT_ADDRESS); 

    if (bind(sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, QUEUE) == -1)
    {
        perror("listen");
        exit(1);
    }
    struct sockaddr_in client_addr;
    socklen_t length = sizeof(client_addr);
    

    while (1)
    {
        int fd = accept(sockfd, (struct sockaddr *)&client_addr, &length);
        if (fd < 0){
            perror("connect");
            exit(1);
        }
        char request[MESSAGE_LEN] = {0};
        int m=recv(fd,request,MESSAGE_LEN,0);
        printf("receive len = %d\n",m);
        char *domain=DNS_request_parse(request);
        char *top_level=DNS_parse_top_level(domain);
        unsigned short type = ntohs(*(unsigned short *)(request + strlen(domain) + 16));//16=header+length

        struct DNS_RR *answer = calloc(1,sizeof(struct DNS_RR));
        DNS_table_init(answer,path,top_level);
        struct DNS_Header header={0};
        DNS_header_create(&header);

        struct DNS_Query *query = calloc(1,sizeof(struct DNS_Query));
        DNS_query_create(query,domain,type);

        char response[MESSAGE_LEN]={0};
        int offset=DNS_build(&header,query,answer,response);
        int send_len=send(fd,response,offset,0);
        printf("send len= %d\n",send_len);
        close(fd);
    }
    
    return 0;
}