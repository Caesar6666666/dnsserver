#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <sys/fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <map>


#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "10.3.9.44"
#define DNS_HOST 0x01
#define DNS_CNAME 0x05
#define LISTENQ 1024

void err_sys(std::string errstr) {
    std::cout << errstr;
}

// "n...." word means network byte

struct dns_header {
    unsigned short nid;
    unsigned short nflags;
    unsigned short nquestions_num;
    unsigned short nanswers_num;
    unsigned short nauthority;
    unsigned short nadditional;
};

struct dns_question {
    std::string name;
    unsigned short ntype;
    unsigned short nclass;
};

struct dns_answer {
    std::string name;
    unsigned short ntype;
    unsigned short nclass;
    unsigned int nttl;
    unsigned short ndatalen;
    std::string ip;
};

std::map<std::string, std::vector<dns_answer>> dns_cache;

auto hostname_to_dnsname(const std::string &name) {
    std::string retstring;

    const char delim[2] = ".";
    char *hostname_dup = new char[name.length() + 1];

    strcpy(hostname_dup, name.c_str());

    char *token = strtok(hostname_dup, delim);

    retstring.clear();
    auto cnt = 0;
    retstring.resize(name.length() + 2);
    while (token != NULL) {
        auto len = strlen(token);
        retstring[cnt] = (unsigned char)len;
        cnt++;
        for (int i = 0; i < len; i++) {
            retstring[cnt + i] = token[i];
        }
        cnt += len;
        token = strtok(NULL, delim);
    }
    retstring[cnt] = '\0';
    delete[] hostname_dup;
    return retstring;
}

static auto is_pointer(int in) {
    return ((in & 0xC0) == 0xC0);
}

static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len) {
    int flag = 0, n = 0;
    char *pos = out + (*len);
    for (;;) {
        flag = (int)ptr[0];

        if (flag == 0) break;
        if (is_pointer(flag)) {
            n = (int)ptr[1];
            ptr = chunk + n;
            dns_parse_name(chunk, ptr, out, len);
            break;
        } else {
            ptr++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;

            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(pos, ".", 1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}
struct dns_message {
public:
    dns_header header;
    std::vector<dns_question> question;
    std::vector<dns_answer> answer;
    unsigned char buff[1024];

    dns_message() {
        bzero(&header, sizeof(header));
        std::vector<dns_question>().swap(question);
        std::vector<dns_answer>().swap(answer);
    }

    auto clear() {
        bzero(&header, sizeof(header));
        std::vector<dns_question>().swap(question);
        std::vector<dns_answer>().swap(answer);
    }

    auto dns_create_header(int question_num = 1) {
        bzero(&header, sizeof(dns_header));

        srandom(time(nullptr));
        header.nid = random();

        header.nflags = htons(0x0100);
        header.nquestions_num = htons(question_num);
        // err_sys("header ok\n");
        return 0;
    }

    auto dns_create_question(std::vector<std::string> &hostname) {
        header.nquestions_num = htons(hostname.size());

        for (auto it = hostname.begin(); it != hostname.end(); it ++) {
            question.push_back({*it, htons(1), htons(1)});
        }
        // err_sys("qeustion ok\n");
    }

    auto dns_build_requestion() {
        if (question.empty()) {
            err_sys("question or request error");
            exit(0);
        }
        bzero(buff, sizeof(buff));

        memcpy(buff, &header, sizeof(dns_header));
        auto offset = sizeof(dns_header);

        for (auto it = question.begin(); it != question.end(); it++) {
            memcpy(buff + offset, hostname_to_dnsname(it->name).c_str(), it->name.length() + 2);
            offset += it->name.length() + 2;
            memcpy(buff + offset, &it->ntype, sizeof(it->ntype));
            offset += sizeof(it->ntype);
            memcpy(buff + offset, &it->nclass, sizeof(it->nclass));
            offset += sizeof(it->nclass);
        }
        // err_sys("request build success\n");
        return offset;
    }

    auto dns_build_response() {
        if (answer.empty()) {
            err_sys("answer error\n");
            return (unsigned long)0;
        }

        bzero(buff, sizeof(buff));
        memcpy(buff, &header, sizeof(dns_header));
        auto offset = sizeof(dns_header);
        for (auto it = question.begin(); it != question.end(); it++) {
            memcpy(buff + offset, hostname_to_dnsname(it->name).c_str(), it->name.length() + 2);
            offset += it->name.length() + 2;
            memcpy(buff + offset, &it->ntype, sizeof(it->ntype));
            offset += sizeof(it->ntype);
            memcpy(buff + offset, &it->nclass, sizeof(it->nclass));
            offset += sizeof(it->nclass);
        }
        // printf("_____________________\n");
        // for(int i = 0;i < 1024;i ++) {
        //     printf("%d ", *(unsigned char*)(buff+i));
        // }
        // printf("\n");
        // std::cout << "answer size:" << answer.size() << '\n';
        for (auto it = answer.begin(); it != answer.end(); it++) {
            memcpy(buff + offset, hostname_to_dnsname(it->name).c_str(), it->name.length() + 2);
            offset += it->name.length() + 2;
            memcpy(buff + offset, &it->ntype, sizeof(it->ntype));
            offset += sizeof(it->ntype);
            memcpy(buff + offset, &it->nclass, sizeof(it->nclass));
            offset += sizeof(it->nclass);
            memcpy(buff + offset, &it->nttl, sizeof(it->nttl));
            offset += sizeof(it->nttl);
            memcpy(buff + offset, &it->ndatalen, sizeof(it->ndatalen));
            offset += sizeof(it->ndatalen);
            inet_pton(AF_INET, it->ip.c_str(), buff + offset);
            offset += ntohs(it->ndatalen);
        }

        // printf("_____________________\n");
        // for(int i = 0;i < 100;i ++) {
        //     printf("%d ", *(unsigned char*)(buff+i));
        // }
        // printf("\n");
        err_sys("response build success\n");
        return offset;
    }

    auto dns_parse_response(unsigned char *buffer) {
        // std::cout << "dns parse response start\n";
        auto ptr = buffer;

        ptr += 4;
        auto query_num = ntohs(*(unsigned short *)ptr);

        ptr += 2;
        auto answer_num = ntohs(*(unsigned short *)ptr);
        header.nanswers_num = htons(answer_num);
        ptr += 6;
        // std::cout << query_num << ' ' << answer_num << '\n';
        for (int i = 0; i < query_num; i++) {
            for (;;) {
                auto flag = (int)ptr[0];
                ptr += (flag + 1);

                if (flag == 0) break;
            }
            ptr += 4;
        }

        char cname[128], aname[128], ip[20], netip[4];
        int len;
        unsigned long ttl;
        unsigned short type, datalen, qclass;
        std::string anamestring;
        for (int i = 0; i < answer_num; i++) {
            bzero(aname, sizeof(aname));
            len = 0;

            dns_parse_name((unsigned char *)buffer, ptr, aname, &len);
            anamestring = aname;
            ptr += 2;

            type = ntohs(*(unsigned short *)ptr);
            ptr += 2;

            qclass = ntohs(*(unsigned short *)ptr);
            ptr += 2;

            ttl = ntohl(*(unsigned long *)ptr);
            ptr += 4;

            datalen = ntohs(*(unsigned short *)ptr);
            ptr += 2;

            if (type == DNS_CNAME) {
                bzero(cname, sizeof(cname));
                len = 0;
                dns_parse_name((unsigned char *)buffer, ptr, cname, &len);
                ptr += datalen;
            } else if (type == DNS_HOST) {
                bzero(ip, sizeof(ip));
                if (datalen == 4) {
                    memcpy(netip, ptr, datalen);
                    inet_ntop(AF_INET, netip, ip, sizeof(sockaddr));
                    // std::cout << type << ' ' << qclass << ' ' << ttl << ' ' << datalen << '\n';
                    answer.push_back({anamestring, htons(type), htons(qclass), htonl(ttl), htons(datalen), ip});

                    dns_cache[anamestring].push_back({anamestring, htons(type), htons(qclass), htonl(ttl), htons(datalen), ip});
                    // std::cout << aname << " has address " << ip << '\n';
                    // std::cout << "\tTime to live: " << ttl / 60 << " minutes ," << ttl % 60 << " seconds\n";

                    // answers.push_back();
                }

                ptr += datalen;
            } else {
                err_sys("unsupported query type\n");
            }
        }

        ptr += 2;
        // std::cout << "dns parse response start\n";
    }

    auto dns_client_commit() {
        auto sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            err_sys("socket error\n");
            exit(0);
        }

        sockaddr_in servaddr;
        bzero(&servaddr, sizeof(sockaddr_in));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(DNS_SERVER_PORT);
        servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

        auto ret = connect(sockfd, (sockaddr *)&servaddr, sizeof(servaddr));
        if (ret != 0) {
            err_sys("connect error\n");
        }

        auto && length = dns_build_requestion();

        auto && slen = sendto(sockfd, buff, length, 0, (sockaddr *)&servaddr, sizeof(sockaddr));
        std::cout << "sendto server:" << slen << '\n';

        unsigned char response[1024];
        bzero(response, sizeof(response));

        sockaddr_in addr;
        auto && addr_len = sizeof(sockaddr_in);
        auto && n = recvfrom(sockfd, response, sizeof(response), 0, (sockaddr *)&addr, (socklen_t *)&addr_len);
        std::cout << "recvfrom server:" << n << '\n';
        // printf("_____________________\n");
        // for (int i = 0; i < 1024; i++) {
        //     printf("%d ", *(unsigned char *)(response + i));
        // }

        dns_parse_response(response);
        close(sockfd);
        return n;
    }
};

auto dns_parse_request(unsigned char *buffer, dns_message &message) {
    // std::cout << "dns parse request strat\n";
    auto ptr = buffer;
    auto && id = ntohs(*(unsigned short *)ptr);
    message.header.nid = *(unsigned short *)ptr;
    ptr += 2;

    auto && flags = ntohs(*(unsigned short *)ptr);
    message.header.nflags = *(unsigned short *)ptr;
    ptr += 2;

    auto && questions = ntohs(*(unsigned short *)ptr);
    message.header.nquestions_num = *(unsigned short *)ptr;
    ptr += 2;

    auto && answers = ntohs(*(unsigned short *)ptr);
    message.header.nanswers_num = *(unsigned short *)ptr;
    ptr += 6;

    char aname[128];
    int len = 0;
    std::cout << "question header" << id << ' ' << flags << ' ' << questions << ' ' << answers << '\n';

    for (int i = 0; i < questions; i++) {
        // for (int i = 0; i < 15; i++) {
        //     printf("%d ", (int)*(ptr + i));
        // }
        // printf("\n");
        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name(buffer, ptr, aname, &len);
        ptr += len + 2;
        auto && qtype = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        auto && qclass = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        std::cout << aname << ' ' << qtype << ' ' << qclass << '\n';
        message.question.push_back({aname, htons(qtype), htons(qclass)});
    }
    // std::cout << "dns parse request end\n";
}

auto dns_server() {
    auto && listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0) {
        err_sys("socket error");
        exit(0);
    }
    sockaddr_in servaddr, cliaddr;
    bzero(&servaddr, sizeof(sockaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listenfd, (sockaddr *)&servaddr, sizeof(servaddr))) {
        err_sys("bind error\n");
        exit(0);
    }

    dns_message message;
    unsigned char request[1024];
    for (;;) {
        std::cout << "________________________________________\n";
        message.clear();
        bzero(request, sizeof(request));
        auto len = (unsigned int)sizeof(cliaddr);
        auto recv_len = recvfrom(listenfd, request, sizeof(request), 0, (sockaddr *)&cliaddr, &len);
        // char name[20];
        // inet_ntop(AF_INET, &cliaddr.sin_addr.s_addr, name, sizeof(sockaddr));
        std::cout << "recvfrom:" << recv_len << '\n';

        dns_parse_request(request, message);

        for(auto it = message.question.begin();it != message.question.end();it ++) {
            auto it_dns = dns_cache.find(it->name);
            if(it_dns == dns_cache.end()) {
                message.dns_client_commit();
                break;
            }
            else {
                std::cout << "cachecachecache\n";
                for(auto it_cache_answer = it_dns->second.begin(); it_cache_answer != it_dns->second.end();it_cache_answer ++) {
                    message.answer.push_back(*it_cache_answer);
                }
                message.header.nanswers_num = htons(it_dns->second.size());
            }
        }

        auto && response_len = message.dns_build_response();
        auto && send_len = sendto(listenfd, message.buff, response_len, 0, (sockaddr *)&cliaddr, sizeof(cliaddr));
        std::cout << "send to client:" << send_len << '\n';
    }
    close(listenfd);
}

int main(int argc, char *argv[]) {
    // if (argc < 2) {
    //     err_sys("input error\n");
    //     exit(0);
    // }
    // std::vector<std::string> dns_domains;
    // for (int i = 1; i < argc; i++) {
    //     dns_domains.push_back(argv[i]);
    // }
    // dns_message message;
    // message.dns_create_header();
    // message.dns_create_question(dns_domains);
    // message.dns_client_commit();
    // for (int i = 0; i < message.answer.size(); i++) {
    //     std::cout << message.it->name << ':' << message.it->ip << '\n';
    // }
    dns_server();
    return 0;
}