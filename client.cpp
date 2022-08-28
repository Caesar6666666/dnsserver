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

#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "114.114.114.114"
#define DNS_HOST 0x01
#define DNS_CNAME 0x05
#define LISTENQ 1024

void err_sys(std::string errstr) {
    std::cout << errstr;
}

struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short questions_num;
    unsigned short answers_num;
    unsigned short authority;
    unsigned short additional;
};

struct dns_question {
    std::string name;
    unsigned short qtype;
    unsigned short qclass;
    int length;
};

struct dns_answer {
    std::string name;
    unsigned short atype;
    unsigned short aclass;
    unsigned int ttl;
    unsigned short datalen;
    std::string ip;
};

struct dns_item {
    std::string domain;
    std::string ip;
};

auto hostname_to_dnsname(const std::string &name) {
    std::string retstring;

    const char delim[2] = ".";
    char *hostname_dup = new char[name.length() + 1];

    strcpy(hostname_dup, name.c_str());

    char *token = strtok(hostname_dup, delim);

    retstring.clear();
    auto cnt = 0;
    while (token != NULL) {
        retstring.resize(retstring.length() + 1);
        size_t len = strlen(token);
        retstring[cnt] = (unsigned char)len;
        cnt++;
        retstring.append(token);
        cnt += strlen(token);
        token = strtok(NULL, delim);
    }
    retstring.resize(retstring.length() + 1);
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
    char buff[1024];

    dns_message() {
        bzero(&header, sizeof(header));
        std::vector<dns_question>().swap(question);
        std::vector<dns_answer>().swap(answer);
    }

    auto dns_create_header(int question_num = 1) {
        bzero(&header, sizeof(dns_header));

        srandom(time(nullptr));
        header.id = random();

        header.flags = htons(0x0100);
        header.questions_num = htons(question_num);
        err_sys("header ok\n");
        return 0;
    }

    auto dns_create_question(std::vector<std::string> &hostname) {
        header.questions_num = htons(hostname.size());
        dns_question question1;
        for (int i = 0; i < hostname.size(); i++) {
            question1.length = hostname[i].length() + 2;
            question1.qtype = htons(1);
            question1.qclass = htons(1);
            question1.name = hostname_to_dnsname(hostname[i]);
            question.push_back(question1);
        }
        err_sys("qeustion ok\n");
    }

    auto dns_build_requestion() {
        if (question.empty()) {
            err_sys("header or question or request error");
            exit(0);
        }
        bzero(buff, sizeof(buff));

        memcpy(buff, &header, sizeof(dns_header));
        auto offset = sizeof(dns_header);
        for (int i = 0; i < question.size(); i++) {
            memcpy(buff + offset, question[i].name.c_str(), question[i].length);
            offset += question[i].length;
            memcpy(buff + offset, &question[i].qtype, sizeof(question[i].qtype));
            offset += sizeof(question[i].qtype);
            memcpy(buff + offset, &question[i].qclass, sizeof(question[i].qclass));
            offset += sizeof(question[i].qclass);
        }
        err_sys("build ok\n");
        return offset;
    }

    auto dns_build_response() {
        if (answer.empty()) {
            err_sys("answer error");
            exit(0);
        }
        bzero(buff, sizeof(buff));
        memcpy(buff, &header, sizeof(dns_header));
        auto offset = sizeof(buff);
    }

    auto dns_parse_response(char *buffer) {
        auto ptr = (unsigned char *)buffer;

        ptr += 4;
        auto query_num = ntohs(*(unsigned short *)ptr);

        ptr += 2;
        auto answer_num = ntohs(*(unsigned short *)ptr);
        header.answers_num = htons(answer_num);
        ptr += 6;
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
        unsigned int ttl;
        unsigned short type, datalen, qclass;

        for (int i = 0; i < answer_num; i++) {
            bzero(aname, sizeof(aname));
            len = 0;

            dns_parse_name((unsigned char *)buffer, ptr, aname, &len);
            ptr += 2;

            type = ntohs(*(unsigned short *)ptr);
            ptr += 2;

            qclass = ntohs(*(unsigned short *)ptr);
            ptr += 2;

            ttl = ntohs(*(unsigned short *)ptr);
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
                    answer.push_back({aname, type, qclass, ttl, datalen, ip});
                    auto ptr1 = (unsigned char *) ptr;
                    for(int i = 0;i < datalen;i ++) {
                        printf("%x ", *(ptr1+i));
                    }
                    printf("\n");
                    // std::cout << aname << " has address " << ip << '\n';
                    // std::cout << "\tTime to live: " << ttl / 60 << " minutes ," << ttl % 60 << " seconds\n";

                    // answers.push_back();
                }

                ptr += datalen;
            }
        }

        ptr += 2;
    }

    auto dns_client_commit() {
        auto sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            err_sys("socket error");
            exit(0);
        }

        sockaddr_in servaddr;
        bzero(&servaddr, sizeof(sockaddr_in));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(DNS_SERVER_PORT);
        servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

        auto ret = connect(sockfd, (sockaddr *)&servaddr, sizeof(servaddr));
        if (ret == 0) {
            std::cout << "connect success\n";
        }

        auto length = dns_build_requestion();

        auto slen = sendto(sockfd, buff, length, 0, (sockaddr *)&servaddr, sizeof(sockaddr));

        char response[1024];
        bzero(response, sizeof(response));
        sockaddr_in addr;
        size_t addr_len = sizeof(sockaddr_in);
        auto n = recvfrom(sockfd, response, sizeof(response), 0, (sockaddr *)&addr, (socklen_t *)&addr_len);
        std::cout << "recvfrom:" << n << '\n';
        // for (int i = 0; i < n; i++) {
        //     printf("%c", response[i]);
        // }

        // for (int i = 0; i < n; i++) {
        //     printf("%x", response[i]);
        // }
        dns_parse_response(response);
        return n;
    }
};

auto dns_parse_request(char *buffer, dns_message &message) {
    auto ptr = (unsigned char *)buffer;
    auto id = ntohs(*(unsigned short *)ptr);
    message.header.id = *(unsigned short *)ptr;
    ptr += 2;

    auto flags = ntohs(*(unsigned short *)ptr);
    message.header.flags = *(unsigned short *)ptr;
    ptr += 2;

    auto questions = ntohs(*(unsigned short *)ptr);
    message.header.questions_num = *(unsigned short *)ptr;
    ptr += 2;

    auto answers = ntohs(*(unsigned short *)ptr);
    message.header.answers_num = *(unsigned short *)ptr;
    ptr += 6;

    char cname[128], aname[128], ip[20], netip[4];
    int len;
    unsigned short qtype, qclass;

    for (int i = 0; i < questions; i++) {
        bzero(aname, sizeof(aname));
        len = 0;

        dns_parse_name((unsigned char *)buffer, ptr, aname, &len);
        ptr += 2;

        qtype = htons(*(unsigned short *)ptr);
        ptr += 2;

        qclass = htons(*(unsigned short *)ptr);
        ptr += 2;

        message.question.push_back({aname, qtype, qclass});
    }

    return message.question.size();
}

auto dns_server() {
    auto listenfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0) {
        err_sys("socket error");
        exit(0);
    }
    sockaddr_in servaddr, cliaddr;
    bzero(&servaddr, sizeof(sockaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_SERVER_PORT);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    auto ret = bind(listenfd, (sockaddr *)&servaddr, sizeof(servaddr));
    pid_t pid;
    socklen_t len;
    for (;;) {
        char request[1024];
        bzero(request, sizeof(request));
        len = sizeof(cliaddr);
        auto n = recvfrom(listenfd,   request, sizeof(request), 0, (sockaddr *)&cliaddr, &len);
        std::cout << "kkk"
                  << "recvfrom:" << n << '\n';
        if ((pid = fork()) == 0) {
            close(listenfd);
            dns_message message;
            int len = dns_parse_request(request, message);
            message.dns_client_commit();
            char response[1024];
            bzero(response, sizeof(response));
            // sendto(sockfd, buff, length, 0, (sockaddr *)&servaddr, sizeof(sockaddr));
        }
    }
    close(listenfd);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        err_sys("input error\n");
        exit(0);
    }
    std::vector<std::string> dns_domains;
    for (int i = 1; i < argc; i++) {
        dns_domains.push_back(argv[i]);
    }
    dns_message message;
    message.dns_create_header();
    message.dns_create_question(dns_domains);
    message.dns_client_commit();
    for (int i = 0; i < message.answer.size(); i++) {
        std::cout << message.answer[i].name << ':' << message.answer[i].ip << '\n';
    }
    // dns_server();
    return 0;
}