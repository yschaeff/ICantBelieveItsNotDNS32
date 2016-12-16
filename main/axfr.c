#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdlib.h>

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "query.h"


static int
open_tcpsock(char *host)
{
    struct addrinfo *res;
    struct addrinfo const hint = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
    int s;

    int error = getaddrinfo(host, "53", &hint, &res);
    if (error) {
        printf("getaddrinfo failed\n");
        return -1;
    }
    s = socket(res->ai_family, res->ai_socktype, 0);
    if (s < 0) {
        freeaddrinfo(res);
        printf("sock failed\n");
        return -1;
    }
    error = connect(s, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (error) {
        close(s);
        printf("connect failed\n");
        return -1;
    }
    return s;
}

int axfr(char *master, char *zone)
{
    int sock;
    size_t msgout_len;
    uint16_t msgin_len; //network byte order!
    char *msg;
    char *query = "\x09schaeffer\x02tk\x00\x00\xFC\x00\x01";
    char *qhdr = "\xAA\xAA\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    /*char *ns = "10.0.0.10";*/
    char *ns = "ns1.schaeffer.tk";

    if ((sock = open_tcpsock(ns)) < 0) return 1;
    /*SEND AXFR REQUEST*/
    if (!(msg = query_axfr_msg(qhdr, query, 1, &msgout_len))) {
        close(sock);
        printf("construct q failed\n");
        return 1;
    }
    write(sock, msg, msgout_len);
    free(msg);

    /*RECV AXFR*/
    ssize_t l = read(sock, &msgin_len, 2);
    if (l != 2) {
        printf("fail %d\n", l);
        perror("read");
    }
    printf("need to allocate %d bytes\n", ntohs(msgin_len));
    size_t bLeft = ntohs(msgin_len);
    char *axfr = malloc(bLeft);
    char *p = axfr;
    while (bLeft > 0) {
        l = read(sock, p, bLeft);
        /*TODO: handle error*/
        bLeft -= l;
        p += l;
        printf("read %d bytes, %d to go\n", l, bLeft);
    }


    close(sock);
    return 0;
}
