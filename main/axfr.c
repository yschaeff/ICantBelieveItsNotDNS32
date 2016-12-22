#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdlib.h>
#include <inttypes.h>

#include "esp_log.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "namedb.h"
#include "query.h"

#define DNS_SERVER_PORT CONFIG_DNS_SERVER_PORT

static int
open_tcpsock(char *host)
{
    struct addrinfo *res;
    struct addrinfo const hint = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };
    int s;

    /*int error = getaddrinfo(host, "DNS_SERVER_PORT", &hint, &res);*/
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

static int
process_axfr_msg(char *buf, int buflen, struct namedb *namedb)
{
    char *c = buf + 12;
    char *bufend = buf+buflen-1;

    if (query_find_owner_uncompressed(c, &c, bufend)) return 1;
    if ((c += 4) > bufend) return 1;
    /*We are now at the start of the answer section*/
    uint16_t an_count = query_pkt_an_count(buf);
    for (; an_count; an_count--) {
        if (c >= bufend) {
            ESP_LOGW(__func__, "out of packet with %" PRIu16, an_count);
            break;
        }
        char *owner, *owner_end, *rdata, *next;
        uint16_t *qtype, *qclass, *rdatalen;
        uint32_t *ttl;

        if (query_read_rr(c, bufend, &owner_end, &qtype, &qclass, &ttl, &rdatalen, &rdata)) {
            printf("FAIL\n");
            return 1;
        }
        owner = c;

        //do stuff here
        char *name = query_find_owner_compressed(buf, buflen, owner);
        if (name) {
            query_printname(name);
            printf("\n");
            namedb_insert(namedb, name, owner_end);
        }

        ESP_LOGI(__func__, "len: %" PRIu16, ntohs(*rdatalen));
        c = rdata + ntohs(*rdatalen);
    }
    ESP_LOGI(__func__, "bytes left: %d pkts: %" PRIu16 "/%" PRIu16, bufend-c+1, an_count, query_pkt_an_count(buf));
    return 0;
}

int axfr(char *master, char *zone, struct namedb *namedb)
{
    int sock;
    size_t msgout_len;
    uint16_t msgin_len; //network byte order!
    char *msg;
    char *query = "\x09schaeffer\x02tk\x00\x00\xFC\x00\x01";
    char *qhdr = "\xAA\xAA\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    char *ns = "10.0.0.10";
    /*char *ns = "ns1.schaeffer.tk";*/

    if ((sock = open_tcpsock(ns)) < 0) return 1;
    /*SEND AXFR REQUEST*/
    if (!(msg = query_axfr_msg(qhdr, query, 1, &msgout_len))) {
        close(sock);
        ESP_LOGE("AXFR", "construct q failed\n");
        return 1;
    }
    write(sock, msg, msgout_len);
    free(msg);

    /*RECV AXFR*/
    ssize_t l = read(sock, &msgin_len, 2);
    if (l != 2) {
        ESP_LOGE("AXFR", "fail %d\n", l);
        perror("read");
    }
    ESP_LOGI("AXFR", "need to allocate %d bytes\n", ntohs(msgin_len));
    size_t bLeft = ntohs(msgin_len);
    char *axfr = malloc(bLeft);
    char *p = axfr;
    while (bLeft > 0) {
        l = read(sock, p, bLeft);
        /*TODO: handle error*/
        bLeft -= l;
        p += l;
        ESP_LOGI(__func__, "read %d bytes, %d to go\n", l, bLeft);
    }

    close(sock);
    if (process_axfr_msg(axfr, ntohs(msgin_len), namedb)) {
        ESP_LOGE("AXFR", "failed to process AXFR");
    }
    return 0;
}
