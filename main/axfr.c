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
        ESP_LOGE(__func__, "getaddrinfo failed");
        return -1;
    }
    s = socket(res->ai_family, res->ai_socktype, 0);
    if (s < 0) {
        freeaddrinfo(res);
        ESP_LOGE(__func__, "sock failed");
        return -1;
    }
    error = connect(s, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (error) {
        close(s);
        ESP_LOGE(__func__, "connect failed");
        return -1;
    }
    return s;
}

static int
process_axfr_msg(char *buf, int buflen, struct namedb *namedb)
{
    char *owner = buf + 12;
    char *bufend = buf+buflen-1;
    char *owner_end, *rdata;
    uint16_t *rdatalen;

    if (query_find_owner_uncompressed(owner, &owner, bufend)) return 1;
    if ((owner += 4) > bufend) return 1;
    /*We are now at the start of the answer section*/
    uint16_t an_count = query_pkt_an_count(buf);
    if (an_count && query_read_rr(owner, bufend, &owner_end, &rdatalen, &rdata)) {
        ESP_LOGE(__func__, "Failed to read starting SOA record");
        return 1;
    }
    owner = rdata + ntohs(*rdatalen);
    for (an_count--; an_count; an_count--) {
        if (owner >= bufend) {
            ESP_LOGW(__func__, "out of packet with %" PRIu16, an_count);
            break;
        }
        if (query_read_rr(owner, bufend, &owner_end, &rdatalen, &rdata)) {
            ESP_LOGE(__func__, "Failed to parse RR");
            return 1;
        }
        owner_end = query_decompress_rdata(buf, buflen, owner_end);
        char *name = query_find_owner_compressed(buf, buflen, owner);
        if (name) namedb_insert(namedb, name, owner_end);
        ESP_LOGV(__func__, "len: %" PRIu16, ntohs(*rdatalen));
        owner = rdata + ntohs(*rdatalen);
    }
    return 0;
}

int axfr(char *master, char *zone, struct namedb *namedb)
{
    int sock;
    size_t msgout_len;
    uint16_t msgin_len; //network byte order!
    char *msg;
    char *query = query_axfr_rr(zone);
    char *qhdr = "\xAA\xAA\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00";

    if ((sock = open_tcpsock(master)) < 0) return 1;
    /*SEND AXFR REQUEST*/
    if (!(msg = query_axfr_msg(qhdr, query, 1, &msgout_len))) {
        free(query);
        close(sock);
        ESP_LOGE(__func__, "construct q failed");
        return 1;
    }
    free(query);
    write(sock, msg, msgout_len);
    free(msg);

    /*RECV AXFR*/
    ssize_t l = read(sock, &msgin_len, 2);
    if (l != 2) {
        ESP_LOGE(__func__, "fail %d", l);
        perror("read");
    }
    ESP_LOGI(__func__, "need to allocate %d bytes", ntohs(msgin_len));
    size_t bLeft = ntohs(msgin_len);
    char *axfr = malloc(bLeft);
    char *p = axfr;
    while (bLeft > 0) {
        l = read(sock, p, bLeft);
        /*TODO: handle error*/
        bLeft -= l;
        p += l;
        ESP_LOGD(__func__, "read %d bytes, %d to go", l, bLeft);
    }

    close(sock);
    if (process_axfr_msg(axfr, ntohs(msgin_len), namedb)) {
        ESP_LOGE("AXFR", "failed to process AXFR");
    }
    return 0;
}
