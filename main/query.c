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

struct dns_header {
    uint16_t id;
    /*The following 2 bytes have reversed endianess*/
    uint16_t rd_flag     :1; //recursion desired
    uint16_t tc_flag     :1; //truncated response
    uint16_t aa_flag     :1; //authorititive answer
    uint16_t opcode      :4;
    uint16_t answer_flag :1;

    uint16_t rcode       :4;
    uint16_t cd_flag     :1; //checking disabled
    uint16_t ad_flag     :1; //authenticated data
    uint16_t z_flag      :1; //reserved
    uint16_t ra_flag     :1; //recursion enabled

    uint16_t qr_count;
    uint16_t an_count;
    uint16_t au_count;
    uint16_t ad_count;
};

//find end of owner name. 1 on error, 0 otherwise
//On error **end is undefined
int find_owner_uncompressed(char *start, char **end, char *bufend)
{
    *end = start;
    while (**end != 0) {
        if (*end + **end + 1 > bufend) return 1;
        *end += **end + 1;
    }
    return 0;
}


size_t dns_reply(char *inb, size_t inn, char *outb, size_t outn)
{
    struct dns_header *hdr;
    if (inn < 12) return 0;

    hdr = (struct dns_header *) inb; //BAM! no more memcpy!
    printf("%d, %d, %d, %d, %d\n", ntohs(hdr->id), ntohs(hdr->qr_count), ntohs(hdr->an_count),
        ntohs(hdr->au_count), ntohs(hdr->ad_count));

    if (hdr->answer_flag) return 0;
    if (ntohs(hdr->opcode) != 0) return 0;
    if (ntohs(hdr->qr_count) == 0) return 0;
    if (inn < 13) return 0;

    char *owner_end;
    if (find_owner_uncompressed(inb+12, &owner_end, inb+inn)) return 0;
    if (owner_end + 2*(sizeof (uint16_t)) >= inb + inn) return 0;

    uint16_t *qtype, *qclass;
    qtype  = (uint16_t *)(owner_end + 1);
    qclass = (uint16_t *)(owner_end + 3);

    printf("type: %d, class: %d\n", ntohs(*qtype), ntohs(*qclass));

    memmove(outb, inb, inn);
    return inn;
}

static char *
axfr_msg(char *qhdr, char *query, int tcp, size_t *s)
{
    *s = strlen(query) + 1 + 4 + 12;
    if (tcp) *s+=2;
    char *buf = malloc(*s);
    if (!buf) return NULL;
    char *p = buf;
    if (tcp) {
        *((uint16_t *)p) = htons(*s-2);
        p += 2;
    }
    memcpy(p, qhdr, 12);
    p+=12;
    memcpy(p, query, strlen(query) + 1 + 4);

    return buf;
}
    
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

int bootstrap(char *master, char *zone)
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
    if (!(msg = axfr_msg(qhdr, query, 1, &msgout_len))) {
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
