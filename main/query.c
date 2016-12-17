#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdlib.h>

#include "esp_log.h"
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
int
query_find_owner_uncompressed(char *start, char **end, char *bufend)
{
    *end = start;
    while (**end != 0) {
        if (((**end) & 0xC0) == 0xC0) {
            *end += 1;
            break;
        }
        if (*end + **end + 1 > bufend) return 1;
        *end += **end + 1;
    }
    *end += 1;
    return 0;
}

uint16_t query_pkt_qr_count(char *buf) {
    struct dns_header *hdr = (struct dns_header *) buf;
    return ntohs(hdr->qr_count);
}
uint16_t query_pkt_an_count(char *buf) {
    struct dns_header *hdr = (struct dns_header *) buf;
    return ntohs(hdr->an_count);
}
uint16_t query_pkt_au_count(char *buf) {
    struct dns_header *hdr = (struct dns_header *) buf;
    return ntohs(hdr->au_count);
}
uint16_t query_pkt_ad_count(char *buf) {
    struct dns_header *hdr = (struct dns_header *) buf;
    return ntohs(hdr->ad_count);
}

void
printx(char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (!((i+1)%8)) printf("\n");
        else if (!((i+1)%4)) printf("   ");
    }
    printf("\n");
}

int
query_read_rr(char *buf, char *bufend, char **owner_end, uint16_t **qtype, uint16_t **qclass, uint32_t **ttl, uint16_t **rdatalen, char **rdata)
{
    /*printx(buf, 40);*/
    ESP_LOGD(__func__, "starting from %p", buf);
    if (query_find_owner_uncompressed(buf, owner_end, bufend)) return 1;
    ESP_LOGD(__func__, "ownerend from %p (%d)", *owner_end, *owner_end-buf+1);
    *qtype    = (uint16_t *)(*owner_end + 0);
    ESP_LOGD(__func__, "qtype from %p", *qtype);
    *qclass   = (uint16_t *)(*owner_end + 2);
    ESP_LOGD(__func__, "qclass from %p", *qclass);
    *ttl      = (uint32_t *)(*owner_end + 4);
    ESP_LOGD(__func__, "ttl from %p", *ttl);
    *rdatalen = (uint16_t *)(*owner_end + 8);
    ESP_LOGD(__func__, "rdatalen from %p", *rdatalen);
    *rdata    = (*owner_end + 10);
    ESP_LOGD(__func__, "rdata from %p", *rdata);
    return 0;
}

size_t query_dns_reply(char *inb, size_t inn, char *outb, size_t outn)
{
    struct dns_header *hdr;
    if (inn < 12) return 0;

    hdr = (struct dns_header *) inb; //BAM! no more memcpy!
    /*printf("%d, %d, %d, %d, %d\n", ntohs(hdr->id), ntohs(hdr->qr_count), ntohs(hdr->an_count),*/
        /*ntohs(hdr->au_count), ntohs(hdr->ad_count));*/

    if (hdr->answer_flag) return 0;
    if (ntohs(hdr->opcode) != 0) return 0;
    if (ntohs(hdr->qr_count) == 0) return 0;
    if (inn < 13) return 0;

    char *owner_end;
    if (query_find_owner_uncompressed(inb+12, &owner_end, inb+inn)) return 0;
    if (owner_end + 2*(sizeof (uint16_t)) > inb + inn) return 0;

    uint16_t *qtype, *qclass;
    qtype  = (uint16_t *)(owner_end + 0);
    qclass = (uint16_t *)(owner_end + 2);

    /*printf("type: %d, class: %d\n", ntohs(*qtype), ntohs(*qclass));*/

    memmove(outb, inb, inn);
    return inn;
}

/*Construct AXFR query from header and q_record.*/
char *
query_axfr_msg(char *qhdr, char *query, int tcp, size_t *s)
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

