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

#define MAX_LABEL_COUNT 63

//find end of owner name. 1 on error, 0 otherwise
//end will be the first byte not part of the name
//On error **end is undefined
int
query_find_owner_uncompressed(char *start, char **end, char *bufend)
{
    *end = start;
    while (**end != 0) {
        if (((**end) & 0xC0) == 0xC0) {
            (*end)++;
            break;
        }
        if (*end + **end + 1 > bufend) return 1;
        *end += **end + 1;
    }
    (*end)++;
    return 0;
}

/*Return buffer with uncompressed owner name. Result must be freed by caller.*/
/*NULL on error. otherwise \0 terminated string guaranteed. */
char *
query_find_owner_compressed(char *pkt, size_t pktlen, char *start)
{
    char *ptr[MAX_LABEL_COUNT];

    for (size_t i = 0; i < MAX_LABEL_COUNT; i++) {
        if (*start == 0) {
            size_t s = 1;
            for (int j = 0; j < i; j++) s += *ptr[j]+1; /* sum */
            char *r, *rp;
            rp = r = malloc(s * sizeof (char));
            if (!r) {
                ESP_LOGE(__func__, "Unable to allocate buffer.");
                return NULL;
            }
            for (int j = 0; j < i; j++) {
                memcpy(rp, ptr[j], *ptr[j]+1);
                rp += *ptr[j]+1;
            }
            *rp = 0;
            return r;
        }
        while (((*start) & 0xC0) == 0xC0) {
            if (start + 1 >= pkt + pktlen) {
                ESP_LOGE(__func__, "Address read out of bounds");
                return NULL;
            }
            uint16_t jmp = ntohs(*((uint16_t*)start)) ^ 0xC000;
            if (jmp >= pktlen) {
                ESP_LOGE(__func__, "Address target out of bounds %d %d", pktlen, jmp);
                return NULL;
            }
            start = pkt + jmp;
            //todo build loop protection.
        }
        ptr[i] = start;
        start += *start + 1;
        if (start >= pkt + pktlen) {
            ESP_LOGE(__func__, "Label read out of buffer.");
            return NULL;
        }
    }
    ESP_LOGE(__func__, "to many jumps in name");
    return NULL;
}

void
query_printname(char *name)
{
    while (*name != 0) {
        char n = *name;
        for (char *p = name+1; p < name + n+1; p++) {
            putchar(*p);
        }
        putchar('.');
        name += n + 1;
    }
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
        if (!((i+1)%32)) printf("\n");
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

/*Caller is supposed to sanity checks before calling*/
void
query_to_formerr(char *buf)
{
    *(uint16_t *)(buf+2) = htons(0x8401);
}
/*Caller is supposed to sanity checks before calling*/
void
query_to_nxdomain(char *buf)
{
    *(uint16_t *)(buf+2) = htons(0x8403);
}

size_t query_dns_reply(char *inb, size_t inn, char *outb, size_t outn)
{
    struct dns_header *hdr;
    if (inn < 12) return 0;

    hdr = (struct dns_header *) inb; //BAM! no more memcpy!
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

char *
query_axfr_rr(char *z)
{
    char *rr = malloc(strlen(z) + 6); /*This might be to much but never to few*/
    char *l = rr;
    char *p = rr+1;
    *l = 0;
    while (*z) {
        if (*z == '.') {
            *p = 0;
            l = p;
        } else {
            *p = *z;
            (*l)++;
        }
        z++;
        p++;
    }
    *p = 0;
    *(uint32_t *)++p = htonl(0x00FC0001);
    return rr;
}
