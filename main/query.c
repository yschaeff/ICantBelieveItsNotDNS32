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

int
is_compressed(char *name)
{
    while (*name) {
        if ((*name & 0xC0) == 0xC0) return 1;
        name += *name + 1;
    }
    return 0;
}

char *
query_decompress_rdata(char *buf, int buflen, char *owner_end)
{
    if (*((uint16_t *)(owner_end+2)) != CLASS_IN)
        return owner_end;

    uint16_t qtype = *(uint16_t *)owner_end;

    if (qtype == CNAME || qtype == NS) {
        if (!is_compressed(owner_end+10)) return owner_end;
        char *name = query_find_owner_compressed(buf, buflen, owner_end+10);
        char *n = malloc(strlen(name) + 11);
        memcpy(n, owner_end, 8);
        *(int16_t *)(n+8) = htons(strlen(name)+1);
        memcpy(n+10, name, strlen(name)+1);
        free(name);
        return n;
    } else if (qtype == MX) {
        if (!is_compressed(owner_end+12)) return owner_end;
        char *name = query_find_owner_compressed(buf, buflen, owner_end+12);
        char *n = malloc(strlen(name) + 13);
        memcpy(n, owner_end, 8);
        *(int16_t *)(n+8) = htons(strlen(name)+3);
        *(int16_t *)(n+10) = *(uint16_t *)(owner_end + 10);
        memcpy(n+12, name, strlen(name)+3);
        free(name);
        return n;
    } else if (qtype == SOA) {
        /*SOA is a bit difficult. the master server can be compressed as well as*/
        /*the following email address. (but where does it start?). To hack around*/
        /*this always point to the question.*/
        char *n = malloc(10 + 4 + 20);
        memcpy(n, owner_end, 8);
        *(int16_t *)(n+8) = htons(24);
        *(int32_t *)(n+10) = htonl(0xC00CC00C);
        memcpy(n+14, owner_end+10 + ntohs(*(uint16_t *)(owner_end+8)) - 20, 20);
        return n;
    }
    return owner_end;
}

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
            /*for (int j = i-1; j >= 0; j--) { //For canonical ordering*/
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

static char *
query_read_rr2(char *buf, char *last, uint16_t *rrtype, int qr, char **rdata,
    uint16_t **rdatalen)
{
    char *end;
    int r = query_find_owner_uncompressed(buf, &end, last);
    if (r) return NULL;
    if (end + 2 > last) return NULL;
    *rrtype = *(uint16_t *)end;
    end += 2;
    if (qr) return end;
    end += 6;
    if (end > last) return NULL;
    *rdatalen = (uint16_t *)end;
    *rdata = end + 2;
    end += 2 + ntohs(*(uint16_t *)end);
    if (end-1 > last) return NULL;
    return end;
}


int
query_read_rr(char *buf, char *bufend, char **owner_end, uint16_t **rdatalen,
    char **rdata)
{
    uint16_t rtype;
    char *rr =  query_read_rr2(buf, bufend, &rtype, 0, rdata, rdatalen);
    *owner_end = *rdata - 10;
    return rr == NULL;
}

char *
query_find_opt(char *buf, size_t buflen, size_t *optlen)
{
    struct dns_header *hdr;
    hdr = (struct dns_header *)buf;
    if (ntohs(hdr->ad_count) == 0) return NULL;
    char *end, *start = buf;
    uint16_t rrtype, *count, *rdatalen;
    char *last = buf+buflen-1;
    char *rdata;

    count = &hdr->qr_count;
    for (int sec = 0; sec < 4; sec++) {
        for (int rr = 0; rr < ntohs(*count); count++) {
            end = query_read_rr2(start, last, &rrtype, count == &hdr->qr_count, &rdata, &rdatalen);
            if (!end) return NULL;
            if (count == &hdr->ad_count) {
                if (rrtype == OPT) {
                    *optlen = end-start;
                    return start;
                }
            }
            start = end;
        }
    }
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

/*Caller is supposed to sanity checks before calling*/
void
query_to_formerr(char *buf)
{
    buf[2] = 0x84 | (buf[2]&0x01);
    buf[3] = 0x01;
}
/*Caller is supposed to sanity checks before calling*/
void
query_to_nxdomain(char *buf)
{
    buf[2] = 0x84 | (buf[2]&0x01);
    buf[3] = 0x03;
}

size_t
query_reply_from_rrset(char *query, size_t qlen, char *payload,
    char *answer, size_t alen, char **rr, size_t rr_count, char *rrsig)
{
    struct dns_header *hdr;
    char *p;
    memcpy(answer, query, (payload-query) + 8); /*hdr + question*/
    answer[2] = 0x84 | (query[2]&0x01);
    answer[3] = 0x00;
    hdr = (struct dns_header *)answer;
    hdr->qr_count = htons(1);
    hdr->an_count = htons((uint16_t)rr_count);
    hdr->au_count = 0;
    hdr->ad_count = 0;
    p = answer + (payload - query) + 4;
    for (size_t i = 0; i < rr_count; i++) {
        *(uint16_t *)p = htons(0xC00C);
        uint16_t rdata_len = ntohs(*(uint16_t *)(rr[i]+8));
        memcpy(p+2, rr[i], 10+rdata_len);
        p += 12 + rdata_len;
    }
    /*TODO: rrsig*/
    return p - answer;
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
