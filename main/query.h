#ifndef QUERY_H
#define QUERY_H

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

void
query_to_formerr(char *buf);

void
query_to_nxdomain(char *buf);

//@return number of bytes in reply. 0 on parse error
size_t
query_dns_reply(char *inb, size_t inn, char *outb, size_t outn);

char *
query_axfr_msg(char *qhdr, char *query, int tcp, size_t *s);

int
query_find_owner_uncompressed(char *start, char **end, char *bufend);

int
query_read_rr(char *buf, char *bufend, char **owner_end, uint16_t **qtype, uint16_t **qclass, uint32_t **ttl, uint16_t **rdatalen, char **rdata);

uint16_t query_pkt_qr_count(char *buf);
uint16_t query_pkt_an_count(char *buf);
uint16_t query_pkt_au_count(char *buf);
uint16_t query_pkt_ad_count(char *buf);

char *
query_find_owner_compressed(char *pkt, size_t pktlen, char *start);

void
query_printname(char *name);

void
printx(char *buf, size_t len);

char *
query_axfr_rr(char *z);

#endif /*QUERY_H*/
