#ifndef QUERY_H
#define QUERY_H

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

#endif /*QUERY_H*/
