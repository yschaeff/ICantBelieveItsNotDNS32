#ifndef QUERY_H
#define QUERY_H

//@return number of bytes in reply. 0 on parse error
size_t
query_dns_reply(char *inb, size_t inn, char *outb, size_t outn);

char *
query_axfr_msg(char *qhdr, char *query, int tcp, size_t *s);

#endif /*QUERY_H*/
