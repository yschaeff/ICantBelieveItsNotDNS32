#ifndef QUERY_H
#define QUERY_H

//@return number of bytes in reply. 0 on parse error
size_t
dns_reply(char *inb, size_t inn, char *outb, size_t outn);

int
bootstrap(char *master, char *zone);
#endif /*QUERY_H*/
