#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdlib.h>

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

/*void bootstrap(char *master, char *zone)*/
/*{*/

/*}*/
