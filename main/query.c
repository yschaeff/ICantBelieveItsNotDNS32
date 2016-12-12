#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>//memset
#include <stdlib.h>

#include "query.h"

ssize_t dns_reply(char *inb, size_t inn, char *outb, size_t outn)
{
    memmove(outb, inb, inn);
    return inn;
}


