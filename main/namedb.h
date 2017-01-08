#ifndef NAMEDB_H
#define NAMEDB_H

#include "tree.h"

struct namedb {
    struct tree *tree;
    struct tree *denial_tree;
};

struct rrset {
    char *owner; /*Uncompressed owner name. Freeable*/
    uint32_t *qtype_class; /* non-freeable */
    int num;
    char **payload; /* freeable. content not freeable. record
                       on wire exluding owner name */
    char *rrsig; /* non-freeable, Same type as payload */
};

struct namedb *
namedb_init();

int
namedb_insert(struct namedb *namedb, char *owner, char *payload);

struct rrset *
namedb_lookup(struct namedb *namedb, char *owner, char *payload, int *nxdomain);

#endif

