#ifndef NAMEDB_H
#define NAMEDB_H

#include "tree.h"

struct namedb {
    struct tree *tree;
};

struct rrset {
    char *owner;
    uint32_t *qtype_class;
    int num;
    char **payload;
};

struct namedb *
namedb_init();

int
namedb_insert(struct namedb *namedb, char *owner, char *payload);

struct rrset *
namedb_lookup(struct namedb *namedb, char *owner, char *payload);

#endif

