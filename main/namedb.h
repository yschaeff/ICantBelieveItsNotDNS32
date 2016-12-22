#ifndef NAMEDB_H
#define NAMEDB_H

#include "tree.h"

struct namedb {
    struct tree *tree;
};

struct namedb *
namedb_init();

int
namedb_insert(struct namedb *namedb, char *owner, char *payload);

#endif

