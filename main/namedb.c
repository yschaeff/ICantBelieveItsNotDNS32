#include <stdlib.h>
#include <string.h>
#include "esp_log.h"

#include "tree.h"
#include "namedb.h"

struct rrset {
    char *owner;
    uint32_t *qtype_class;
    int num;
    char **payload;
};

int
namedb_insert(struct namedb *namedb, char *owner, char *payload)
{
    struct rrset *rrset = malloc(sizeof(struct rrset));
    if (!rrset) return 1;
    rrset->owner = owner;
    rrset->qtype_class = (uint32_t*)payload;
    rrset->num = 1;
    rrset->payload = malloc(sizeof(char*));
    if (!rrset->payload) {
        free(rrset);
        return 1;
    }
    rrset->payload[0] = payload;
    return tree_insert(namedb->tree, rrset);
}

char *
namedb_lookup(struct namedb *namedb, char *owner, char *payload)
{
    struct rrset *rrset = malloc(sizeof(struct rrset));
    if (!rrset) return NULL;
    rrset->owner = owner;
    rrset->qtype_class = (uint32_t*)payload;
    rrset->num = 0;
    rrset->payload = NULL;
    return tree_lookup(namedb->tree, rrset);
}

/*BEWARE this function might free(a.owner). as a consequence when deleting
 * nodes we don't know if we can free owner. */
static int
namedb_compare(void *a, void *b)
{
    struct rrset *left = a;
    struct rrset *right = b;
    if (*left->qtype_class - *right->qtype_class)
        return *left->qtype_class - *right->qtype_class;
    int c = strcmp(left->owner, right->owner);
    /*Horrid memory optimization. */
    /*No DONT DO IT it is as evil as you initially thought it would be*/
    /*If you do lookups and fail you are no longer sure if you can free owner*/
    /*if (!c && left->owner != right->owner) {*/
        /*free(left->owner);*/
        /*left->owner = right->owner;*/
    /*}*/
    return c;
}

static void
namedb_merge(void *a, void *b)
{
    struct rrset *from = a;
    struct rrset *to = b;
    /*This should also work if one or both are empty;*/
    to->payload = realloc(to->payload, (to->num + from->num) * sizeof(char*));
    if (!to->payload) return; /*needed in case of malloc failure*/
    while (from->num) {
        to->payload[to->num] = from->payload[from->num -1];
        from->num--;
        to->num++;
    }
    free(from->owner);
    free(from->payload);
    free(from);
}

struct namedb *
namedb_init()
{
    struct namedb *namedb;
    namedb = malloc(sizeof(struct namedb));
    if (!namedb) return NULL;
    namedb->tree = tree_init(namedb_compare, namedb_merge);
    if (namedb->tree) return namedb;
    free(namedb);
    return NULL;
}

