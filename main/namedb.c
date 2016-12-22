#include <stdlib.h>
#include <string.h>
#include "esp_log.h"

#include "tree.h"
#include "namedb.h"

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

struct rrset *
namedb_lookup(struct namedb *namedb, char *owner, char *payload)
{
    ESP_LOGI(__func__, "looking up %s", owner);
    struct rrset rrset = {
        .owner = owner,
        .qtype_class = (uint32_t*)payload
    };
    return tree_lookup(namedb->tree, &rrset);
}

static int
namedb_compare(void *a, void *b)
{
    struct rrset *left = a;
    struct rrset *right = b;
    ESP_LOGI(__func__, "cmp %s %s", left->owner, right->owner);
    if (*left->qtype_class - *right->qtype_class)
        return *left->qtype_class - *right->qtype_class;
    int c = strcmp(left->owner, right->owner);
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

