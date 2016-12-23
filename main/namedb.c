#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "lwip/sockets.h"

#include "tree.h"
#include "namedb.h"

#define CNAME (htons(5))
#define RRSIG (htons(46))
#define NSEC  (htons(47))
#define NSEC3 (htons(50))

int
namedb_insert(struct namedb *namedb, char *owner, char *payload)
{
    struct rrset *rrset = malloc(sizeof(struct rrset));
    if (!rrset) return 1;
    rrset->owner = owner;
    rrset->qtype_class = (uint32_t*)payload;
    /* If this is a rrsig insert it as associated rr instead. But instead
     * if the payload add a rrsig */
    if (*(uint16_t *)payload == RRSIG) {
        rrset->num = 0;
        rrset->rrsig = payload;
        *(uint16_t *)payload = *(((uint16_t *)payload) + 5);
        rrset->payload = NULL;
    } else {
        rrset->rrsig = NULL;
        rrset->num = 1;
        rrset->payload = malloc(rrset->num * sizeof(char*));
        if (!rrset->payload) {
            free(rrset);
            return 1;
        }
        rrset->payload[0] = payload;
    }
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
    /*TODO: for consistency I think we only need to return num and payload and rrsig*/
    return tree_lookup(namedb->tree, &rrset);
}

static int
namedb_compare(void *a, void *b)
{
    struct rrset *left = a;
    struct rrset *right = b;
    ESP_LOGI(__func__, "%s %d - %s %d", left->owner, ntohs(*left->qtype_class), right->owner, ntohs(*right->qtype_class));
    int c = strcmp(left->owner, right->owner);
    if (c) return c;

    if (*(uint16_t*)right->qtype_class == CNAME && !(*(uint16_t*)right->qtype_class == NSEC || *(uint16_t*)right->qtype_class == NSEC3)) {
        /*CNAME matches with everything. Though we still need to cmp CLASS*/
        ESP_LOGE(__func__, "right is CNAME!");
        return *((uint16_t *)left->qtype_class + 1) - *((uint16_t *)right->qtype_class + 1);
    }
    return *left->qtype_class - *right->qtype_class;
}

static void
namedb_merge(void *a, void *b)
{
    struct rrset *from = a;
    struct rrset *to = b;
    uint16_t to_qtype = *(uint16_t*)to->qtype_class;
    ESP_LOGI(__func__, "%s %d - %s %d", from->owner, ntohs(*from->qtype_class), to->owner, ntohs(*to->qtype_class));
    if (to_qtype != CNAME) {
        /*CNAME ocludes everything*/
        /*This should also work if one or both are empty;*/
        to->payload = realloc(to->payload, (to->num + from->num) * sizeof(char*));
        if (!to->payload) return; /*needed in case of malloc failure*/
        while (from->num) {
            to->payload[to->num] = from->payload[from->num -1];
            from->num--;
            to->num++;
        }
    }
    if (from->rrsig)
        to->rrsig = from->rrsig;
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

