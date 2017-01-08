#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "lwip/sockets.h"

#include "tree.h"
#include "query.h"
#include "namedb.h"

static char*
type_to_name(uint16_t type)
{
    switch (ntohs(type)) {
        case 0x0001: return "A";
        case 0x0002: return "NS";
        case 0x0005: return "CNAME";
        case 0x0006: return "SOA";
        case 0x000F: return "MX";
        case 0x0010: return "TXT";
        case 0x001C: return "AAAA";
        case 0x002E: return "RRSIG";
        case 0x002F: return "NSEC";
        case 0x0030: return "DNSKEY";
        case 0x0032: return "NSEC3";
        /*case 0x0000: return "NSEC3PARAM";*/
    }
    return "???";
}

static void
print_rrset(void *value, int lvl)
{
    struct rrset *rrset = (struct rrset *)value;
    while (lvl--) printf(" ");
    printf("*%s\t%d-%s\t(num=%d)\n", rrset->owner, ntohs(*rrset->qtype_class), type_to_name(*rrset->qtype_class), rrset->num);
}

int
namedb_insert(struct namedb *namedb, char *owner, char *payload)
{
    int r;
    struct rrset *rrset = malloc(sizeof(struct rrset));
    if (!rrset) {
        ESP_LOGE(__func__, "Malloc failure.");
        return 1;
    }
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
    if (*(uint16_t *)payload == NSEC ||*(uint16_t *)payload  == NSEC3) {
        r = tree_insert(namedb->denial_tree, rrset);
        tree_walk(namedb->denial_tree, print_rrset);
    } else {
        r = tree_insert(namedb->tree, rrset);
        tree_walk(namedb->tree, print_rrset);
    }
    return r;
}

struct rrset *
namedb_lookup(struct namedb *namedb, char *owner, char *payload, int *nxdomain)
{
    ESP_LOGD(__func__, "looking up %s", owner);
    struct rrset rrset = {
        .owner = owner,
        .qtype_class = (uint32_t*)payload
    };
    return tree_lookup(namedb->tree, &rrset, nxdomain);
}

static int
namedb_compare(void *a, void *b, void *usr)
{
    ESP_LOGD(__func__, "looking up");
    struct rrset *left = a;
    struct rrset *right = b;
    int c = strcmp(left->owner, right->owner);
    if (c) return c;
    if (usr) *(int *)usr = 0;
    c = *((uint16_t *)left->qtype_class + 1) - *((uint16_t *)right->qtype_class + 1);
    if (c) return c;

    if (*(uint16_t*)right->qtype_class == CNAME) {
        /*CNAME matches with everything.*/
        ESP_LOGV(__func__, "right is CNAME!");
        return 0;
    }
    return *((uint16_t *)left->qtype_class) - *((uint16_t *)right->qtype_class);
}

static void
namedb_merge(void *a, void *b)
{
    struct rrset *from = a;
    struct rrset *to = b;
    uint16_t to_qtype = *(uint16_t*)to->qtype_class;
    uint16_t from_qtype = *(uint16_t*)from->qtype_class;
    ESP_LOGD(__func__, "%s %d - %s %d", from->owner, ntohs(*from->qtype_class), to->owner, ntohs(*to->qtype_class));
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
    namedb->denial_tree = tree_init(namedb_compare, namedb_merge);
    if (namedb->tree) return namedb;
    free(namedb);
    return NULL;
}

