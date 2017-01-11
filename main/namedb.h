#ifndef NAMEDB_H
#define NAMEDB_H

/** This unit is a database for RR sets. An RR set consist of a q-tuple
 * (owner, type, class), the resource records and optionally a dnssec
 * signature
 */

struct namedb;

struct rrset {
    char *owner;
    uint32_t *qtype_class;
    int num;
    char **payload;
    char *rrsig;
};
/** \struct rrset namedb.h "main/namedb.h"
 * owner and qtype_class form the qtuple for searches. Owner must not
 * be compressed. Payload is a set of
 * resource records and num their count. Num might be 0. rrsig is signature over
 * the record set. Might be NULL;
 */

/** Initialize database
 *
 * @return NULL on failure, database otherwise
 */
struct namedb *
namedb_init();

/** Insert resource record in to database
 *
 * @param namedb   initialized database
 * @param owner    owner name in wire format. After insert owner by namedb.
 * @param payload  rest of RR starting from type field
 * @return 0 on success, 1 on error.
 */
int
namedb_insert(struct namedb *namedb, char *owner, char *payload);

/** Find RR in database. 
 *
 * @param      namedb   initialized database.
 * @param      owner    owner name in wire format
 * @param      payload  rest of RR starting from type field
 * @param[out] owner_match Target integer will be set to 1 when an RRset is
 *                      encountered with the same owner name.
 * @return RRset on success NULL otherwise.
 */
struct rrset *
namedb_lookup(struct namedb *namedb, char *owner, char *payload, int *owner_match);

#endif

