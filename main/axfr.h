#ifndef AXFR_H
#define AXFR_H

#include "namedb.h"

/** Initialte zone transfer and fill database
 *
 * @param master    Address or hostname of the AXFR provider
 * @param zone      Zone to transfer
 * @param namedb    Database to add the records to.
 * @return 1 on error, 0 n success.
 */
int axfr(char *master, char *zone, struct namedb *namedb);

#endif /*AXFR_H*/
