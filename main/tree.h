#ifndef TREE_H
#define TREE_H

/** This implements a red black tree. So it keeps itself balanced.
 * As a non standard addition will its insert function perform a user
 * supplied merge function when a key is already in the database.
 */

struct tree;

/** Initialize the tree.
 *
 * @param cmp   User supplied function that compares the first two arguments.
 *              returning -1, 0, or 1. Third argument is user data that is 
 *              passed to the lookup function.
 * @param merge User supplied function that merges the first argument in to the second.
 * @return: tree object
 */
struct tree *
tree_init(int (*cmp)(void *, void *, void *), void (*merge)(void *, void *));

/** Insert data in to the tree.
 *
 * @param tree: initialized tree
 * @param value: data to be inserted of the type that is understood by the compare 
 * and merge function.
 * @return: 0 on success, 1 on failure.
 */
int
tree_insert(struct tree *tree, void *value);

/** lookup data in the tree.
 *
 * @param tree: initialized tree
 * @param value: data to be searched for of the type that is understood by the compare 
 * function.
 * @param usr: user data passed to the cmp function
 * @return: object from the tree, NULL if not found.
 */
void *
tree_lookup(struct tree *tree, void *value, void *usr);

/** Walk the tree in order calling cb for every item encountered.
 *
 * \tree: initialized tree
 * \cb: user defined function being passed an item and the depth of the item.
 */
void
tree_walk(struct tree *tree, void cb(void *, int));

#endif
