#ifndef TREE_H
#define TREE_H

struct tree {
    struct node *root;
    int (*cmp)(void *, void *);
    void (*merge)(void *, void *);
};

struct tree *
tree_init(int (*cmp)(void *, void *), void (*merge)(void *, void *));

int
tree_insert(struct tree *tree, void *value);

void *
tree_lookup(struct tree *tree, void *value);

#endif
