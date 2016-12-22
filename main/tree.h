#ifndef TREE_H
#define TREE_H

struct tree {
    struct node *root;
    int (*cmp)(void *, void *);
    void (*merge)(void *, void *); //also does dedup of owner names
};

struct tree *
tree_init(int (*cmp)(void *, void *), void (*merge)(void *, void *));

int
tree_insert(struct tree *tree, void *value);
#endif
