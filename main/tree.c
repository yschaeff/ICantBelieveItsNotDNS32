#include <stdlib.h>
#include "esp_log.h"

#include "tree.h"

struct node {
    void *value;
    struct node *left;
    struct node *right;
};

struct tree *
tree_init(int (*cmp)(void *, void *), void (*merge)(void *, void *))
{
    struct tree *tree = malloc(sizeof(struct tree));
    if (!tree) return NULL;
    tree->root = NULL;
    tree->cmp = cmp;
    tree->merge = merge;
    return tree;
}

int
tree_insert(struct tree *tree, void *value)
{
    struct node **parent;
    struct node *node = malloc(sizeof(struct node));
    if (!node) {
        ESP_LOGE(__func__, "Out of memory!");
        return 1;
    }
    node->value = value;
    node->left = node->right = NULL;
    parent = &tree->root;

    while ( *parent != NULL ) {
        int c = tree->cmp(node->value, (*parent)->value);
        if (!c) {
            tree->merge(node->value, (*parent)->value);
            free(node);
            return 0;
        }
        parent = ( c==-1 ) ? &(*parent)->left : &(*parent)->right;
    }
    *parent = node;
    ESP_LOGI(__func__, "insert new");
    return 0;
}

void *
tree_lookup(struct tree *tree, void *value)
{
    struct node *parent = tree->root;
    while (parent) {
        int c = tree->cmp(value, parent->value);
        if (!c) return parent->value;
        parent = (c == -1) ? parent->left : parent->right;
    }
    return NULL;
}

