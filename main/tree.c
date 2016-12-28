#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"

#include "tree.h"

enum color {RED, BLACK};

struct node {
    void *value;
    struct node *parent;
    struct node *left;
    struct node *right;
    enum color color;
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

void
rb_tree_rotright(struct tree *tree, struct node *g)
{
    struct node *p = g->left;
    g->left = p->right;
    if (p->right) p->right->parent = g;
    if (!g->parent) {
        tree->root = p;
        p->parent = NULL;
    } else if (g == g->parent->right) {
        g->parent->right = p;
        p->parent = g->parent;
    } else {
        g->parent->left = p;
        p->parent = g->parent;
    }
    p->right = g;
    g->parent = p;
}

void
rb_tree_rotleft(struct tree *tree, struct node *g)
{
    struct node *p = g->right;
    g->right = p->left;
    if (p->left) p->left->parent = g;
    if (!g->parent) {
        tree->root = p;
        p->parent = NULL;
    } else if (g == g->parent->left) {
        g->parent->left = p;
        p->parent = g->parent;
    } else {
        g->parent->right = p;
        p->parent = g->parent;
    }
    p->left = g;
    g->parent = p;
}

void
rb_tree_fix(struct tree *tree, struct node *node)
{
    while (node->parent && node->parent->color == RED) {
        if (node->parent == node->parent->parent->left) {
            struct node *uncle = node->parent->parent->right;
            if (uncle && uncle->color == RED) {
                node->parent->color = BLACK;
                uncle->color = BLACK;
                node->parent->parent->color = RED;
                node = node->parent->parent;
            } else {
                //left right
                if (node == node->parent->right) {
                    node = node->parent;
                    rb_tree_rotleft(tree, node);
                }
                //left left
                node->parent->color = BLACK;
                node->parent->parent->color = RED;
                rb_tree_rotright(tree, node->parent->parent);
            }
        } else {
            struct node *uncle = node->parent->parent->left;
            if (uncle && uncle->color == RED) {
                node->parent->color = BLACK;
                uncle->color = BLACK;
                node->parent->parent->color = RED;
                node = node->parent->parent;
            } else {
                /*right left*/
                if (node == node->parent->left) {
                    node = node->parent;
                    rb_tree_rotright(tree, node);
                }
                //right right
                node->parent->color = BLACK;
                node->parent->parent->color = RED;
                rb_tree_rotleft(tree, node->parent->parent);
            }
        }
    }
    tree->root->color = BLACK;
}

int
tree_insert(struct tree *tree, void *value)
{
    struct node **n;
    struct node *node = malloc(sizeof(struct node));
    if (!node) {
        ESP_LOGE(__func__, "Out of memory!");
        return 1;
    }
    node->parent = NULL;
    node->color = RED;
    node->value = value;
    node->left = node->right = NULL;
    n = &tree->root;

    while ( *n != NULL ) {
        int c = tree->cmp(node->value, (*n)->value);
        if (!c) {
            tree->merge(node->value, (*n)->value);
            free(node);
            return 0;
        }
        node->parent = *n;
        n = ( c < 0 ) ? &(*n)->left : &(*n)->right;
    }
    *n = node;
    rb_tree_fix(tree, node);
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

void
tree_walk_recurse(struct node *node, void cb(void *, int), int lvl)
{
    if (!node) return;
    tree_walk_recurse(node->left, cb, lvl+1);
    cb(node->value, lvl);
    tree_walk_recurse(node->right, cb, lvl+1);
}

void
tree_walk(struct tree *tree, void cb(void *, int))
{
    tree_walk_recurse(tree->root, cb, 0);
}
