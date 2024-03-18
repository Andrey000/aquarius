#ifndef RBTREE_H
#define RBTREE_H

#include "common.h"

typedef enum { BLACK, RED } nodeColor;

typedef struct Node_ {
    struct Node_ *left;
    struct Node_ *right;
    struct Node_ *parent;
    nodeColor color;
    CUser data;
} Node;

Node *find(CUser data);
void delete(Node *z);
Node *insert(CUser data);

#endif // RBTREE_H
