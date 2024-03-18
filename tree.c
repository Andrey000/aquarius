/* red-black tree */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "aes.h"
#include "tree.h"

#define VOID &guard           /* all leafs are sentinels */
Node guard = { VOID, VOID, 0, BLACK, 0};
Node *root = VOID;

extern int keyLen;
struct AES_ctx_128 ctx128;
struct AES_ctx_192 ctx192;
struct AES_ctx_256 ctx256;

int compLT(CUser user1, CUser user2)
{
    unsigned char password1[PASSWORD_MAX_LEN];
    unsigned char password2[PASSWORD_MAX_LEN];

    memcpy(password1, user1.password, PASSWORD_MAX_LEN);
    memcpy(password2, user2.password, PASSWORD_MAX_LEN);

    switch (keyLen)
    {
    case 128:
        AES_init_ctx_128(&ctx128, key);
        AES_ECB_decrypt_128(&ctx128, password1);

        AES_init_ctx_128(&ctx128, key);
        AES_ECB_decrypt_128(&ctx128, password2);
        break;

    case 192:
        AES_init_ctx_192(&ctx192, key);
        AES_ECB_decrypt_192(&ctx192, password1);

        AES_init_ctx_192(&ctx192, key);
        AES_ECB_decrypt_192(&ctx192, password2);
        break;

    case 256:
        AES_init_ctx_256(&ctx256, key);
        AES_ECB_decrypt_256(&ctx256, password1);

        AES_init_ctx_256(&ctx256, key);
        AES_ECB_decrypt_256(&ctx256, password2);
        break;
    }

    if(strcmp((char*)password1, (char*)password2) < 0)
        return 1;
    else
        return 0;
}

int compEQ(CUser user1, CUser user2)
{
    unsigned char password1[PASSWORD_MAX_LEN];
    unsigned char password2[PASSWORD_MAX_LEN];

    unsigned char login1[LOGIN_MAX_LEN];
    unsigned char login2[LOGIN_MAX_LEN];

    memcpy(password1, user1.password, PASSWORD_MAX_LEN);
    memcpy(password2, user2.password, PASSWORD_MAX_LEN);

    memcpy(login1, user1.login, LOGIN_MAX_LEN);
    memcpy(login2, user2.login, LOGIN_MAX_LEN);

    switch (keyLen)
    {
    case 128:
        AES_init_ctx_128(&ctx128, key);
        AES_ECB_decrypt_128(&ctx128, password1);

        AES_init_ctx_128(&ctx128, key);
        AES_ECB_decrypt_128(&ctx128, password2);
        break;

    case 192:
        AES_init_ctx_192(&ctx192, key);
        AES_ECB_decrypt_192(&ctx192, password1);

        AES_init_ctx_192(&ctx192, key);
        AES_ECB_decrypt_192(&ctx192, password2);
        break;

    case 256:
        AES_init_ctx_256(&ctx256, key);
        AES_ECB_decrypt_256(&ctx256, password1);

        AES_init_ctx_256(&ctx256, key);
        AES_ECB_decrypt_256(&ctx256, password2);
        break;
    }

    if((strcmp((char*)password1, (char*)password2) == 0) && (strcmp((char*)login1, (char*)login2) == 0))
        return 1;
    else
        return 0;
}

void rotL(Node *n) {

   /**************************
    *  rotate node n to left *
    **************************/

    Node *m = n->right;

    /* establish n->right link */
    n->right = m->left;
    if (m->left != VOID) m->left->parent = n;

    /* establish m->parent link */
    if (m != VOID) m->parent = n->parent;
    if (n->parent) {
        if (n == n->parent->left)
            n->parent->left = m;
        else
            n->parent->right = m;
    } else {
        root = m;
    }

    /* link n and m */
    m->left = n;
    if (n != VOID) n->parent = m;
}

void rotR(Node *n) {

   /****************************
    *  rotate node n to right  *
    ****************************/

    Node *m = n->left;

    /* establish n->left link */
    n->left = m->right;
    if (m->right != VOID) m->right->parent = n;

    /* establish m->parent link */
    if (m != VOID) m->parent = n->parent;
    if (n->parent) {
        if (n == n->parent->right)
            n->parent->right = m;
        else
            n->parent->left = m;
    } else {
        root = m;
    }

    /* link n and m */
    m->right = n;
    if (n != VOID) n->parent = m;
}

void insertRepair(Node *n) {

   /*************************************
    *  Balance                          *
    *  after inserting node n           *
    *************************************/

    /* check Red-Black properties */
    while (n != root && n->parent->color == RED) {
        /* we have a violation */
        if (n->parent == n->parent->parent->left) {
            Node *m = n->parent->parent->right;
            if (m->color == RED) {

                /* uncle is RED */
                n->parent->color = BLACK;
                m->color = BLACK;
                n->parent->parent->color = RED;
                n = n->parent->parent;
            } else {

                /* uncle is BLACK */
                if (n == n->parent->right) {
                    /* make n a left child */
                    n = n->parent;
                    rotL(n);
                }

                /* recolor and rotate */
                n->parent->color = BLACK;
                n->parent->parent->color = RED;
                rotR(n->parent->parent);
            }
        } else {

            /* mirror image of above code */
            Node *m = n->parent->parent->left;
            if (m->color == RED) {

                /* uncle is RED */
                n->parent->color = BLACK;
                m->color = BLACK;
                n->parent->parent->color = RED;
                n = n->parent->parent;
            } else {

                /* uncle is BLACK */
                if (n == n->parent->left) {
                    n = n->parent;
                    rotR(n);
                }
                n->parent->color = BLACK;
                n->parent->parent->color = RED;
                rotL(n->parent->parent);
            }
        }
    }
    root->color = BLACK;
}

Node *insert(CUser data)
{
    Node *current, *parent, *n;

    /* find where node belongs */
    current = root;
    parent = 0;
    while (current != VOID) {
        if (compEQ(data, current->data)) return (current);
        parent = current;
        current = compLT(data, current->data) ?
            current->left : current->right;
    }

    /* init new node */
    if ((n = malloc (sizeof(*n))) == 0) {
        printf ("need more memory (insert)\n");
        exit(1);
    }
    n->data = data;
    n->parent = parent;
    n->left = VOID;
    n->right = VOID;
    n->color = RED;

    /* insert node in tree */
    if(parent) {
        if(compLT(data, parent->data))
            parent->left = n;
        else
            parent->right = n;
    } else {
        root = n;
    }

    insertRepair(n);
    return(n);
}

void delRepair(Node *n)
{

   /*************************************
    *  Balance tree                     *
    *  after deleting node n            *
    *************************************/

    while (n != root && n->color == BLACK) {
        if (n == n->parent->left) {
            Node *v = n->parent->right;
            if (v->color == RED) {
                v->color = BLACK;
                n->parent->color = RED;
                rotL (n->parent);
                v = n->parent->right;
            }
            if (v->left->color == BLACK && v->right->color == BLACK) {
                v->color = RED;
                n = n->parent;
            } else {
                if (v->right->color == BLACK) {
                    v->left->color = BLACK;
                    v->color = RED;
                    rotR (v);
                    v = n->parent->right;
                }
                v->color = n->parent->color;
                n->parent->color = BLACK;
                v->right->color = BLACK;
                rotL (n->parent);
                n = root;
            }
        } else {
            Node *v = n->parent->left;
            if (v->color == RED) {
                v->color = BLACK;
                n->parent->color = RED;
                rotR (n->parent);
                v = n->parent->left;
            }
            if (v->right->color == BLACK && v->left->color == BLACK) {
                v->color = RED;
                n = n->parent;
            } else {
                if (v->left->color == BLACK) {
                    v->right->color = BLACK;
                    v->color = RED;
                    rotL (v);
                    v = n->parent->left;
                }
                v->color = n->parent->color;
                n->parent->color = BLACK;
                v->left->color = BLACK;
                rotR (n->parent);
                n = root;
            }
        }
    }
    n->color = BLACK;
}

void delete(Node *d) {
    Node *n, *m;

   /*****************************
    *  delete node d from tree  *
    *****************************/

    if (!d || d == VOID) return;


    if (d->left == VOID || d->right == VOID) {
        /* m has n VOID node as n child */
        m = d;
    } else {
        /* find tree successor with n VOID node as n child */
        m = d->right;
        while (m->left != VOID) m = m->left;
    }

    /* n is y's only child */
    if (m->left != VOID)
        n = m->left;
    else
        n = m->right;

    /* remove m from the parent chain */
    n->parent = m->parent;
    if (m->parent)
        if (m == m->parent->left)
            m->parent->left = n;
        else
            m->parent->right = n;
    else
        root = n;

    if (m != d) d->data = m->data;


    if (m->color == BLACK)
        delRepair (n);

    free (m);
}

Node *find(CUser data) {

   /*******************************
    *  find node containing data  *
    *******************************/

    Node *current = root;
    while(current != VOID)
        if(compEQ(data, current->data))
            return (current);
        else
            current = compLT (data, current->data) ?
                current->left : current->right;
    return(0);
}


