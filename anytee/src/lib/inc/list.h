/**
 * Bao, a Lightweight Static Partitioning Hypervisor
 *
 * Copyright (c) Bao Project (www.bao-project.org), 2019-
 *
 * Authors:
 *      Jose Martins <jose.martins@bao-project.org>
 *
 * Bao is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free
 * Software Foundation, with a special exception exempting guest code from such
 * license. See the COPYING file in the top-level directory for details.
 *
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <bao.h>
#include <spinlock.h>

typedef void* node_t;
struct list {
    node_t* head;
    node_t* tail;
    spinlock_t lock;
};

struct node_data {
    node_t node;
    void* data;
};

#define list_foreach(list, type, nodeptr)                     \
    for (type* nodeptr = ((type*)list.head); nodeptr != NULL; \
         nodeptr = *((type**)nodeptr))

#define list_foreach_tail(list, type, nodeptr, tail)                \
    for (type* nodeptr = ((type*)list.head), *tail = ((type*)list); \
         nodeptr != NULL; tail = nodeptr, nodeptr = *((type**)nodeptr))

static inline void list_init(struct list* list)
{
    if (list != NULL) {
        list->head = NULL;
        list->tail = NULL;
        list->lock = SPINLOCK_INITVAL;
    }
}

static inline void list_push(struct list* list, node_t* node)
{
    node_t* temp = NULL;
    if (list != NULL && node != NULL) {
        *node = NULL;
        spin_lock(&list->lock);

        if (list->tail != NULL) *list->tail = node;

        temp = node;
        list->tail = node;
        while (*temp != NULL) {
            temp = *temp;
        }
        list->tail = temp;

        if (list->head == NULL) list->head = node;

        spin_unlock(&list->lock);
    }
}

static inline void list_push_front(struct list* list, node_t* node)
{
    if (list != NULL && node != NULL) {
        spin_lock(&list->lock);

        if (list->head != NULL) *node = list->head;

        spin_unlock(&list->lock);
    }
}

static inline node_t* list_pop(struct list* list)
{
    node_t* temp = NULL;
    if (list != NULL) {
        spin_lock(&list->lock);

        if (list->head != NULL) {
            temp = list->head;
            list->head = *list->head;

            if (list->head == NULL) list->tail = NULL;

            *temp = NULL;
        }

        spin_unlock(&list->lock);
    }
    return temp;
}

static inline node_t* list_peek(struct list* list)
{
    node_t* temp = NULL;
    if (list != NULL) {
        temp = list->head;
    }
    return temp;
}

static inline bool list_empty(struct list* list)
{
    return (list->head == NULL);
}

static inline bool list_rm(struct list* list, node_t* node)
{
    if (list != NULL && node != NULL) {
        spin_lock(&list->lock);

        node_t* temp = list->head;
        node_t* temp_prev = NULL;
        while (temp != NULL && temp != node) {
            temp_prev = temp;
            temp = *temp;
        }
        if (temp != NULL && temp == node) {
            /* found the node, remove it */
            if(temp_prev != NULL) {
                *temp_prev = *temp;
            } else {
                list->head = *temp;
            }

            if(list->head == NULL) {
                list->tail = NULL;
            }
        }

        spin_unlock(&list->lock);
    }

    return true;
}

#endif /* __LIST_H__ */
