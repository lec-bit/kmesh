/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef __DESERIALIZATION_TO_BPF_MAP_H__
#define __DESERIALIZATION_TO_BPF_MAP_H__

/* equal MAP_SIZE_OF_OUTTER_MAP */
#define MAX_OUTTER_MAP_ENTRIES        (1 << 20)
#define INIT_OUTTER_MAP_ENTRIES       (8192)
#define OUTTER_MAP_ENTRIES_STEP       (1024)
#define OUTTER_MAP_USAGE_HIGH_PERCENT (0.7)
#define OUTTER_MAP_USAGE_LOW_PERCENT  (0.4)

struct element_list_node {
    void *elem;
    struct element_list_node *next;
};

int deserial_update_elem(void *key, void *value);
void *deserial_lookup_elem(void *key, const void *msg_desciptor);
struct element_list_node *deserial_lookup_all_elems(const void *msg_desciptor);
void deserial_free_elem(void *value);
void deserial_free_elem_list(struct element_list_node *head);
int deserial_delete_elem(void *key, const void *msg_desciptor);

int deserial_init();
void deserial_uninit();

#endif /* __DESERIALIZATION_TO_BPF_MAP_H__ */
