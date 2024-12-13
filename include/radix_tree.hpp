#ifndef RADIX_TREE_HPP
#define RADIX_TREE_HPP

#include "lib.h"

class radix_tree {
public:
    radix_tree() { root = nullptr; }
    ~radix_tree() { if (root) delete_rec(root); }

    void add_entry(route_table_entry *entry) {
        root = add_route_rec(root, entry);
    }

    route_table_entry *find_best(uint32_t ip);
private:
    struct node;
    node *root;

    // get a mask reprezenting the common part of the 2 IP addresses
    // which is blocked to mask's size
    uint32_t compute_common(uint32_t ip1, uint32_t ip2, uint32_t mask);

    void delete_rec(node *tree);
    node *add_route_rec(node *tree, route_table_entry *entry);
};

#endif  // RADIX_TREE_HPP
