#include "include/radix_tree.hpp"

struct radix_tree::node {
    // all the entries from the tree starting from this node
    // will have the label as a prefix of their ip and their mask
    // will be equal or bigger than label_mask
    uint32_t label;
    uint32_t label_mask;

    // if there is an entry whose ip is exactly label and
    // whose mask is exactly label_mask, it will be pointed by this field
    route_table_entry *entry;

    node *left;
    node *right;

    node(route_table_entry *_entry) {
        entry = _entry;
        label = entry->prefix;
        label_mask = entry->mask;
        left = right = nullptr;
    }

    node(uint32_t _label, uint32_t _label_mask) {
        entry = nullptr;
        label = _label;
        label_mask = _label_mask;
        left = right = nullptr;
    }
};

void radix_tree::delete_rec(radix_tree::node *tree) {
    if (tree->left) {
        delete_rec(tree->left);
    }
    if (tree->right) {
        delete_rec(tree->right);
    }

    delete tree->entry;
    delete tree;
}

uint32_t radix_tree::compute_common(uint32_t ip1, uint32_t ip2, uint32_t mask) {
    uint32_t common = (~(ip1 ^ ip2)) & mask;
    uint32_t aux = 0x80000000;
    while (common & aux) {
        aux >>= 1;
    }

    /* aux has only one bit set, at the first position where the 2 address
     * differ; (~((aux << 1) - 1)) contains 1 from the beginning of the number
     * until this bit and 0 everywhere else
     */
    return common & (~((aux << 1) - 1));
}

radix_tree::node *radix_tree::add_route_rec(radix_tree::node *tree,
                                            route_table_entry *entry) {
    if (tree == nullptr) {
        return new node(entry);
    }

    uint32_t common_mask = compute_common(tree->label, 
                                        entry->prefix, 
                                        tree->label_mask & entry->mask);

    if (common_mask < tree->label_mask) {
        // create an intermediary node, whose label is 
        // the common part of tree->label and entry->prefix
        node *intermediary = new node(tree->label & common_mask, common_mask);

        // test which side tree should be attached to
        if (tree->label & (common_mask >> 1) & (~common_mask)) {
            intermediary->right = tree;
        } else {
            intermediary->left = tree;
        }

        /* If entry->mask is equal to common_mask, then entry->prefix was a
         * prefix of tree->label; in this case, it should be put to
         * intermediary->entry
         */
        if (common_mask == entry->mask) {
            intermediary->entry = entry;
        } else if (intermediary->left) {
            intermediary->right = new node(entry);
        } else {
            intermediary->left = new node(entry);
        }

        return intermediary;
    }

    if (entry->mask == tree->label_mask) {
        // entry should be put exactly here
        if (tree->entry == nullptr) {
            tree->entry = entry;
        }

        return tree;
    }

    // insert entry in the correct child
    if (entry->prefix & (common_mask >> 1) & (~common_mask)) {
        tree->right = add_route_rec(tree->right, entry);
    } else {
        tree->left = add_route_rec(tree->left, entry);
    }

    return tree;
}

route_table_entry *radix_tree::find_best(uint32_t ip) {
    node *iter = root;
    route_table_entry *best = nullptr;

    while (iter) {
        if (iter->label != (ip & iter->label_mask)) {
            // none of the nodes from this subtree can fit ip
            break;
        }

        if (iter->entry) {
            // this is the node with the biggest mask that 
            // fits ip (found until now)
            best = iter->entry;
        }

        // continue searching in the correct child
        if (ip & (iter->label_mask >> 1) & (~iter->label_mask)) {
            iter = iter->right;
        } else {
            iter = iter->left;
        }
    }

    return best;
}
