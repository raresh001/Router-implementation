#include "lib.h"

typedef struct radix_tree_node *radix_tree;

struct radix_tree_node {
    struct route_table_entry *entry;
    uint32_t label;
    uint8_t label_size;
    radix_tree left;
    radix_tree right;
};

radix_tree route_data_root;

void f(radix_tree iter, int size) {
    if (iter == NULL)
        return;
    
    if (iter->entry) {
        printf("%x %d\n", iter->entry->prefix, size);
    }

    f(iter->left, 1 + size);
    f(iter->right, 1 + size);
}

void init_routing_data(struct route_table_entry *entries, size_t size) {
    struct route_table_entry *end = entries + size;
    while (entries < end) {
        // represent prefix and mask on host endianness
        entries->prefix = ntohl(entries->prefix);
        entries->mask = ntohl(entries->mask);
        add_route_entry(entries);

        f(route_data_root, 0);

        printf("\n");
        entries++;
    }
}

uint8_t get_mask_size(uint32_t mask) {
    uint8_t count = 0;
    while (mask & 0x80000000) {
        count++;
        mask <<= 1;
    }

    return count;
}

uint8_t get_ip_label_size(uint32_t ip) {
    uint8_t count = 0;
    while ((ip & (1 << count)) == 0) {
        count++;
    }

    return 32 - count;
}

uint8_t count_similar_bits(uint32_t label, uint32_t prefix) {
    return get_mask_size(~(label ^ prefix));
}

radix_tree add_route_rec(radix_tree root, struct route_table_entry *entry) {
    if (root == NULL) {
        printf("Cazul 0\n");
        // create a new tree with entry
        root = calloc(1, sizeof(struct radix_tree_node));
        DIE(root == NULL, "add_route_rec");

        root->entry = entry;
        root->label = entry->prefix;
        root->label_size = get_mask_size(entry->mask);

        return root;
    }

    uint8_t similar_bits = count_similar_bits(root->label, entry->prefix);
    printf("Similar bits: %x and %x is %hhu\n", root->label, entry->prefix, similar_bits);

    if (similar_bits < root->label_size) {
        // insert an intermediary node that contains exactly the similar bits
        // of current node and entry
        printf("Cazul 1 - %x\n", root->label);
        radix_tree intermediary = calloc(1, sizeof(struct radix_tree_node));
        DIE(intermediary == NULL, "add_route_rec");

        // label represent the first similar_bits bits from root->label
        printf("%hhu - %x\n", similar_bits, ~((1 << (32 - similar_bits)) - 1));
        intermediary->label = root->label & ~(((1 << (32 - similar_bits)) - 1));
        printf("Intermediary bits: %x\n", intermediary->label);

        intermediary->label_size = similar_bits;

        printf("%x\n", intermediary->label);

        if (root->label & (1 << (31 - similar_bits))) {
            // current root will be put on the right, and entry will be inserted on the left
            intermediary->right = root;
            intermediary->left = add_route_rec(NULL, entry);
        } else {
            // current root will be put on the left, and entry will be inserted on the right
            intermediary->left = root;
            intermediary->right = add_route_rec(NULL, entry);
        }

        return intermediary;
    }

    if (root->label_size == get_mask_size(entry->mask)) {
        printf("Cazul 2 - %x\n", root->label);
        
        // this node is exactly where we should position entry        
        free(root->entry);
        root->entry = entry;

        return root;
    }

    printf("Cazul 3 - %x\n", root->label);
    // insert entry in the correct child
    if (entry->prefix & (1 << (31 - root->label_size))) {
        root->right = add_route_rec(root->right, entry);
    } else {
        root->left = add_route_rec(root->left, entry);
    }

    return root;
}

void add_route_entry(struct route_table_entry *entry) {
    route_data_root = add_route_rec(route_data_root, entry);
}

struct route_table_entry *find_ip(uint32_t ip) {
    radix_tree iter = route_data_root;
    struct route_table_entry *best = NULL;

    while (iter != NULL) {
        if (iter->entry && ((ip & iter->entry->mask) == iter->entry->prefix)) {
            best = iter->entry;
        }

        printf("AICI\n");
        if (iter->entry) {
            printf("%x\n", iter->entry->prefix);
        }

        #warning TODO_EXIT_WHEN_PREFIX_IS_BAD

        if (ip & (1 << (31 - iter->label_size))) {
            iter = iter->right;
        } else {
            iter = iter->left;
        }
    }

    return best;
}

int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask)  + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
        printf("%d\n", j);
	}
	return j;
}

int main() {
    struct route_table_entry entries[100];
    int size = read_rtable("rtable.txt", entries);

    init_routing_data(&entries, size);

    printf("\n\n\n");
    f(route_data_root, 0);

    printf("%x\n", entries[0].prefix);

    struct route_table_entry *best;
    if (best = find_ip(entries[0].prefix + 7)) {
        printf("Da - %x, %x\n", best->prefix, best->mask);
    }

    return 0;
}
