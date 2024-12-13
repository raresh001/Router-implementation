#include <iostream>

#include "include/router.hpp"

int main(int argc, char *argv[]) {
	init(argc - 2, argv + 2);

    try {
        Router *router = new Router(argv[1]);
        router->run();
        delete router;
    } catch (exception &e) {
        cerr << "Error occured: " << e.what() << endl;
        return -1;
    }

	return 0;
}
