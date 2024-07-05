#include "utils/files.h"
#include "dkls23.h"

int main(int argc, const char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: <input_file> <output_file>\n");
        return EXIT_FAILURE;
    }

    const char* ins[4];
    const char* outs[4];

    readlines(argv[1], ins, 4);
    dkg(ins, outs);
    writelines(argv[2], outs, 4);

    for (size_t i = 0; i < 4; i++) {
        free((void *) ins[i]);
        free((void *) outs[i]);
    }
}
