#include "utils/files.h"
#include "dkls23.h"

int main(int argc, const char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: <method> <input_file> <output_file>\n");
        fprintf(stderr, "method: dkg|sign\n");
        return EXIT_FAILURE;
    }

    size_t ins_len, outs_len;

    if (strcmp(argv[1], "dkg") == 0 || strcmp(argv[1], "sign") == 0) {
        ins_len = outs_len = 4;
    } else {
        return EXIT_FAILURE;
    }

    const char* ins[ins_len];
    const char* outs[outs_len];

    readlines(argv[2], ins, ins_len);

    if (strcmp(argv[1], "dkg") == 0) {
        dkg(ins, outs);
    } else if (strcmp(argv[1], "sign") == 0) {
        sign(ins, outs);
    }

    writelines(argv[3], outs, outs_len);

    for (size_t i = 0; i < ins_len; i++) {
        free((void *) ins[i]);
    }

    for (size_t i = 0; i < outs_len; i++) {
        free((void *) outs[i]);
    }
}
