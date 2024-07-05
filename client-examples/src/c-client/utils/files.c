#include "files.h"

#define INITIAL_BUFFER_SIZE 1024

char *read_line(FILE *file) {
    size_t size = INITIAL_BUFFER_SIZE;
    size_t len = 0;
    char *buffer = malloc(size);
    if (!buffer) {
        perror("Faled to allocate memory");
        return NULL;
    }

    int c;
    while ((c = fgetc(file)) != EOF && c != '\n') {
        if (len + 1 >= size) {
            size += INITIAL_BUFFER_SIZE;
            char *new_buffer = realloc(buffer, size);
            if (!new_buffer) {
                free(buffer);
                perror("Failed to reallocate memory");
                return NULL;
            }
            buffer = new_buffer;
        }
        buffer[len] = c;
        len++;
    }

    if (len == 0 && c == EOF) {
        free(buffer);
        return NULL;
    }

    buffer[len] = '\0';
    return buffer;
}

void readlines(const char *filename, const char **data, size_t num_lines) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    size_t count = 0;
    char *line;
    while (count < num_lines && (line = read_line(file)) != NULL) {
        data[count] = line;
        count++;
    }

    fclose(file);
}

void writelines(const char *filename, const char **data, size_t num_lines) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file for writing");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < num_lines; i++) {
        if (data[i]) {
            fprintf(file, "%s\n", data[i]);
        }
    }

    fclose(file);
}
