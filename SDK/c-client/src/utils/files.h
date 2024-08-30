#ifndef FILES_H
#define FILES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void readlines(const char *filename, const char **data, size_t num_lines);
void writelines(const char *filename, const char **data, size_t num_lines);

#endif
