#include "pbc_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>


int pairing_init_from_file(pairing_t pairing, const char *param_file) {
  FILE *fp = fopen(param_file, "r");
    if (!fp) {
        perror("fopen(param_file)");
        return -1;
    }
    // パラメータファイル全体をバッファに読み込む
    char *buf = NULL;
    size_t buf_size = 0;
    fseek(fp, 0, SEEK_END);
    buf_size = ftell(fp);
    rewind(fp);
    buf = malloc(buf_size);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    if (fread(buf, 1, buf_size, fp) != buf_size) {
        perror("fread");
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (pairing_init_set_buf(pairing, buf, buf_size)) {
        fprintf(stderr, "pairing_init_set_buf failed\n");
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}



int save_elem(element_t *elems, size_t count, const char *dir, const char *basename, int base)
{
    char path[PATH_MAX];
    FILE *fp;

    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }

    if (snprintf(path, sizeof(path), "%s/%s", dir, basename)
        >= (int)sizeof(path)) {
        fprintf(stderr, "path too long: %s/%s\n", dir, basename);
        return -1;
    }

    fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        element_out_str(fp, base, elems[i]);
        fputc('\n', fp);
    }
    fclose(fp);
    
    printf("Generated:\n  %s -> %s/%s\n", basename, dir, basename);
    return 0;
}



int load_elem(element_t e, const char *filename, int base) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen(load)");
        return -1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read = getline(&line, &len, fp);
    fclose(fp);
    if (read < 0) {
        perror("getline");
        free(line);
        return -1;
    }

    if (line[read-1] == '\n') line[read-1] = '\0';

    if (element_set_str(e, line, base)) {
        fprintf(stderr, "element_set_str failed for %s\n", filename);
        free(line);
        return -1;
    }
    free(line);
    return 0;
}
