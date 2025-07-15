#include "pbc_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>


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



int load_elem(element_t *elems, size_t count, const char *dir, const char *basename, int base) {
    char path[PATH_MAX];
    FILE *fp;
    size_t read_count = 0;
    
    char line_buf[4096]; 

    if (snprintf(path, sizeof(path), "%s/%s", dir, basename) >= (int)sizeof(path)) {
        fprintf(stderr, "Error: path too long: %s/%s\n", dir, basename);
        return -1;
    }
    fp = fopen(path, "r");
    if (!fp) {
        perror("fopen");
        fprintf(stderr, "Error opening file for reading: %s\n", path);
        return -1;
    }

    for (read_count = 0; read_count < count; read_count++) {
        // ファイルから1行読み込む
        if (fgets(line_buf, sizeof(line_buf), fp) == NULL) {
            // ファイルの終端かエラー
            break; 
        }
        // 読み込んだ文字列を元に要素をセット
        if (element_set_str(elems[read_count], line_buf, base) == 0) {
            // 失敗した場合
            fprintf(stderr, "Error parsing element %zu from file: %s\n", read_count, path);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return read_count;
}



// ハッシュ → Zr
void hash_to_Zr(element_t out, element_t X, element_t X_tilde, element_t R, element_t R_tilde) {
  int len1 = element_length_in_bytes(X);
  int len2 = element_length_in_bytes(X_tilde);
  int len3 = element_length_in_bytes(R);
  int len4 = element_length_in_bytes(R_tilde);
  int buf_len = len1+len2+len3+len4;
  unsigned char *buf = malloc(buf_len), *p = buf;

  // バイト列を順番に連結してハッシュ化
  element_to_bytes(p, X);           
  p += len1;
  element_to_bytes(p, X_tilde);     
  p += len2;
  element_to_bytes(p, R);          
  p += len3;
  element_to_bytes(p, R_tilde);

  unsigned char hash[SHA512_DIGEST_LENGTH];
  SHA512(buf, buf_len, hash);
  free(buf);

  //Zrの元にマップ
  element_from_hash(out, hash, SHA512_DIGEST_LENGTH);
}

