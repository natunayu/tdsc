#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> 
#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>  
#include <sys/stat.h>   
#include <sys/types.h>
#include "pbc_utils.h"


typedef struct {
  element_t *gpk;
  element_t *msk;
} group_params;



// g, g_hatの生成
void setup(pairing_t pairing, element_t g, element_t g_hat, const char* param_path) {
  char param[1024];
  FILE* paramfile = fopen(param_path, "r");
  if (!paramfile) {
    fprintf(stderr, "Error opening parameter file\n");
    exit(1);
  }
  size_t count = fread(param, 1, 1024, paramfile);
  if (!count) {
    fprintf(stderr, "Error reading parameter file\n");
    exit(1);
  }
  fclose(paramfile);

  if (pairing_init_set_buf(pairing, param, count)) {
    fprintf(stderr, "Error initializing pairing\n");
    exit(1);
  }

  element_init_G1(g, pairing);
  element_init_G2(g_hat, pairing);
  
  element_random(g);
  element_random(g_hat);
}



// gpk, mskの生成
void keygen(pairing_t pairing, element_t g, element_t g_hat, group_params *params) {
  params->gpk = (element_t*)malloc(13 * sizeof(element_t));
  params->msk = (element_t*)malloc(3 * sizeof(element_t));

  for (int i = 0; i < 11; i++) {
    element_init_G1(params->gpk[i], pairing);
  }
  element_init_G2(params->gpk[11], pairing);
  element_init_G2(params->gpk[12], pairing);

  for (int i = 0; i < 3; i++) {
    element_init_Zr(params->msk[i], pairing);
  }

  element_random(params->gpk[0]); // f
  element_random(params->gpk[1]); // g_tilde
  element_random(params->gpk[2]); // g2
  element_random(params->gpk[3]); // h0
  element_random(params->gpk[4]); // h1
  element_random(params->gpk[5]); // h2

  element_random(params->msk[0]); // gamma_A
  element_random(params->msk[1]); // gamma_B
  element_random(params->msk[2]); // gamma_O

  element_pow_zn(params->gpk[6], params->gpk[0], params->msk[2]); // g1 = f^gamma_O
  element_pow_zn(params->gpk[11], g_hat, params->msk[0]); // vk_A = g_hat^gamma_A
  element_pow_zn(params->gpk[12], g_hat, params->msk[1]); // vk_B = g_hat^gamma_B

  for (int i = 7; i < 11; i++) {
    element_random(params->gpk[i]);
  }
}



int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <pairing_param_file> <ID>\n", argv[0]);
    return 1;
  }

  // 変数定義
  pairing_t pairing;
  element_t g, g_hat;
  group_params params;

  const char *param_path = argv[1];
  const char *id         = argv[2];

  // setup, keygenの実行
  setup(pairing, g, g_hat, param_path);
  keygen(pairing, g, g_hat, &params);

  // IDディレクトリを作成, サブディレクトリ pub_params, user_keys を作成
  if (mkdir(id, 0755) && errno != EEXIST) {
    perror("mkdir ID directory");
    exit(1);
  }

  char dir_pub[512], dir_user[512];
  snprintf(dir_pub,  sizeof(dir_pub),  "%s/pub_params", id);
  snprintf(dir_user, sizeof(dir_user), "%s/user_keys",  id);

  if (mkdir(dir_pub,  0755) && errno != EEXIST) {
    perror("mkdir pub_params");
    exit(1);
  }
  if (mkdir(dir_user, 0755) && errno != EEXIST) {
    perror("mkdir user_keys");
    exit(1);
  }

  // 書き出し
  if (save_elem(&g, 1,     dir_pub, "g",     16) < 0) return EXIT_FAILURE;
  if (save_elem(&g_hat, 1, dir_pub, "g_hat", 16) < 0) return EXIT_FAILURE;  
  if (save_elem(params.gpk, 13, id, "groupkey.pub", 16) < 0) return 1;
  if (save_elem(params.msk, 3, id, "masterkey", 10) < 0) return 1;
  
  // メモリ開放
  for (int i = 0; i < 13; i++)  element_clear(params.gpk[i]);
  for (int i = 0; i <  3; i++)  element_clear(params.msk[i]);
  free(params.gpk);
  free(params.msk);
  element_clear(g);
  element_clear(g_hat);
  pairing_clear(pairing);

  return 0;
}