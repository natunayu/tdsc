#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h> 
#include <sys/stat.h>
#include <sys/time.h>
#include <math.h>  
#include <sys/types.h>
#include "types.h"
#include "pbc_utils.h"




void join(pairing_t pairing, group_params *params, element_t X, element_t X_tilde, element_t x, element_t s, element_t c) {
  element_random(x);
  element_pow_zn(X, params->gpk[5], x);      // X = h2^x
  element_pow_zn(X_tilde, params->gpk[1], x); // X_tilde = g_tilde^x

  // ZKPのハッシュ値用
  element_t r, R, R_tilde, tmp;
  element_init_Zr(r,  pairing);
  element_init_G1(R,  pairing);
  element_init_G1(R_tilde, pairing);
  element_init_Zr(tmp, pairing); //tmpはc, xの計算で使うのでZrで初期化

  element_random(r); // rを選択,
  element_pow_zn(R, params->gpk[5], r); //R = h2^r
  element_pow_zn(R_tilde, params->gpk[1], r); //R_tilde = g_tilde^r

  // c = H'( X || X_tilde || R || R_tilde )
  hash_to_Zr(c, X, X_tilde, R, R_tilde);

  element_mul(tmp, c, x);   // tmp = c * x
  element_add(s, r, tmp);   // s = r + c·x

  // element_printf("h2=%B\n", params->gpk[5]);
  // element_printf("g_tilde=%B\n", params->gpk[1]);
  // element_printf("X=%B\n", X);
  // element_printf("X_tilde=%B\n", X_tilde);
  // element_printf("R=%B\n", R);
  // element_printf("R_tilde=%B\n", R_tilde);
  // element_printf("c=%B\n", c);
  // element_printf("s=%B\n", s);

  // join内で使ったメモリの開放
  element_clear(r);
  element_clear(R);
  element_clear(R_tilde);
  element_clear(tmp);
}



int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <pairing_param_file> <ID> <USERID>\n", argv[0]);
    return 1;
  }

  pairing_t pairing;
  element_t g_tilde, c, s, X, X_tilde, x;
  group_params params;

  const char *param_path = argv[1];
  const char *id         = argv[2];
  const char *userid     = argv[3];

  // 初期化
  pairing_init_from_file(pairing, param_path); //ペアリングパラメータ
  element_init_G1(X, pairing); 
  element_init_G1(X_tilde, pairing); 
  element_init_Zr(x, pairing);
  element_init_Zr(s, pairing); 
  element_init_Zr(c, pairing); 

  params.gpk = (element_t*)malloc(13 * sizeof(element_t));
  for (int i = 0; i < 11; i++) element_init_G1(params.gpk[i], pairing);
  element_init_G2(params.gpk[11], pairing);
  element_init_G2(params.gpk[12], pairing);

  if (load_elem(params.gpk, 13, id, "groupkey.pub", 16) != 13) return 1; // gpkの読み込み

  // x, X, X_tilde, s, c の計算
  join(pairing, &params, X, X_tilde, x, s, c);

  // 各ユーザファイル作成
  char user_key_path[512];
  snprintf(user_key_path, sizeof(user_key_path), "%s/user_keys/%s",  id, userid);
  if (mkdir(user_key_path, 0755) && errno != EEXIST) {
    perror("mkdir %ss KeyFile");
    exit(1);
  }

  //x, X, X_tilde, s, cの書き出し
  if (save_elem(&x, 1,     user_key_path, "x",     16) < 0) return EXIT_FAILURE;
  if (save_elem(&X, 1,     user_key_path, "X",     16) < 0) return EXIT_FAILURE;
  if (save_elem(&X_tilde, 1, user_key_path, "X_tilde", 16) < 0) return EXIT_FAILURE;
  if (save_elem(&s, 1,     user_key_path, "s",     16) < 0) return EXIT_FAILURE;
  if (save_elem(&c, 1,     user_key_path, "c",     16) < 0) return EXIT_FAILURE;

  // メモリ開放
  for (int i = 0; i < 13; i++)  element_clear(params.gpk[i]);
  free(params.gpk);
  element_clear(x);
  element_clear(X);
  element_clear(X_tilde);
  element_clear(c);
  element_clear(s);
  pairing_clear(pairing);

  return 0;
}