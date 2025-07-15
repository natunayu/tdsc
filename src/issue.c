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

#ifndef MAX_TIME
#define MAX_TIME 2048
#endif



int verify_join(pairing_t pairing, group_params *params, element_t X, element_t X_tilde, element_t s, element_t c) {
  element_t tmp1, tmp2, R_calc, R_tilde_calc;
  element_init_G1(tmp1, pairing);
  element_init_G1(tmp2, pairing);
  element_init_G1(R_calc, pairing);
  element_init_G1(R_tilde_calc, pairing);

  element_pow_zn(tmp1, params->gpk[5], s); //tmp1=h2^s
  element_pow_zn(tmp2, X, c); //tmp2=X^c
  element_div(R_calc, tmp1, tmp2); // R_calc=tmp1/tmp2

  element_pow_zn(tmp1, params->gpk[1], s); //tmp1=g_tilde^s
  element_pow_zn(tmp2, X_tilde, c); //tmp2=X_tilde^c
  element_div(R_tilde_calc, tmp1, tmp2); //R_tilde_calc = tmp1/tmp2

  element_printf("h2=%B\n", params->gpk[5]);
  element_printf("g_tilde_tilde=%B\n", params->gpk[1]);
  element_printf("X=%B\n", X);
  element_printf("X_tilde=%B\n", X_tilde);
  element_printf("R_calc=%B\n", R_calc);
  element_printf("R_tilde_calc=%B\n", R_tilde_calc);
  element_printf("c=%B\n", c);
  element_printf("s=%B\n", s);

  element_t c2;
  element_init_Zr(c2, pairing);

  // c2 = H'( X || X_tilde || R_calc || R_tilde_calc )
  hash_to_Zr(c2, X, X_tilde, R_calc, R_tilde_calc);

  element_printf("c2=%B\n", c2);

  element_clear(tmp1);
  element_clear(tmp2);
  element_clear(R_calc);
  element_clear(R_tilde_calc);
  if (element_cmp(c, c2)==0){
    element_clear(c2);
    return 0;
  }
  else{
    element_clear(c2);
    return -1;
  }
}



int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <pairing_param_file> <ID> <USERID>\n", argv[0]);
    return 1;
  }

  pairing_t pairing;
  element_t g_tilde, c, s, X, X_tilde;
  group_params params;

  const char *param_path = argv[1];
  const char *id         = argv[2];
  const char *userid     = argv[3];

  char dir_pub[512];
  snprintf(dir_pub,  sizeof(dir_pub),  "%s/pub_params", id);
  char usr_dir[1024];
  snprintf(usr_dir,  sizeof(usr_dir),  "%s/user_keys/%s", id, userid);

  // ファイルの読み込み
  pairing_init_from_file(pairing, param_path); //ペアリング

  element_init_G1(X, pairing);
  element_init_G1(X_tilde, pairing);
  element_init_Zr(s, pairing);
  element_init_Zr(c, pairing);

  if (load_elem(&X, 1, usr_dir, "X", 16) < 0) return EXIT_FAILURE; // X
  if (load_elem(&X_tilde, 1, usr_dir, "X_tilde", 16) < 0) return EXIT_FAILURE; // X_tilde
  if (load_elem(&s, 1, usr_dir, "s", 16) < 0) return EXIT_FAILURE; // s
  if (load_elem(&c, 1, usr_dir, "c", 16) < 0) return EXIT_FAILURE; // c

  params.gpk = (element_t*)malloc(13 * sizeof(element_t));
  for (int i = 0; i < 11; i++) element_init_G1(params.gpk[i], pairing);
  element_init_G2(params.gpk[11], pairing);
  element_init_G2(params.gpk[12], pairing);

  if (load_elem(params.gpk, 13, id, "groupkey.pub", 16) != 13) return 1; //gpk

  // joinの結果を検証
  if(verify_join(pairing, &params, X, X_tilde, s, c) < 0){
    fprintf(stderr, "ZKP verification for %s failed.\n", userid);
    element_clear(X);
    element_clear(X_tilde);
    element_clear(c);
    element_clear(s);
    pairing_clear(pairing);
    return 0;
  }
  fprintf(stderr, "ZKP verification for %s completed successfully.\n", userid);

  element_clear(X);
  element_clear(X_tilde);
  element_clear(c);
  element_clear(s);
  pairing_clear(pairing);
  return 0;
}