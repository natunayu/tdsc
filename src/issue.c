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
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#ifndef MAX_TIME
#define MAX_TIME 2048
#endif





void issue(pairing_t pairing, group_params *params, const char *user_id, int expiry_time, user_key *user_sk, reg_entry *reg, element_t X, element_t X_tilde, element_t g) {
  // パス長 L を expiry_time に合わせて計算
  int L = 0;
  for(int t = expiry_time; t > 0; t >>= 1) { // 2で割り続けて0になるまでの回数をカウント
    L++;
  }

  user_sk->A_len = L;
  user_sk->A_list = malloc(sizeof(element_t) * L); //BBS+署名用のメモリ確保
  user_sk->XI_list = malloc(sizeof(element_t)*L);
  user_sk->Z_list = malloc(sizeof(element_t)*L);
  reg->A_list = malloc(sizeof(element_t) * L); 

  for(int j = 0; j < L; j++){
    element_init_G1(user_sk->A_list[j], pairing); // 署名はG1上
    element_init_Zr(user_sk->XI_list[j], pairing);
    element_init_Zr(user_sk->Z_list[j], pairing);
    element_init_G1(reg->A_list[j],    pairing);
  }

  element_init_G1(reg->rev_token, pairing);
  user_sk->expiry = expiry_time;
  reg->expiry = expiry_time;
  element_set(reg->rev_token, X_tilde); 

  //ここからパスノードの計算
  int *path_nodes = malloc(sizeof(int) * L); //パスノードの配列を確保
  int h = expiry_time;
  int index = L - 1;

  //葉(expiry_time)から根までhを親に辿る
  while (h > 0 && index >= 0) {
    //現在の葉ノード
    //printf("%d, %d\n", h, index);

    //次の葉ノードの計算
    path_nodes[index] = h;
    h = h / 2;      // 親ノードの計算
    index--;
  }

  // 各ノードu_jからBBS+署名を実行してA_jを作成
  for(int j = 0; j < L; j++){
    int u_j = path_nodes[j];
    
    element_random(user_sk->Z_list[j]);
    element_random(user_sk->XI_list[j]);

    // g * h0^Z * h1^{u_j} * X
    element_t tmp1, tmp2, val1, val2;
    element_init_G1(tmp1, pairing);
    element_init_G1(val1, pairing);

    element_pow_zn(tmp1, params->gpk[3], user_sk->Z_list[j]); // h0^Z
    element_mul(val1, g, tmp1); // g*h0^Z

    // h1^{u_j}
    element_t uj_zr; //element powは整数を取れないのでzr上の要素に変換
    element_init_Zr(uj_zr, pairing);
    element_set_si(uj_zr, u_j); // uj_zr = u_j の整数値
    element_pow_zn(tmp1, params->gpk[4], uj_zr); //h1^uj
    element_clear(uj_zr);

    element_mul(val1, val1, tmp1); //g * h0^Z * h1^{u_j} 
    element_mul(val1, val1, X); //*X ,  val2 = g * h0^Z * h1^{u_j} * X

    //指数部分
    element_init_Zr(tmp2, pairing);
    element_init_Zr(val2, pairing);
    element_add(tmp2, user_sk->XI_list[j], params->msk[0]); //XI + gamma_A
    element_invert(val2, tmp2); // (XI + gamma_A){-1}

    // A_j = val2 ^ val1
    element_pow_zn(user_sk->A_list[j], val1, val2);
    // Regにも保存
    element_set(reg->A_list[j], user_sk->A_list[j]);

    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(val1);
    element_clear(val2);

  }

  // gski (ユーザ署名鍵) の出力
  // gski = ({(A_j, XI_j, Z_j), u_i} jE[1.L]) and \tau
// --- gski（ユーザ署名鍵）の出力 ---
fprintf(stdout, "=== gski for user %s ===\n", user_id);
fprintf(stdout, "expiry_time = %d\n", user_sk->expiry);

for(int j = 0; j < L; j++){
  // 各要素を文字列化
  char buf_A[1024], buf_XI[1024], buf_Z[1024];
  element_snprint(buf_A,  sizeof(buf_A),  user_sk->A_list[j]);
  element_snprint(buf_XI, sizeof(buf_XI), user_sk->XI_list[j]);
  element_snprint(buf_Z,  sizeof(buf_Z),  user_sk->Z_list[j]);

  fprintf(stdout,
          "tuple %d: u_j=%d\n"
          "  XI = %s\n"
          "  Z  = %s\n"
          "  A  = %s\n",
          j,
          path_nodes[j],
          buf_XI, buf_Z, buf_A);
}


// revocation token τ (X_tilde) の出力
{
  char buf_tau[1024];
  element_snprint(buf_tau, sizeof(buf_tau), reg->rev_token);
  fprintf(stdout, "revocation token (X_tilde) = %s\n", buf_tau);
}

  //regへユーザ情報の保存
  // (\tau, grti, {A_j}jE[1,L]) to reg[i]

  free(path_nodes);
}



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

  // element_printf("h2=%B\n", params->gpk[5]);
  // element_printf("g_tilde_tilde=%B\n", params->gpk[1]);
  // element_printf("X=%B\n", X);
  // element_printf("X_tilde=%B\n", X_tilde);
  // element_printf("R_calc=%B\n", R_calc);
  // element_printf("R_tilde_calc=%B\n", R_tilde_calc);
  // element_printf("c=%B\n", c);
  // element_printf("s=%B\n", s);

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
  if (argc != 5) {
    fprintf(stderr, "Usage: %s <pairing_param_file> <ID> <USERID> <EXPIRYTIME>\n", argv[0]);
    return 1;
  }

  pairing_t pairing;
  element_t c, s, X, X_tilde;
  group_params params;

  const char *param_path = argv[1];
  const char *id         = argv[2];
  const char *userid     = argv[3];
  int expiry_time = atoi(argv[4]);

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
    // ZKPに失敗したので Issueせず終了
    for (int i = 0; i < 13; i++)  element_clear(params.gpk[i]);
    free(params.gpk);
    element_clear(X);
    element_clear(X_tilde);
    element_clear(c);
    element_clear(s);
    pairing_clear(pairing);
    return 0;
  }

  fprintf(stderr, "ZKP verification for %s completed successfully.\n", userid);
  // ZKPに成功したのでIssueを実行

  // issueで使う要素のロード
  element_t g;
  element_init_G1(g, pairing);
  if (load_elem(&g, 1, dir_pub, "g", 16) < 0) return EXIT_FAILURE; // g
 
  params.msk = (element_t*)malloc(3 * sizeof(element_t));
  for (int i = 0; i < 3; i++) element_init_Zr(params.msk[i], pairing);
  if (load_elem(params.msk, 3, id, "masterkey", 10) != 3) return 1; //msk

  user_key user_sk;
  reg_entry reg;

  // issue
  issue(pairing, &params, userid, expiry_time, &user_sk, &reg, X, X_tilde, g);

  // メモリ開放
  for (int i = 0; i < 13; i++)  element_clear(params.gpk[i]);
  free(params.gpk);
  element_clear(X);
  element_clear(X_tilde);
  element_clear(c);
  element_clear(s);
  pairing_clear(pairing);
  return 0;
}