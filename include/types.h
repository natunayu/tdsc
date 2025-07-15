#ifndef TYPES_H
#define TYPES_H
#include <pbc/pbc.h>


typedef struct {
  element_t *gpk;
  element_t *msk;
  int num_users;
} group_params;

typedef struct {
  element_t *A;
  element_t x;
  int t; // expiry time
} user_key;

typedef struct {
  element_t grt;
  int t; // expiry time
  element_t *A;
} reg_entry;

typedef struct {
  element_t h_t;
  element_t h_t_hat;
  element_t *grt_i_t;
  int num_revoked;
} revocation_list;

typedef struct {
  element_t c1, c2, c3, c4, c5, c6, c7;
  element_t c, sa, sb, sz, s_sigma, sz_prime, s_sigma_prime, su, sx, sd, sd_prime;
} signature;

struct revoke_times {
  double ei_t_time;
  double rl_t_time;
  double total_time;
};

struct ei_t_size {
  size_t h_t_size;          // htのサイズ
  size_t total_B_size;      // 全てのBi,tのサイズ
  size_t total_alpha_size;  // 全てのα'iのサイズ
  size_t total_z_size;      // 全てのz'iのサイズ
  size_t total_v_size;      // 全てのviのサイズ
  size_t total_size;        // 合計サイズ
  int num_nodes;            // ノード数
};


#endif