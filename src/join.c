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

#ifndef MAX_TIME
#define MAX_TIME 2048
#endif



typedef struct {
  element_t *gpk;
  element_t *msk;
} group_params;



void join(pairing_t pairing, group_params *params, int user_id, element_t *X, element_t *X_tilde, element_t x) {
  element_random(x);
  element_pow_zn(*X, params->gpk[5], x);      // X = h2^x
  element_pow_zn(*X_tilde, params->gpk[1], x); // X_tilde = g_tilde^x
}



int main(int argc, char *argv[]) {
  pairing_t pairing;
  element_t g, g_hat;
  group_params params;


  element_t X, X_tilde, x;
  element_init_G1(X, pairing);
  element_init_G1(X_tilde, pairing);
  element_init_Zr(x, pairing);





}