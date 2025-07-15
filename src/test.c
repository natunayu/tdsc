#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "types.h"
#include "pbc_utils.h"

// ---- Fiat–Shamir Schnorr ZKP ----
// 設定: 群 G1 上の生成元 g と秘密鍵 x ∈ Zr、公開鍵 h = g^x を用意。
// 証明生成 (Prover):
//   1. ランダムな r ∈ Zr を選び、コミット t = g^r を計算。
//   2. チャレンジ c = H(g ∥ h ∥ t) ∈ Zr をハッシュで導出。
//   3. レスポンス s = r − x·c ∈ Zr を計算。
//   返却する証明は (t, s)。
// 検証 (Verifier):
//   1. 同様に c = H(g ∥ h ∥ t) を求める。
//   2. 左辺 L = g^s · h^c を計算し、L == t なら検証成功。
// ----------------------------------

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pbc_param_file>\n", argv[0]);
        return 1;
    }

    // 1. pairing の初期化
    pairing_t pairing;
    const char *param_path = argv[1];
    pairing_init_from_file(pairing, param_path);

    // 2. 要素の初期化
    element_t g, h;        // G1 の生成元と公開鍵
    element_t x;           // Zr の秘密鍵
    element_init_G1(g, pairing);
    element_init_G1(h, pairing);
    element_init_Zr(x, pairing);

    // 3. キー生成
    element_random(g);           // ランダムな生成元 g
    element_random(x);           // 秘密鍵 x
    element_pow_zn(h, g, x);     // h = g^x

    // 4. Prover: 証明生成
    element_t r, t;
    element_init_Zr(r, pairing);
    element_init_G1(t, pairing);

    element_random(r);            // r をランダム選択
    element_pow_zn(t, g, r);      // t = g^r

    // 5. チャレンジ c = H(g || h || t) ∈ Zr
    int len_g = element_length_in_bytes(g);
    int len_h = element_length_in_bytes(h);
    int len_t = element_length_in_bytes(t);
    int buf_len = len_g + len_h + len_t;
    unsigned char *buf = malloc(buf_len), *p = buf;
    element_to_bytes(p, g); p += len_g;
    element_to_bytes(p, h); p += len_h;
    element_to_bytes(p, t);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(buf, buf_len, hash);

    element_t c;
    element_init_Zr(c, pairing);
    element_from_hash(c, hash, SHA512_DIGEST_LENGTH); 
    free(buf);

    // 6. レスポンス s = r - x*c
    element_t xc, s;
    element_init_Zr(xc, pairing);
    element_init_Zr(s, pairing);
    element_mul(xc, x, c);       // xc = x*c
    element_sub(s, r, xc);       // s = r - xc

    // 7. 証明 (t, s) を出力
    printf("=== Public parameters ===\n");
    printf("g: "); element_printf("%B\n", g);
    printf("h: "); element_printf("%B\n", h);

    printf("\n=== Proof (t, s) ===\n");
    printf("t: "); element_printf("%B\n", t);
    printf("s: "); element_printf("%B\n", s);

    // 8. Verifier: 検証
    //    再度 c' = H(g || h || t) を計算し、
    //    g^s * h^c' == t かチェック
    // ---- 再ハッシュ ----
    buf = malloc(buf_len);
    p = buf;
    element_to_bytes(p, g); p += len_g;
    element_to_bytes(p, h); p += len_h;
    element_to_bytes(p, t);

    unsigned char hash_ver[SHA512_DIGEST_LENGTH];
    SHA512(buf, buf_len, hash_ver);
    
    element_t c_ver;
    element_init_Zr(c_ver, pairing);
    element_from_hash(c_ver, hash_ver, SHA512_DIGEST_LENGTH);
    free(buf);

    // ---- g^s ----
    element_t gs;
    element_init_G1(gs, pairing);
    element_pow_zn(gs, g, s);

    // ---- h^c ----
    element_t hc;
    element_init_G1(hc, pairing);
    element_pow_zn(hc, h, c_ver);

    // ---- L = g^s * h^c ----
    element_t L;
    element_init_G1(L, pairing);
    element_mul(L, gs, hc);
    printf("L: "); element_printf("%B\n", L);
    // ---- 比較 ----
    if (element_cmp(L, t) == 0) {
        printf("\n[+] Proof verified: OK\n");
    } else {
        printf("\n[-] Proof verified: FAILED\n");
    }

    // 9. リソース解放
    element_clear(g); element_clear(h);
    element_clear(x); element_clear(r);
    element_clear(t); element_clear(c);
    element_clear(xc); element_clear(s);
    element_clear(c_ver);
    element_clear(gs); element_clear(hc); element_clear(L);
    pairing_clear(pairing);

    return 0;
}
