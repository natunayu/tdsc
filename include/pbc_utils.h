#ifndef PBC_UTILS_H
#define PBC_UTILS_H

#include <pbc/pbc.h>

/**
 * pairing をパラメータファイルから初期化する
 * @param pairing (out) 初期化済み pairing_t
 * @param param_file (in) PARAM ファイルのパス
 * @return  0: 成功, -1: エラー
 */
int pairing_init_from_file(pairing_t pairing, const char *param_file);

/**
 * element の配列をまとめてファイルに保存
 * ディレクトリがなければ作成します。
 *
 * @param elems    (in) 保存する element の配列
 * @param count    (in) elems の要素数 (1 なら単一要素)
 * @param dir      (in) 出力先ディレクトリ (例: "test/pub_params")
 * @param basename (in) ファイル名 (例: "g.pub"  or "groupkey.pub")
 * @param base     (in) 16進なら16、10進なら10
 * @return 0: 成功, -1: エラー
 */
int save_elem(element_t *elems,
              size_t count,
              const char *dir,
              const char *basename,
              int base);
/**
 * ファイルから PBC element を読み込む
 *   ※ 要素はあらかじめ element_init_*() で初期化しておくこと
 * @param e        (in/out) 読み込んだ要素を保持する element_t
 * @param filename (in)     読み込み元ファイルパス
 * @param base     (in)     16進数なら 16, 10進数なら 10
 * @return 0: 成功, -1: エラー
 */
int element_load_from_file(element_t e, const char *filename, int base);

#endif /* PBC_UTILS_H */
