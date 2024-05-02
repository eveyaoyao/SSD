/*
 * Student Name: Yueh-Yueh Yao
 * Student ID: D23125333      
 */

#include <stdlib.h>
#include "rijndael.h"

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < 16; i++) {
    block[i] = sbox[block[i]];  // sbox is the substitution box used in AES
  }
}

void shift_rows(unsigned char *block) {
  unsigned char temp[16];

  // copy the original block into temp
  for (int i = 0; i < 16; i++) {
    temp[i] = block[i];
  }

  // shift rows to the left
  for (int i = 0; i < 16; i++) {
    block[i] = temp[(i + (i / 4)) % 16];
  }
}

void mix_columns(unsigned char *block) {
  unsigned char temp[16];

  // copy the original block into temp
  for (int i = 0; i < 16; i++) {
    temp[i] = block[i];
  }

  // mix each column
  for (int i = 0; i < 16; i += 4) {
    block[i] = mul2[temp[i]] ^ mul3[temp[i+1]] ^ temp[i+2] ^ temp[i+3];
    block[i+1] = temp[i] ^ mul2[temp[i+1]] ^ mul3[temp[i+2]] ^ temp[i+3];
    block[i+2] = temp[i] ^ temp[i+1] ^ mul2[temp[i+2]] ^ mul3[temp[i+3]];
    block[i+3] = mul3[temp[i]] ^ temp[i+1] ^ temp[i+2] ^ mul2[temp[i+3]];
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < 16; i++) {
    block[i] = inv_s_box[block[i]];
  }
}

void invert_shift_rows(unsigned char *block) {
  unsigned char temp[16];

  for (int i = 0; i < 16; i++) {
    temp[i] = block[i];
  }

  block[1] = temp[13];
  block[5] = temp[1];
  block[9] = temp[5];
  block[13] = temp[9];

  block[2] = temp[10];
  block[6] = temp[14];
  block[10] = temp[2];
  block[14] = temp[6];

  block[3] = temp[7];
  block[7] = temp[11];
  block[11] = temp[15];
  block[15] = temp[3];
}

void invert_mix_columns(unsigned char *block) {
  unsigned char temp[16];

  for (int i = 0; i < 16; i++) {
    temp[i] = block[i];
  }

  for (int i = 0; i < 16; i += 4) {
    block[i] = mul14[temp[i]] ^ mul11[temp[i+1]] ^ mul13[temp[i+2]] ^ mul9[temp[i+3]];
    block[i+1] = mul9[temp[i]] ^ mul14[temp[i+1]] ^ mul11[temp[i+2]] ^ mul13[temp[i+3]];
    block[i+2] = mul13[temp[i]] ^ mul9[temp[i+1]] ^ mul14[temp[i+2]] ^ mul11[temp[i+3]];
    block[i+3] = mul11[temp[i]] ^ mul13[temp[i+1]] ^ mul9[temp[i+2]] ^ mul14[temp[i+3]];
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < 16; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
    unsigned char *expanded_keys = (unsigned char *)malloc(sizeof(unsigned char) * 176);
    key_expansion(cipher_key, expanded_keys);
    return expanded_keys;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    unsigned char *expanded_keys = expand_key(key);

    // Initial round
    add_round_key(plaintext, expanded_keys); 

    // 9 main rounds
    for (int i = 1; i < 10; i++) {
        sub_bytes(plaintext);
        shift_rows(plaintext);
        mix_columns(plaintext);
        add_round_key(plaintext, expanded_keys + (i * 16));
    }

    // Final round
    sub_bytes(plaintext);
    shift_rows(plaintext);
    add_round_key(plaintext, expanded_keys + 160);

    memcpy(output, plaintext, BLOCK_SIZE);
    free(expanded_keys);

    return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
    unsigned char *expanded_keys = expand_key(key);

    // Initial round
    add_round_key(ciphertext, expanded_keys + 160);

    // 9 main rounds
    for (int i = 9; i > 0; i--) {
        invert_shift_rows(ciphertext);
        invert_sub_bytes(ciphertext);
        add_round_key(ciphertext, expanded_keys + (i * 16));
        invert_mix_columns(ciphertext);
    }

    // Final round
    invert_shift_rows(ciphertext);
    invert_sub_bytes(ciphertext);
    add_round_key(ciphertext, expanded_keys);

    memcpy(output, ciphertext, BLOCK_SIZE);
    free(expanded_keys);

    return output;
}
