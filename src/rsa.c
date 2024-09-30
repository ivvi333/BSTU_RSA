#include "rsa.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "asn1.h"
#include "base64.h"
#include "bignum.h"
#include "montgomery.h"

void import_pub_key(rsa_pub_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PUBLIC KEY-----";
    const char end[] = "-----END PUBLIC KEY-----";
    size_t in_size = 2048;
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (beg_idx == 0 && end_idx == pem_size - end_size) {
        const uint8_t *int_ptr;
        size_t int_size;
        uint8_t *read_ptr;
        size_t read_size;
        uint8_t buffer[in_size];
        memset(buffer, 0, in_size);

        base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

        const size_t key_padding = asn1_get_padding_pub_key(buffer);
        read_ptr = buffer + key_padding;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->mod, int_ptr, int_size);
        read_ptr += read_size;

        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(&key->pub_exp, int_ptr, int_size);
        read_ptr += read_size;
    }
}

void import_pvt_key(rsa_pvt_key_t *key, const char *data) {
    const char begin[] = "-----BEGIN PRIVATE KEY-----";
    const char end[] = "-----END PRIVATE KEY-----";
    size_t in_size = 9192;
    char pem[in_size];
    strcpy(pem, data);

    size_t beg_size = strlen(begin);
    size_t end_size = strlen(end);
    size_t pem_size = strlen(pem);
    char *beg_pos = strstr(pem, begin);
    size_t beg_idx = beg_pos - pem;
    char *end_pos = strstr(pem, end);
    size_t end_idx = end_pos - pem;

    if (!(beg_idx == 0 && end_idx == pem_size - end_size)) {
        return;
    }
    
    const uint8_t *int_ptr;
    size_t int_size;
    uint8_t *read_ptr;
    size_t read_size;
    uint8_t buffer[in_size];
    memset(buffer, 0, in_size);

    base64_read((uint8_t *)data + beg_size, pem_size - beg_size - end_size, buffer, in_size);

    const size_t key_padding = asn1_get_padding_pvt_key(buffer);
    read_ptr = buffer + key_padding;
    read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
    if (read_size == -1) {
        return;
    }

    bignum_t version;
    bn_from_bytes(&version, int_ptr, int_size);
    if (!bn_is_zero(&version, BN_ARRAY_SIZE)) {
        return;
    }
    read_ptr += read_size;

    bignum_t *targets[] = {&key->mod, &key->pub_exp, &key->pvt_exp, &key->p, &key->q, &key->exp1, &key->exp2, &key->coeff};
    size_t targets_size = sizeof(targets) / sizeof(bignum_t *);
    for (size_t i = 0; i < targets_size; i++) {
        read_size = asn1_get_int(read_ptr, &int_ptr, &int_size);
        if (read_size == -1) {
            return;
        }
        bn_from_bytes(targets[i], int_ptr, int_size);
        read_ptr += read_size;
    }
}

static void encrypt(const rsa_pub_key_t *key, const montg_t *montg_domain_n, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out = {0};

    montg_transform(montg_domain_n, bignum_in, &bignum_montg_in);

    montg_pow(montg_domain_n, &bignum_montg_in, &key->pub_exp, &bignum_montg_out);
    montg_revert(montg_domain_n, &bignum_montg_out, bignum_out);
}

void encrypt_buf(const rsa_pub_key_t *key, const montg_t *montg_domain_n, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
    bignum_t in_bn = {0}, out_bn;

    memmove(in_bn, buffer_in, buffer_in_len * sizeof(char));
    encrypt(key, montg_domain_n, &in_bn, &out_bn);
    bn_to_string(&out_bn, buffer_out, buffer_out_len);
}

static void decrypt(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const montg_t *montg_domain_p, const montg_t *montg_domain_q, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_p_in, bignum_montg_q_in, bignum_montg_p_out = {0}, bignum_montg_q_out = {0}, bignum_p_out, bignum_q_out, h, hq;

    montg_transform(montg_domain_p, bignum_in, &bignum_montg_p_in);
    montg_pow(montg_domain_p, &bignum_montg_p_in, &key->exp1, &bignum_montg_p_out);
    montg_revert(montg_domain_p, &bignum_montg_p_out, &bignum_p_out);

    montg_transform(montg_domain_q, bignum_in, &bignum_montg_q_in);
    montg_pow(montg_domain_q, &bignum_montg_q_in, &key->exp2, &bignum_montg_q_out);
    montg_revert(montg_domain_q, &bignum_montg_q_out, &bignum_q_out);

    bn_sub(&bignum_p_out, &bignum_q_out, &bignum_p_out, BN_ARRAY_SIZE);
    montg_mul(montg_domain_p, &key->coeff, &bignum_p_out, &h);
    montg_mul(montg_domain_n, &h, &key->q, &hq);
    bn_add(&bignum_q_out, &hq, bignum_out, BN_ARRAY_SIZE);

    while (bn_cmp(bignum_out, &key->mod, BN_ARRAY_SIZE) != BN_CMP_SMALLER) {
        bn_sub(bignum_out, &key->mod, bignum_out, BN_ARRAY_SIZE);
    }
}

void decrypt_buf(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const montg_t *montg_domain_p, const montg_t *montg_domain_q, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
    bignum_t in_bn = {0}, out_bn;

    bn_from_string(&in_bn, buffer_in, buffer_in_len);
    decrypt(key, montg_domain_n, montg_domain_p, montg_domain_q, &in_bn, &out_bn);
    memmove(buffer_out, out_bn, buffer_out_len * sizeof(uint8_t));
}

static void sign(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const bignum_t *bignum_in, bignum_t *bignum_out) {
    bignum_t bignum_montg_in, bignum_montg_out = {0};

    montg_transform(montg_domain_n, bignum_in, &bignum_montg_in);

    montg_pow(montg_domain_n, &bignum_montg_in, &key->pvt_exp, &bignum_montg_out);
    montg_revert(montg_domain_n, &bignum_montg_out, bignum_out);
}

void sign_buf(const rsa_pvt_key_t *key, const montg_t *montg_domain_n, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
    bignum_t in_bn = {0}, out_bn;

    memmove(in_bn, buffer_in, buffer_in_len * sizeof(char));
    sign(key, montg_domain_n, &in_bn, &out_bn);
    bn_to_string(&out_bn, buffer_out, buffer_out_len);
}

void verify_buf(const rsa_pub_key_t *key, const montg_t *montg_domain_n, const char *buffer_in, size_t buffer_in_len, char *buffer_out, size_t buffer_out_len) {
#define verify encrypt
    
    bignum_t in_bn = {0}, out_bn;

    bn_from_string(&in_bn, buffer_in, buffer_in_len);
    verify(key, montg_domain_n, &in_bn, &out_bn);
    memmove(buffer_out, out_bn, buffer_out_len * sizeof(uint8_t));
}