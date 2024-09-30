#include "bignum.h"
#include "frame.h"
#include "stack.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static void lshift_one_bit(bignum_t *bignum);
static void rshift_one_bit(bignum_t *bignum);

static void bn_inner_karatsuba(bignum_t *left, const bignum_t *right, const size_t in_bn_size);

// memset может выйти за границы bignum, никак не проверяется
void bn_memset(bignum_t *bignum, const size_t offset, const int value, const size_t count) {
    memset((*bignum) + offset, value, count * BN_WORD_SIZE);
}

void bn_init(bignum_t *bignum, const size_t size) {
    bn_memset(bignum, 0, 0, size);
}

// memcpy может выйти за границы bignum_dst и/или bignum_src, никак не проверяется
void bn_assign(bignum_t *bignum_dst, const size_t bignum_dst_offset, const bignum_t *bignum_src,
               const size_t bignum_src_offset, const size_t count)
{
    memcpy((*bignum_dst) + bignum_dst_offset, (*bignum_src) + bignum_src_offset, count * BN_WORD_SIZE);
}

void bn_from_bytes(bignum_t *bignum, const uint8_t *bytes, const size_t nbytes) {
    bn_init(bignum, BN_ARRAY_SIZE);

    // Хорошо бы было вернуть какой-нибудь код ошибки
    if (nbytes > BN_BYTE_SIZE) {
        return;
    }

    uint8_t padding = ((nbytes - 1) / BN_WORD_SIZE + 1) * BN_WORD_SIZE - nbytes;

    for (size_t i = 0; i < nbytes; ++i) {
        (*bignum)[(nbytes - 1 - i) / BN_WORD_SIZE] |= (BN_DTYPE)bytes[i] << ((BN_WORD_SIZE - 1 - i - padding) % BN_WORD_SIZE) * 8;
    }
}

void bn_from_string(bignum_t *bignum, const char *str, const size_t nbytes) {
    bn_init(bignum, BN_ARRAY_SIZE);

    size_t i = nbytes;
    size_t j = 0;
    while (i > 0) {
        BN_DTYPE tmp = 0;
        i = i > sizeof(BN_DTYPE_TMP) ? i - sizeof(BN_DTYPE_TMP) : 0;
        sscanf(&str[i], BN_SSCANF_FORMAT_STR, &tmp);
        (*bignum)[j] = tmp;
        ++j;
    }
}

// from_int не самое удачное название
void bn_from_int(bignum_t *bignum, const BN_DTYPE_TMP value, size_t size) {
    bn_init(bignum, size);

    size = MIN(size, 2);
    for (size_t i = 0; i < size; i++) {
        (*bignum)[i] = value >> (i * BN_WORD_SIZE * 8);
    }
}

void bn_to_string(const bignum_t *bignum, char *str, size_t nbytes) {
    int j = BN_ARRAY_SIZE - 1;
    size_t i = 0;
    while (j >= 0 && nbytes > i + 1) {
        if ((*bignum)[j]) {
            sprintf(&str[i], BN_SPRINTF_FORMAT_STR, (*bignum)[j]);
            i += sizeof(BN_DTYPE_TMP);
        }
        --j;
    }

    str[i] = '\0';
}

void bn_add(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    uint8_t carry = 0;
    for (size_t i = 0; i < size; ++i) {
        BN_DTYPE_TMP tmp = (BN_DTYPE_TMP)(*bignum1)[i] + (*bignum2)[i] + carry;
        carry = tmp > BN_MAX_VAL;
        (*bignum_res)[i] = tmp & BN_MAX_VAL;
    }
}

void bn_add_carry(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    uint8_t carry = 0;
    for (size_t i = 0; i + 1 < size; ++i) {
        BN_DTYPE_TMP tmp = (BN_DTYPE_TMP)(*bignum1)[i] + (*bignum2)[i] + carry;
        carry = tmp > BN_MAX_VAL;
        (*bignum_res)[i] = tmp & BN_MAX_VAL;
    }
    (*bignum_res)[size - 1] = carry;
}

void bn_sub(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    if (bn_cmp(bignum1, bignum2, size) == BN_CMP_SMALLER) {
        return;
    }

    uint8_t borrow = 0;
    for (size_t i = 0; i < size; ++i) {
        BN_DTYPE_TMP tmp1 = (BN_DTYPE_TMP)(*bignum1)[i] + BN_MAX_VAL + 1;
        BN_DTYPE_TMP tmp2 = (BN_DTYPE_TMP)(*bignum2)[i] + borrow;
        BN_DTYPE_TMP res = tmp1 - tmp2;
        (*bignum_res)[i] = (BN_DTYPE)(res & BN_MAX_VAL);
        borrow = res <= BN_MAX_VAL;
    }
}

void bn_karatsuba(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    bn_assign(bignum_res, 0, bignum1, 0, size >> 1);
    bn_inner_karatsuba(bignum_res, bignum2, size >> 1);
}

static void bn_inner_karatsuba(bignum_t *left, const bignum_t *right, const size_t in_bn_size) {
    stack_t stack;
    stack_init(&stack);

    frame_t frame_tmp;
    frame_init(&frame_tmp, left, right, in_bn_size);
    stack_push(&stack, &frame_tmp);

    while (!stack_is_empty(&stack)) {
        frame_t *frame;
        stack_peek(&stack, &frame);

        switch (frame->stage) {
            case STAGE1: {
                if (frame->in_bn_size == 1) {
                    bn_from_int(frame->left, (BN_DTYPE_TMP)(*frame->left)[0] * (BN_DTYPE_TMP)(*frame->right)[0], 2);
                    stack_pop_without_get(&stack);

                    break;
                }
                
                if (bn_is_zero(frame->left, frame->in_bn_size)) {
                    bn_memset(frame->left, frame->in_bn_size, 0, frame->in_bn_size);
                    stack_pop_without_get(&stack);
                    
                    break;
                }

                if (bn_is_zero(frame->right, frame->in_bn_size)) {
                    bn_memset(frame->left, 0, 0, frame->in_bn_size << 1);
                    stack_pop_without_get(&stack);
                    
                    break;
                }

                memset(frame->z, 0, z_size * (frame->in_bn_size << 1) * BN_WORD_SIZE);
                frame->z0_ptr = (bignum_t *)((BN_DTYPE *) frame->z + 0);
                frame->z1_ptr = (bignum_t *)((BN_DTYPE *) frame->z + (frame->in_bn_size << 1));
                frame->is_using_z = 1;

                frame->bn_size_shift = frame->in_bn_size >> 1;

                // (L1 + L2)
                bn_add_carry((bignum_t*)*frame->left, (bignum_t*)(*frame->left + frame->bn_size_shift), frame->z0_ptr, frame->bn_size_shift + 1);

                // (R1 + R2)
                bn_add_carry((bignum_t*)*frame->right, (bignum_t*)(*frame->right + frame->bn_size_shift), frame->z1_ptr, frame->bn_size_shift + 1);

                // (L1 + L2) * (R1 + R2)
                const size_t size = ((*frame->z0_ptr)[frame->bn_size_shift] | (*frame->z1_ptr)[frame->bn_size_shift]) ? frame->in_bn_size : frame->bn_size_shift;

                frame_t frame_tmp;
                frame_init(&frame_tmp, frame->z0_ptr, frame->z1_ptr, size);
                stack_push(&stack, &frame_tmp);
                
                frame->stage = STAGE2;
            }
            break;

            case STAGE2: {
                // Z1 = L2 * R2
                bn_assign(frame->z1_ptr, 0, frame->left, frame->bn_size_shift, frame->bn_size_shift);

                frame_t frame_tmp;
                frame_init(&frame_tmp, frame->z1_ptr, (bignum_t*)(*(bignum_t *)frame->right + frame->bn_size_shift), frame->bn_size_shift);
                stack_push(&stack, &frame_tmp);
                
                frame->stage = STAGE3;
            }
            break;

            case STAGE3: {
                bn_sub(frame->z0_ptr, frame->z1_ptr, frame->z0_ptr, frame->in_bn_size << 1);

                // left = L1 * R1
                bn_memset(frame->left, frame->bn_size_shift, 0, frame->in_bn_size + frame->bn_size_shift);

                frame_t frame_tmp;
                frame_init(&frame_tmp, frame->left, frame->right, frame->bn_size_shift);
                stack_push(&stack, &frame_tmp);
                
                frame->stage = STAGE4;
            }
            break;

            case STAGE4: {
                bn_sub(frame->z0_ptr, frame->left, frame->z0_ptr, frame->in_bn_size << 1);

                // Result Z2 + Z1 + Z0 (shift adjusted)
                bn_assign(frame->left, frame->in_bn_size, frame->z1_ptr, 0, frame->in_bn_size);
                bn_memset(frame->z1_ptr, 0, 0, frame->bn_size_shift);
                bn_assign(frame->z1_ptr, frame->bn_size_shift, frame->z0_ptr, 0, frame->in_bn_size + 1);

                bignum_t *bignum_answer = stack_get_size(&stack) != 1 ? frame->left : left;
                bn_add(frame->left, frame->z1_ptr, bignum_answer, frame->in_bn_size << 1);
                stack_pop_without_get(&stack);
            }
            break;
        }
    }
}

void bn_div(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    if (bn_is_zero(bignum2, size)) {
        return;
    }

    bignum_t current;
    bignum_t denom;
    bignum_t tmp;

    bn_from_int(&current, 1, size);
    bn_assign(&denom, 0, bignum2, 0, size);
    bn_assign(&tmp, 0, bignum1, 0, size);

    uint8_t overflow = 0;
    while (bn_cmp(&denom, bignum1, size) != BN_CMP_LARGER) {
        const BN_DTYPE_TMP half_max = 1 + (BN_DTYPE_TMP)(BN_MAX_VAL / 2);
        if (denom[size - 1] >= half_max) {
            overflow = 1;
            break;
        }
        lshift_one_bit(&current);
        lshift_one_bit(&denom);
    }
    if (!overflow) {
        rshift_one_bit(&denom);
        rshift_one_bit(&current);
    }
    bn_init(bignum_res, size);

    while (!bn_is_zero(&current, size)) {
        if (bn_cmp(&tmp, &denom, size) != BN_CMP_SMALLER) {
            bn_sub(&tmp, &denom, &tmp, size);
            bn_or(bignum_res, &current, bignum_res, size);
        }
        rshift_one_bit(&current);
        rshift_one_bit(&denom);
    }
}

void bn_mod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    if (bn_is_zero(bignum2, size)) {
        return;
    }

    bignum_t tmp;
    bn_divmod(bignum1, bignum2, &tmp, bignum_res, size);
}

void bn_divmod(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_div, bignum_t *bignum_mod, size_t size) {
    if (bn_is_zero(bignum2, size)) {
        return;
    }

    bignum_t tmp;
    bn_div(bignum1, bignum2, bignum_div, size);
    bn_karatsuba(bignum_div, bignum2, &tmp, size);
    bn_sub(bignum1, &tmp, bignum_mod, size);
}

void bn_or(const bignum_t *bignum1, const bignum_t *bignum2, bignum_t *bignum_res, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        (*bignum_res)[i] = (*bignum1)[i] | (*bignum2)[i];
    }
}

bignum_compare_state bn_cmp(const bignum_t *bignum1, const bignum_t *bignum2, size_t size) {
    do {
        --size;
        if ((*bignum1)[size] > (*bignum2)[size]) {
            return BN_CMP_LARGER;
        } else if ((*bignum1)[size] < (*bignum2)[size]) {
            return BN_CMP_SMALLER;
        }
    } while (size != 0);

    return BN_CMP_EQUAL;
}

uint8_t bn_is_zero(const bignum_t *bignum, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if ((*bignum)[i] != 0) {
            return 0;
        }
    }

    return 1;
}

static void lshift_one_bit(bignum_t *bignum) {
    for (size_t i = BN_ARRAY_SIZE - 1; i > 0; --i) {
        (*bignum)[i] = ((*bignum)[i] << 1) | ((*bignum)[i - 1] >> (BN_WORD_SIZE * 8 - 1));
    }
    (*bignum)[0] <<= 1;
}

static void rshift_one_bit(bignum_t *bignum) {
    for (size_t i = 0; i < BN_ARRAY_SIZE - 1; ++i) {
        (*bignum)[i] = ((*bignum)[i] >> 1) | ((*bignum)[i + 1] << (BN_WORD_SIZE * 8 - 1));
    }
    (*bignum)[BN_ARRAY_SIZE - 1] >>= 1;
}

size_t bn_bitcount(const bignum_t *bignum) {
    size_t bits = (BN_BYTE_SIZE << 3) - (BN_WORD_SIZE << 3);
    int i;
    for (i = BN_ARRAY_SIZE - 1; i >= 0 && (*bignum)[i] == 0; --i) {
        bits -= BN_WORD_SIZE << 3;
    }

    for (BN_DTYPE value = (*bignum)[i]; value != 0; value >>= 1) {
        bits++;
    }

    return bits;
}
