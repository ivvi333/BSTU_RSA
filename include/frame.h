#ifndef FRAME_H
#define FRAME_H

#include "bignum.h"
#include <stdint.h>
#include <stddef.h>

typedef enum {
    STAGE1,
    STAGE2,
    STAGE3,
    STAGE4,
} stage_t;

#define z_size 2

typedef struct {
    bignum_t *left;
    bignum_t *right;
    size_t in_bn_size;
    size_t bn_size_shift;

    uint8_t is_using_z;
    bignum_t z[z_size];
    bignum_t *z0_ptr;
    bignum_t *z1_ptr;

    size_t stage;
} frame_t;

void frame_init(frame_t *frame, const bignum_t *left, const bignum_t *right, size_t in_bn_size);
void frame_assign(frame_t *frame_dst, const frame_t *frame_src);

#endif //FRAME_H