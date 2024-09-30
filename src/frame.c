#include "frame.h"
#include "bignum.h"

void frame_init(frame_t *frame, const bignum_t *left, const bignum_t *right, size_t in_bn_size) {
    frame->in_bn_size = in_bn_size;
    frame->left = (bignum_t *)left;
    frame->right = (bignum_t *)right;
    frame->is_using_z = 0;
    frame->stage = STAGE1;
}

void frame_assign(frame_t *frame_dst, const frame_t *frame_src) {
    frame_dst->left = frame_src->left;
    frame_dst->right = frame_src->right;
    frame_dst->in_bn_size = frame_src->in_bn_size;
    frame_dst->bn_size_shift = frame_src->bn_size_shift;

    if (frame_dst->is_using_z) {
        bn_assign(frame_dst->z, 0, frame_src->z, 0, z_size * (frame_src->in_bn_size << 1));
        frame_dst->z0_ptr = frame_src->z0_ptr;
        frame_dst->z1_ptr = frame_src->z1_ptr;
    }
    
    frame_dst->stage = frame_src->stage;
}