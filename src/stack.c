#include "stack.h"
#include "frame.h"

void stack_init(stack_t *stack) {
    stack->size = 0;
}

int stack_get_size(stack_t *stack) {
    return stack->size;
}

int stack_is_empty(stack_t *stack) {
    return stack_get_size(stack) == 0;
}

int stack_is_full(stack_t *stack) {
    return stack_get_size(stack) + 1 == STACK_SIZE;
}

int stack_push(stack_t *stack, element_t *element) {
    if (stack_is_full(stack)) {
        return -1;
    }

    // stack->data[stack->size++] = *element;
    frame_assign(stack->data + (stack->size++), element);

    return 0;
}

int stack_pop(stack_t *stack, element_t *element) {
    if (stack_is_empty(stack)) {
        return -1;
    }

    // *element = stack->data[--stack->size];
    frame_assign(element, stack->data + (--stack->size));

    return 0;
}

int stack_peek(stack_t *stack, element_t **element) {
    if (stack_is_empty(stack)) {
        return -1;
    }

    *element = stack->data + stack->size - 1;

    return 0;
}

int stack_pop_without_get(stack_t *stack) {
    if (stack_is_empty(stack)) {
        return -1;
    }

    --stack->size;

    return 0;
}