#ifndef STACK_H
#define STACK_H

#include "frame.h"
#include <stddef.h>

#define STACK_SIZE 100

typedef frame_t element_t;

typedef struct {
    element_t data[STACK_SIZE];
    size_t size;
} stack_t;

void stack_init(stack_t *stack);

int stack_get_size(stack_t *stack);
int stack_is_empty(stack_t *stack);
int stack_is_full(stack_t *stack);
int stack_push(stack_t *stack, element_t *element);
int stack_pop(stack_t *stack, element_t *element);
int stack_peek(stack_t *stack, element_t **element);

int stack_pop_without_get(stack_t *stack);

#endif //STACK_H