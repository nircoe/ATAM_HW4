#ifndef STACK_H_
#define STACK_H_
#include <stdlib.h>

typedef struct stack_t{
    int size;
    unsigned long data;
    struct stack_t* before;
    struct stack_t* max_node;
}*Stack;

Stack init()
{
    Stack stack = (Stack)malloc(sizeof(struct stack_t));
    stack->size = 0;
    stack->data = 0;
    stack->before = NULL;
    stack->max_node = stack;
    return stack;
}

void push(Stack stack, unsigned long new_data)
{
    Stack new_stack = (Stack)malloc(sizeof(struct stack_t));
    new_stack->data = new_data;

    stack->size += 1;
    new_stack->size = stack->size;

    new_stack->before = stack->max_node;
    new_stack->max_node = NULL;
    stack->max_node = new_stack;
}

unsigned long pop(Stack stack)
{
    if(stack->size == 0)
        return 0;
    Stack highest = stack->max_node;
    stack->max_node = highest->before;
    stack->size -= 1;

    unsigned long result = highest->data;
    free(highest);
    return result;
}

#endif