#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #define DEBUG

struct token
{
    char* value;
};

struct tokenized_instruction
{
    struct token** tokens;
    int token_count;
    int capacity;
};

struct tokenized_program
{
    struct tokenized_instruction** instructions;
    int instruction_count;
    int capacity;
};

enum registers
{
    REG_R0, // Provola
    REG_R1, // pRovola
    REG_R2, // prOvola
    REG_R3, // proVola
    REG_R4, // provOla
    REG_R5, // provoLa
    REG_R6, // provolA
};

#define EXPRESSION_TERMINATOR "provola"
#define EXPRESSION_PLUS "pROVOLA"
#define EXPRESSION_MINUS "prOVOLA"
#define EXPRESSION_MUL "proVOLA"
#define EXPRESSION_DIV "provOLA"
#define EXPRESSION_XOR "provoLA"
#define EXPRESSION_CHAT_AT "prOVOla"

#define EXPRESSION_CMP "pRoVOLA"
#define EXPRESSION_JMP "prOvOLA"
#define EXPRESSION_JP "pr0VoLA"

#define EXPRESSION_LABEL "PRovOLA"
#define EXPRESSION_CALL "PrOVOLA"
#define EXPRESSION_RET "ProVOLA"

#define EXPRESSION_SYSCALL "provOLa"

enum node_type
{
    NODE_TYPE_ASSIGNMENT,
    NODE_TYPE_PUSH_POP,
    NODE_TYPE_REG,
    NODE_TYPE_IMMEDIATE,
    NODE_TYPE_STRING,
    NODE_TYPE_TERMINATOR,
    NODE_TYPE_ACTION,
    NODE_TYPE_BINARY,
};

const int ARITY[] = {
    [NODE_TYPE_ASSIGNMENT] = 0, [NODE_TYPE_PUSH_POP] = 0,
    [NODE_TYPE_REG] = 0,        [NODE_TYPE_IMMEDIATE] = 0,
    [NODE_TYPE_STRING] = 0,     [NODE_TYPE_TERMINATOR] = 0,
    [NODE_TYPE_ACTION] = 0,     [NODE_TYPE_BINARY] = 2,
};

#define MAX(a, b) ((a) > (b) ? (a) : (b))

enum action
{
    ACTION_LABEL,
    ACTION_CALL,
    ACTION_RET,
    ACTION_SYSCALL,
    ACTION_JMP,
    ACTION_JP,
};

enum binary_op
{
    BINARY_OP_PLUS,
    BINARY_OP_MINUS,
    BINARY_OP_MUL,
    BINARY_OP_DIV,
    BINARY_OP_XOR,
    BINARY_OP_CMP,
    BINARY_OP_CHAR_AT,
};

struct expression_node
{
    enum node_type type;
    union
    {
        struct
        {
            struct expression_node* left;
            struct expression_node* right;
        } assignment;
        struct main
        {
            struct expression_node* left;
            struct expression_node* right;
            enum binary_op op;
        } binary;
        struct
        {
            enum registers reg;
        } reg;
        struct
        {
            uint64_t value;
        } immediate;
        struct
        {
            char* value;
        } string;
        struct
        {
            struct expression_node* left;
        } push_pop;
        struct
        {
            enum action action;
        } action;
    } data;
};

struct expression
{
    struct expression_node* root;
};

struct frame
{
    uint64_t registers[8];
    bool reg_alias_types[8]; // 1 = string, 0 = anything else
    int return_address;
};

struct emulator_state
{
    struct frame** frames;
    int frame_count;
    uint64_t stack[1024];
    bool alias_stack[1024];
    uint64_t stack_pointer;
};

struct label_marker
{
    char* label;
    int instruction_index;
};

struct program
{
    struct expression** expressions;
    int expression_count;
    struct emulator_state state;
    struct label_marker** labels;
    int label_count;
};

struct token* create_token(char* value)
{
    struct token* t = malloc(sizeof(struct token));
    t->value = value;
    return t;
}

struct tokenized_instruction* create_tokenized_instruction()
{
    struct tokenized_instruction* i =
      malloc(sizeof(struct tokenized_instruction));
    i->tokens = malloc(1 * sizeof(struct token*));
    i->token_count = 0;
    i->capacity = 1;
    return i;
}

void add_token_to_instruction(struct tokenized_instruction* i, struct token* t)
{
    if (i->token_count == i->capacity) {
        i->capacity *= 2;
        i->tokens = realloc(i->tokens, i->capacity * sizeof(struct token*));
    }
    i->tokens[i->token_count++] = t;
}

struct tokenized_program* create_tokenized_program()
{
    struct tokenized_program* p = malloc(sizeof(struct tokenized_program));
    p->instructions = malloc(1 * sizeof(struct tokenized_instruction*));
    p->instruction_count = 0;
    p->capacity = 1;
    return p;
}

void add_instruction_to_tokenized_program(struct tokenized_program* p,
                                          struct tokenized_instruction* i)
{
    if (p->instruction_count == p->capacity) {
        p->capacity *= 2;
        p->instructions = realloc(
          p->instructions, p->capacity * sizeof(struct tokenized_instruction*));
    }
    p->instructions[p->instruction_count++] = i;
}

void free_token(struct token* t)
{
    free(t->value);
    free(t);
}

void free_token_instruction(struct tokenized_instruction* i)
{
    for (int j = 0; j < i->token_count; j++) {
        free_token(i->tokens[j]);
    }
    free(i->tokens);
    free(i);
}

void free_tokenized_program(struct tokenized_program* p)
{
    for (int i = 0; i < p->instruction_count; i++) {
        free_token_instruction(p->instructions[i]);
    }
    free(p->instructions);
    free(p);
}

void menu(char* argv[])
{
    printf("PROVOLA Interpreter v1.0\n");
    printf("Usage: %s <filename>\n", argv[0]);
}

FILE* open_file(char* filename)
{
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
#ifdef DEBUG
        printf("Error: file not found\n");
#endif
        exit(1);
    }
    return file;
}

void close_file(FILE* file)
{
    fclose(file);
}

struct tokenized_program* tokenize(FILE* file)
{
    struct tokenized_program* p = create_tokenized_program();
    char* line = NULL;
    bool should_free_token = false;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        struct tokenized_instruction* i = create_tokenized_instruction();
        char* token = strtok(line, " \n");
        while (token != NULL) {
            if (token[0] == '"') {
                size_t len = strlen(token);
                if (token[len - 1] != '"') {
                    char *concat_string = malloc(len + 1);
                    strcpy(concat_string, token);
                    while (concat_string[len - 1] != '"') {
                        token = strtok(NULL, " \n");
                        len += strlen(token) + 1;
                        concat_string = realloc(concat_string, len + 1);
                        strcat(concat_string, " ");
                        strcat(concat_string, token);
                    }
                    token = concat_string;
                    should_free_token = true;
                }
            }

            add_token_to_instruction(i, create_token(strdup(token)));
            if (strcmp(token, EXPRESSION_TERMINATOR) == 0) {
                add_instruction_to_tokenized_program(p, i);
                i = create_tokenized_instruction();
            }

            if (should_free_token) {
                free(token);
                should_free_token = false;
            }

            token = strtok(NULL, " \n");
        }
        if (i->token_count > 0) {
            add_instruction_to_tokenized_program(p, i);
        } else {
            free_token_instruction(i);
        }
    }
    free(line);
    return p;
}

#ifdef DEBUG
void pprint_tokenized_program(struct tokenized_program* p)
{
    for (int i = 0; i < p->instruction_count; i++) {
        for (int j = 0; j < p->instructions[i]->token_count; j++) {
            printf("%s ", p->instructions[i]->tokens[j]->value);
        }
        printf("\n");
    }
}
#endif

struct program* create_program()
{
    struct program* p = malloc(sizeof(struct program));
    return p;
}

struct expression_node* create_expression_node(enum node_type type)
{
    struct expression_node* n = malloc(sizeof(struct expression_node));
    n->type = type;
    return n;
}

enum node_type determine_expression_type(struct token* token)
{
    // first and last characters is " -> string
    if (token->value[0] == '"' &&
        token->value[strlen(token->value) - 1] == '"') {
        return NODE_TYPE_STRING;
    }

    // if it's a number -> immediate
    bool all_digits = true;
    for (int i = 0; i < strlen(token->value); i++) {
        if (token->value[i] < '0' || token->value[i] > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) {
        errno = 0;
        strtol(token->value, NULL, 10);
        if (errno == 0) {
            return NODE_TYPE_IMMEDIATE;
        }
    }

    int lowercase_count = 0, uppercase_count = 0, number_count = 0;
    for (int i = 0; i < strlen(token->value); i++) {
        if (token->value[i] >= 'a' && token->value[i] <= 'z') {
            lowercase_count++;
        } else if (token->value[i] >= 'A' && token->value[i] <= 'Z') {
            uppercase_count++;
        } else if (token->value[i] >= '0' && token->value[i] <= '9') {
            number_count++;
        }
    }

    // a single uppercase letter and no numbers -> register
    if (uppercase_count == 1 && number_count == 0) {
        // validate that the string, converted to lowercase, is equal to
        // "provola"
        char* lowercase = strdup(token->value);
        for (int i = 0; i < strlen(lowercase); i++) {
            if (lowercase[i] >= 'A' && lowercase[i] <= 'Z') {
                lowercase[i] += 32;
            }
        }
        if (strcmp(lowercase, EXPRESSION_TERMINATOR) != 0) {
#ifdef DEBUG
            printf("Error: invalid register name\n");
#endif
            exit(1);
        }
        free(lowercase);
        return NODE_TYPE_REG;
    }

    // if it's a valid action -> action
    if (strcmp(token->value, EXPRESSION_LABEL) == 0) {
        return NODE_TYPE_ACTION;
    } else if (strcmp(token->value, EXPRESSION_CALL) == 0) {
        return NODE_TYPE_ACTION;
    } else if (strcmp(token->value, EXPRESSION_RET) == 0) {
        return NODE_TYPE_ACTION;
    } else if (strcmp(token->value, EXPRESSION_SYSCALL) == 0) {
        return NODE_TYPE_ACTION;
    } else if (strcmp(token->value, EXPRESSION_JMP) == 0) {
        return NODE_TYPE_ACTION;
    } else if (strcmp(token->value, EXPRESSION_JP) == 0) {
        return NODE_TYPE_ACTION;
    }

    // if it's a valid binary operator -> binary
    if (strcmp(token->value, EXPRESSION_PLUS) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_MINUS) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_MUL) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_DIV) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_XOR) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_CMP) == 0) {
        return NODE_TYPE_BINARY;
    } else if (strcmp(token->value, EXPRESSION_CHAT_AT) == 0) {
        return NODE_TYPE_BINARY;
    }

#ifdef DEBUG
    printf("Error: invalid expression type %s\n", token->value);
#endif
    exit(1);
}

enum registers determine_register(struct token* token)
{
    // return the index of the first uppercase letter
    for (int i = 0; i < strlen(token->value); i++) {
        if (token->value[i] >= 'A' && token->value[i] <= 'Z') {
            return i;
        }
    }

#ifdef DEBUG
    printf("Error: invalid register name\n");
#endif
    exit(1);
}

enum binary_op determine_op(struct token* token)
{
    if (strcmp(token->value, EXPRESSION_PLUS) == 0) {
        return BINARY_OP_PLUS;
    } else if (strcmp(token->value, EXPRESSION_MINUS) == 0) {
        return BINARY_OP_MINUS;
    } else if (strcmp(token->value, EXPRESSION_MUL) == 0) {
        return BINARY_OP_MUL;
    } else if (strcmp(token->value, EXPRESSION_DIV) == 0) {
        return BINARY_OP_DIV;
    } else if (strcmp(token->value, EXPRESSION_XOR) == 0) {
        return BINARY_OP_XOR;
    } else if (strcmp(token->value, EXPRESSION_CMP) == 0) {
        return BINARY_OP_CMP;
    } else if (strcmp(token->value, EXPRESSION_CHAT_AT) == 0) {
        return BINARY_OP_CHAR_AT;
    }

#ifdef DEBUG
    printf("Error: invalid binary operator\n");
#endif
    exit(1);
}

struct expression_node* parse_polish_notation(
  struct tokenized_instruction* source,
  int* used,
  int start)
{
    struct expression_node* n = malloc(sizeof(struct expression_node));
    n->type = determine_expression_type(source->tokens[start]);

    // any type that is ASSIGNMENT, PUSH_POP, ACTION or TERMINATOR is invalid
    // here
    if (n->type == NODE_TYPE_ASSIGNMENT || n->type == NODE_TYPE_PUSH_POP ||
        n->type == NODE_TYPE_ACTION || n->type == NODE_TYPE_TERMINATOR) {
#ifdef DEBUG
        printf("Error: invalid expression type\n");
#endif
        exit(1);
    }

    if (n->type == NODE_TYPE_REG) {
        n->data.reg.reg = determine_register(source->tokens[start]);
        *used += 1;
        return n;
    }

    if (n->type == NODE_TYPE_IMMEDIATE) {
        n->data.immediate.value =
          strtol(source->tokens[start]->value, NULL, 10);
        *used += 1;
        return n;
    }

    if (n->type == NODE_TYPE_STRING) {
        // remove the quotes
        n->data.string.value = strdup(source->tokens[start]->value + 1);
        n->data.string.value[strlen(n->data.string.value) - 1] = '\0';
        *used += 1;
        return n;
    }

    if (n->type == NODE_TYPE_BINARY) {
        n->data.binary.op = determine_op(source->tokens[start]);
        int new_used = 0;
        n->data.binary.left =
          parse_polish_notation(source, &new_used, start + 1);
        n->data.binary.right =
          parse_polish_notation(source, used, start + 1 + new_used);
        *used += 1 + new_used;
        return n;
    }

#ifdef DEBUG
    printf("Error: invalid expression type\n");
#endif
    exit(1);
}

enum action determine_action(struct token* token)
{
    if (strcmp(token->value, EXPRESSION_LABEL) == 0) {
        return ACTION_LABEL;
    } else if (strcmp(token->value, EXPRESSION_CALL) == 0) {
        return ACTION_CALL;
    } else if (strcmp(token->value, EXPRESSION_RET) == 0) {
        return ACTION_RET;
    } else if (strcmp(token->value, EXPRESSION_SYSCALL) == 0) {
        return ACTION_SYSCALL;
    } else if (strcmp(token->value, EXPRESSION_JMP) == 0) {
        return ACTION_JMP;
    } else if (strcmp(token->value, EXPRESSION_JP) == 0) {
        return ACTION_JP;
    }

#ifdef DEBUG
    printf("Error: invalid action\n");
#endif
    exit(1);
}

void parse_tokenized_expression(struct expression* dest,
                                struct tokenized_instruction* source)
{
    int expression_length = source->token_count;
    if (expression_length == 0) {
#ifdef DEBUG
        printf("Error: empty expression\n");
#endif
        exit(1);
    }

    // the last token should always be the terminator
    if (strcmp(source->tokens[expression_length - 1]->value,
               EXPRESSION_TERMINATOR) != 0) {
#ifdef DEBUG
        printf("Error: expression does not end with terminator\n");
#endif
        exit(1);
    }

    // if we have only the terminator, the expression is just a nop
    if (expression_length == 1) {
        dest->root = create_expression_node(NODE_TYPE_TERMINATOR);
        return;
    }

    // if we have only one other token, it can either be a register and the
    // expression is push/pop, or it can be an action
    if (expression_length == 2 &&
        determine_expression_type(source->tokens[0]) == NODE_TYPE_REG) {
        dest->root = create_expression_node(NODE_TYPE_PUSH_POP);
        dest->root->data.push_pop.left =
          create_expression_node(determine_expression_type(source->tokens[0]));
        dest->root->data.push_pop.left->data.reg.reg =
          determine_register(source->tokens[0]);
        return;
    } else if (expression_length == 2 &&
               determine_expression_type(source->tokens[0]) ==
                 NODE_TYPE_ACTION) {
        dest->root = create_expression_node(NODE_TYPE_ACTION);
        dest->root->data.action.action = determine_action(source->tokens[0]);
        return;
    } else if (expression_length == 2) {
#ifdef DEBUG
        printf("Error: invalid expression\n");
#endif
        exit(1);
    }

    // if we have more than two tokens, the first token must be a register, and
    // the root is an assignment
    if (determine_expression_type(source->tokens[0]) != NODE_TYPE_REG) {
#ifdef DEBUG
        printf("Error: invalid expression\n");
#endif
        exit(1);
    }

    dest->root = create_expression_node(NODE_TYPE_ASSIGNMENT);
    dest->root->data.assignment.left = create_expression_node(NODE_TYPE_REG);
    dest->root->data.assignment.left->data.reg.reg =
      determine_register(source->tokens[0]);
    int used = 0;
    dest->root->data.assignment.right = parse_polish_notation(source, &used, 1);

    // the number of tokens used should be equal to the number of tokens in the
    // expression
    // used + 1 (for the register) + 1 (for the terminator)
    if (used + 1 + 1 != expression_length) {
#ifdef DEBUG
        printf("Error: invalid expression: used %d, length %d\n", used,
               expression_length);
#endif
        exit(1);
    }
}

void parse_tokenized_program(struct program* dest,
                             struct tokenized_program* source)
{
    dest->expressions =
      malloc(source->instruction_count * sizeof(struct expression*));
    dest->expression_count = source->instruction_count;

    for (int i = 0; i < source->instruction_count; i++) {
        struct expression* e = malloc(sizeof(struct expression));
        dest->expressions[i] = e;
        parse_tokenized_expression(e, source->instructions[i]);
    }
}

void free_expression_node(struct expression_node* n)
{
    if (n->type == NODE_TYPE_ASSIGNMENT) {
        free_expression_node(n->data.assignment.left);
        free_expression_node(n->data.assignment.right);
    } else if (n->type == NODE_TYPE_PUSH_POP) {
        free_expression_node(n->data.push_pop.left);
    } else if (n->type == NODE_TYPE_STRING) {
        free(n->data.string.value);
    } else if (n->type == NODE_TYPE_REG) {
        // nothing to free
    } else if (n->type == NODE_TYPE_IMMEDIATE) {
        // nothing to free
    } else if (n->type == NODE_TYPE_ACTION) {
        // nothing to free
    } else if (n->type == NODE_TYPE_BINARY) {
        free_expression_node(n->data.binary.left);
        free_expression_node(n->data.binary.right);
    }
    free(n);
}

void free_expression(struct expression* e)
{
    free_expression_node(e->root);
    free(e);
}

void free_program(struct program* p)
{
    for (int i = 0; i < p->expression_count; i++) {
        free_expression(p->expressions[i]);
    }
    free(p->expressions);
    free(p);
}

#ifdef DEBUG
void pprint_node(struct expression_node* n)
{
    if (n->type == NODE_TYPE_ASSIGNMENT) {
        printf("Assignment\n");
        pprint_node(n->data.assignment.left);
        pprint_node(n->data.assignment.right);
    } else if (n->type == NODE_TYPE_PUSH_POP) {
        printf("Push/Pop\n");
        pprint_node(n->data.push_pop.left);
    } else if (n->type == NODE_TYPE_REG) {
        printf("Register %d\n", n->data.reg.reg);
    } else if (n->type == NODE_TYPE_IMMEDIATE) {
        printf("Immediate %lu\n", n->data.immediate.value);
    } else if (n->type == NODE_TYPE_STRING) {
        printf("String %s\n", n->data.string.value);
    } else if (n->type == NODE_TYPE_TERMINATOR) {
        printf("Terminator\n");
    } else if (n->type == NODE_TYPE_ACTION) {
        printf("Action\n");
        if (n->data.action.action == ACTION_LABEL) {
            printf("Label\n");
        } else if (n->data.action.action == ACTION_CALL) {
            printf("Call\n");
        } else if (n->data.action.action == ACTION_RET) {
            printf("Return\n");
        } else if (n->data.action.action == ACTION_SYSCALL) {
            printf("Syscall\n");
        } else if (n->data.action.action == ACTION_JMP) {
            printf("Jump\n");
        } else if (n->data.action.action == ACTION_JP) {
            printf("Jump if positive\n");
        }
    } else if (n->type == NODE_TYPE_BINARY) {
        printf("Binary\n");
        if (n->data.binary.op == BINARY_OP_PLUS) {
            printf("Plus\n");
        } else if (n->data.binary.op == BINARY_OP_MINUS) {
            printf("Minus\n");
        } else if (n->data.binary.op == BINARY_OP_MUL) {
            printf("Multiply\n");
        } else if (n->data.binary.op == BINARY_OP_DIV) {
            printf("Divide\n");
        } else if (n->data.binary.op == BINARY_OP_XOR) {
            printf("Xor\n");
        } else if (n->data.binary.op == BINARY_OP_CMP) {
            printf("Compare\n");
        } else if (n->data.binary.op == BINARY_OP_CHAR_AT) {
            printf("Char at\n");
        }
        pprint_node(n->data.binary.left);
        pprint_node(n->data.binary.right);
    }
}

void pprint_expression(struct expression* e)
{
    pprint_node(e->root);
}

void pprint_program(struct program* p)
{
    for (int i = 0; i < p->expression_count; i++) {
        printf("Expression %d\n", i);
        pprint_expression(p->expressions[i]);
    }
}
#endif

void init_emulator(struct program* p)
{
    p->state.frames = malloc(1 * sizeof(struct frame*));
    p->state.frame_count = 1;
    p->state.frames[0] = malloc(sizeof(struct frame));
    for (int i = 0; i < 8; i++) {
        p->state.frames[0]->registers[i] = 0;
        p->state.frames[0]->reg_alias_types[i] = 0;
    }
    p->state.stack_pointer = 0;
    p->labels = NULL;
    p->label_count = 0;
}

void push_frame(struct program* p)
{
    p->state.frame_count++;
    p->state.frames =
      realloc(p->state.frames, p->state.frame_count * sizeof(struct frame*));
    p->state.frames[p->state.frame_count - 1] = malloc(sizeof(struct frame));
    for (int i = 0; i < 8; i++) {
        p->state.frames[p->state.frame_count - 1]->registers[i] = 0;
        p->state.frames[p->state.frame_count - 1]->reg_alias_types[i] = 0;
    }
}

void pop_frame(struct program* p)
{
    free(p->state.frames[p->state.frame_count - 1]);
    p->state.frame_count--;
    p->state.frames =
      realloc(p->state.frames, p->state.frame_count * sizeof(struct frame*));
}

#define GET_REG(p, r) p->state.frames[p->state.frame_count - 1]->registers[r]
#define IS_STRING(p, r)                                                        \
    (p->state.frames[p->state.frame_count - 1]->reg_alias_types[r] == 1)
#define SET_STRING(p, r, v)                                                    \
    p->state.frames[p->state.frame_count - 1]->reg_alias_types[r] = v

void interpret_syscall(struct expression_node* n, struct program* p)
{
    if (IS_STRING(p, REG_R0)) {
#ifdef DEBUG
        printf("Error: syscall number cannot be a string\n");
#endif
        exit(1);
    }

    uint64_t syscall_number = GET_REG(p, REG_R0);

    if (syscall_number == 0) {
#ifdef DEBUG
        printf("Syscall 0: exit\n");
#endif
        exit(0);
    } else if (syscall_number == 1) {
#ifdef DEBUG
        printf("Syscall 1: write\n");
#endif
        if (IS_STRING(p, REG_R1)) {
            printf("%s", (char*)GET_REG(p, REG_R1));
        } else if (GET_REG(p, REG_R2) == 1) { // write char
            printf("%c", (char)GET_REG(p, REG_R1));
        } else {
            printf("%lu\n", GET_REG(p, REG_R1));
        }
    } else if (syscall_number == 2) {
#ifdef DEBUG
        printf("Syscall 2: read\n");
#endif
        if (IS_STRING(p, REG_R1)) {
#ifdef DEBUG
            printf("Error: read size cannot be a string\n");
#endif
            exit(1);
        }
        char* buffer = malloc(GET_REG(p, REG_R1) + 1);
        ssize_t read_bytes = read(0, buffer, GET_REG(p, REG_R1));
        buffer[read_bytes] = '\0';
        SET_STRING(p, REG_R0, 1);
        GET_REG(p, REG_R0) = (uint64_t)buffer;
        GET_REG(p, REG_R1) = read_bytes;
        SET_STRING(p, REG_R1, 0);
    } else {
#ifdef DEBUG
        printf("Error: invalid syscall number\n");
#endif
        exit(1);
    }
}

void interpret_action(struct expression_node* n, struct program* p, int* i)
{
    if (n->data.action.action == ACTION_SYSCALL) {
        interpret_syscall(n, p);
    } else if (n->data.action.action == ACTION_LABEL) {
        // no-op
    } else if (n->data.action.action == ACTION_CALL) {
        if (!IS_STRING(p, REG_R0)) {
#ifdef DEBUG
            printf("Error: invalid label\n");
#endif
            exit(1);
        }

        struct label_marker* label = NULL;
        for (int j = 0; j < p->label_count; j++) {
            if (strcmp(p->labels[j]->label, (char*)GET_REG(p, REG_R0)) == 0) {
                label = p->labels[j];
                break;
            }
        }

#ifdef DEBUG
        printf("CALL to label: %s\n", (char*)GET_REG(p, REG_R0));
#endif

        if (label == NULL) {
#ifdef DEBUG
            printf("Error: label not found\n");
#endif
            exit(1);
        }

        push_frame(p);
        p->state.frames[p->state.frame_count - 1]->return_address = *i;
        *i = label->instruction_index;
    } else if (n->data.action.action == ACTION_RET) {
        if (p->state.frame_count == 1) {
#ifdef DEBUG
            printf("Error: cannot return from main\n");
#endif
            exit(1);
        }

#ifdef DEBUG
        printf("RET\n");
#endif

        *i = p->state.frames[p->state.frame_count - 1]->return_address;
        pop_frame(p);
    } else if (n->data.action.action == ACTION_JMP) {
        if (!IS_STRING(p, REG_R0)) {
#ifdef DEBUG
            printf("Error: invalid label\n");
#endif
            exit(1);
        }

        struct label_marker* label = NULL;
        for (int j = 0; j < p->label_count; j++) {
            if (strcmp(p->labels[j]->label, (char*)GET_REG(p, REG_R0)) == 0) {
                label = p->labels[j];
                break;
            }
        }

#ifdef DEBUG
        printf("JMP to label: %s\n", (char*)GET_REG(p, REG_R0));
#endif

        if (label == NULL) {
#ifdef DEBUG
            printf("Error: label not found\n");
#endif
            exit(1);
        }

        *i = label->instruction_index;
    } else if (n->data.action.action == ACTION_JP) {
        if (GET_REG(p, REG_R0) > 0) {
            if (!IS_STRING(p, REG_R1)) {
#ifdef DEBUG
                printf("Error: invalid label\n");
#endif
                exit(1);
            }

            struct label_marker* label = NULL;
            for (int j = 0; j < p->label_count; j++) {
                if (strcmp(p->labels[j]->label, (char*)GET_REG(p, REG_R1)) ==
                    0) {
                    label = p->labels[j];
                    break;
                }
            }

#ifdef DEBUG
            printf("JP to label: %s\n", (char*)GET_REG(p, REG_R1));
#endif

            if (label == NULL) {
#ifdef DEBUG
                printf("Error: label not found\n");
#endif
                exit(1);
            }

            *i = label->instruction_index;
        }
    }
}

uint64_t interpret_node(struct expression_node* n,
                        struct program* p,
                        bool* result_is_string, 
                        bool labeling_mode)
{
    if (n->type == NODE_TYPE_REG) {
        *result_is_string = IS_STRING(p, n->data.reg.reg);
        return GET_REG(p, n->data.reg.reg);
    } else if (n->type == NODE_TYPE_IMMEDIATE) {
        *result_is_string = 0;
        return n->data.immediate.value;
    } else if (n->type == NODE_TYPE_BINARY && !labeling_mode) {
        bool left_is_string, right_is_string;
        uint64_t left = interpret_node(n->data.binary.left, p, &left_is_string, labeling_mode);
        uint64_t right =
          interpret_node(n->data.binary.right, p, &right_is_string, labeling_mode);
        if (n->data.binary.op == BINARY_OP_PLUS) {
            if (!left_is_string && !right_is_string) {
                *result_is_string = 0;
                return left + right;
            } else if (left_is_string && right_is_string) {
                *result_is_string = 1;
                char* result =
                  malloc(1 + strlen((char*)left) + strlen((char*)right) + 1);
                strcpy(result, (char*)left);
                strcat(result, (char*)right);
                return (uint64_t)result;
            } else {
#ifdef DEBUG
                printf("Error: cannot add string and number\n");
                if (left_is_string) {
                    printf("Left: %s, Right: %lu\n", (char*) left, right);
                } else {
                    printf("Left: %lu, Right: %s\n", left, (char*) right);
                }
#endif
                exit(1);
            }
        } else if (n->data.binary.op == BINARY_OP_MINUS) {
            if (right_is_string) {
#ifdef DEBUG
                printf("Error: cannot subtract strings\n");
#endif
                exit(1);
            } else if (!left_is_string && !right_is_string) {
                *result_is_string = 0;
                return left - right;
            } else {
                *result_is_string = 1;
                char* result = strdup((char*)left);
                size_t len = strlen(result);
                if (len < right) {
                    right = len;
                }
#ifdef DEBUG
                printf("Subtracting %lu (%lu) from %s\n", right, len, result);
#endif
                result[right] = '\0';
                return (uint64_t)result;
            }
            return left - right;
        } else if (n->data.binary.op == BINARY_OP_MUL) {
            if (left_is_string && !right_is_string) {
                *result_is_string = 1;
                char* result = malloc(strlen((char*)left) * right + 1);
                strcpy(result, (char*)left);
                for (int i = 0; i < right - 1; i++) {
                    strcat(result, (char*)left);
                }
                return (uint64_t)result;
            } else if (!left_is_string && !right_is_string) {
                *result_is_string = 0;
                return left * right;
            } else {
#ifdef DEBUG
                printf("Error: invalid multiplication\n");
#endif
                exit(1);
            }
        } else if (n->data.binary.op == BINARY_OP_DIV) {
            if (left_is_string || right_is_string) {
#ifdef DEBUG
                printf("Error: cannot divide strings\n");
#endif
                exit(1);
            }
            *result_is_string = 0;
            return left / right;
        } else if (n->data.binary.op == BINARY_OP_XOR) {
            if (left_is_string && right_is_string) {
                *result_is_string = 1;
                size_t left_len = strlen((char*)left);
                size_t right_len = strlen((char*)right);
                char* result = malloc(MAX(left_len, right_len) + 1);
                for (int i = 0; i < MAX(left_len, right_len); i++) {
                    result[i] = ((char*)left)[i % left_len] ^
                                ((char*)right)[i % right_len];
                }
                result[MAX(left_len, right_len)] = '\0';
                return (uint64_t)result;
            } else if (!left_is_string && !right_is_string) {
                *result_is_string = 0;
                return left ^ right;
            } else {
#ifdef DEBUG
                printf("Error: invalid xor operation\n");
#endif
                exit(1);
            }
        } else if (n->data.binary.op == BINARY_OP_CMP) {
            if (left_is_string && right_is_string) {
                *result_is_string = 0;
                return strcmp((char*)left, (char*)right) == 0;
            } else if (!left_is_string && !right_is_string) {
                *result_is_string = 0;
                return left == right;
            } else {
#ifdef DEBUG
                printf("Error: invalid comparison\n");
#endif
                exit(1);
            }
        } else if (n->data.binary.op == BINARY_OP_CHAR_AT) {
            if (!left_is_string || right_is_string) {
#ifdef DEBUG
                printf("Error: invalid char_at operation\n");
#endif
                exit(1);
            }
            if (right >= strlen((char*)left)) {
#ifdef DEBUG
                printf("Error: index out of bounds\n");
#endif
                exit(1);
            }
            *result_is_string = 0;
            return ((char*)left)[right];
        }
    } else if (n->type == NODE_TYPE_STRING) {
        *result_is_string = 1;
        return (uint64_t)n->data.string.value;
    }

    if (labeling_mode) {
        return 0;
    }

#ifdef DEBUG
    printf("Error: invalid node type\n");
#endif
    exit(1);
}

void interpret_expression_root(struct expression* e, struct program* p, int* i)
{
    struct expression_node* n = e->root;
    if (n->type == NODE_TYPE_ASSIGNMENT) {
        bool is_string;
        GET_REG(p, n->data.assignment.left->data.reg.reg) =
          interpret_node(n->data.assignment.right, p, &is_string, false);
        SET_STRING(p, n->data.assignment.left->data.reg.reg, is_string);
    } else if (n->type == NODE_TYPE_PUSH_POP) {
        if (n->data.push_pop.left->type == NODE_TYPE_REG) {
            uint64_t val = GET_REG(p, n->data.push_pop.left->data.reg.reg);
            if (val) { // push
                if (p->state.stack_pointer >= 1023) {
#ifdef DEBUG
                    printf("Error: stack overflow\n");
#endif
                    exit(1);
                }
#ifdef DEBUG
                if (IS_STRING(p, n->data.push_pop.left->data.reg.reg)) {
                    printf("Pushing %s\n",
                           (char*)GET_REG(p, n->data.push_pop.left->data.reg.reg));
                } else {
                    printf("Pushing %lu\n", val);
                }
#endif
                p->state.stack[p->state.stack_pointer++] = val;
                p->state.alias_stack[p->state.stack_pointer - 1] =
                  IS_STRING(p, n->data.push_pop.left->data.reg.reg);
            } else { // pop
                if (p->state.stack_pointer == 0) {
#ifdef DEBUG
                    printf("Error: stack underflow\n");
#endif
                    exit(1);
                }
                GET_REG(p, n->data.push_pop.left->data.reg.reg) =
                p->state.stack[--p->state.stack_pointer];
                SET_STRING(p,
                    n->data.push_pop.left->data.reg.reg,
                    p->state.alias_stack[p->state.stack_pointer]);
#ifdef DEBUG
                if (IS_STRING(p, n->data.push_pop.left->data.reg.reg)) {
                    printf("Popping %s\n",
                           (char*)GET_REG(p, n->data.push_pop.left->data.reg.reg));
                } else {
                    printf("Popping %lu\n",
                           GET_REG(p, n->data.push_pop.left->data.reg.reg));
                }
#endif
                }
        } else {
#ifdef DEBUG
            printf("Error: invalid push/pop target\n");
#endif
            exit(1);
        }
    } else if (n->type == NODE_TYPE_ACTION) {
        interpret_action(n, p, i);
    } else {
#ifdef DEBUG
        printf("Error: invalid root node type\n");
#endif
        exit(1);
    }
}

void compute_labels(struct program* p)
{
    // we have to run through the program once to compute the labels
    // we can compute just the assignments and the label actions
    for (int i = 0; i < p->expression_count; i++) {
        struct expression_node* n = p->expressions[i]->root;
        if (n->type == NODE_TYPE_ASSIGNMENT) {
            bool is_string;
            GET_REG(p, n->data.assignment.left->data.reg.reg) =
              interpret_node(n->data.assignment.right, p, &is_string, true);
            SET_STRING(p, n->data.assignment.left->data.reg.reg, is_string);
        } else if (n->type == NODE_TYPE_ACTION) {
            if (n->data.action.action == ACTION_LABEL) {
                // check if the label already exists
                bool found = false;
                for (int j = 0; j < p->label_count; j++) {
                    if (strcmp(p->labels[j]->label,
                               (char*)GET_REG(p, REG_R0)) == 0) {
                        found = true;
                        p->labels[j]->instruction_index = i;
                        break;
                    }
                }

                if (!found) {
                    p->label_count++;
                    p->labels = realloc(
                      p->labels, p->label_count * sizeof(struct label_marker*));
                    p->labels[p->label_count - 1] =
                      malloc(sizeof(struct label_marker));
                    p->labels[p->label_count - 1]->label =
                      strdup((char*)GET_REG(p, REG_R0));
                    p->labels[p->label_count - 1]->instruction_index = i;
                }

                // after a label, we have to push a fake frame by clearing all registers
                for (int j = 0; j < 8; j++) {
                    p->state.frames[p->state.frame_count - 1]->registers[j] = 0;
                    p->state.frames[p->state.frame_count - 1]->reg_alias_types[j] = 0;
                }
            }
        }
    }
}

void interpreter_main(struct program* p)
{
    for (int i = 0; i < p->expression_count; i++) {
        struct expression_node* n = p->expressions[i]->root;
        interpret_expression_root(p->expressions[i], p, &i);
    }
}

void free_emulator(struct program* p)
{
    for (int i = 0; i < p->state.frame_count; i++) {
        free(p->state.frames[i]);
    }
    free(p->state.frames);

    for (int i = 0; i < p->label_count; i++) {
        free(p->labels[i]->label);
        free(p->labels[i]);
    }
    free(p->labels);
}

void reset_state(struct program* p)
{
    for (int i = 0; i < p->state.frame_count; i++) {
        free(p->state.frames[i]);
    }
    free(p->state.frames);

    p->state.frames = malloc(1 * sizeof(struct frame*));
    p->state.frame_count = 1;
    p->state.frames[0] = malloc(sizeof(struct frame));
    for (int i = 0; i < 8; i++) {
        p->state.frames[0]->registers[i] = 0;
        p->state.frames[0]->reg_alias_types[i] = 0;
    }
    p->state.stack_pointer = 0;
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        menu(argv);
        return 1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    FILE* file = open_file(argv[1]);
    struct tokenized_program* tp = tokenize(file);
    close_file(file);

#ifdef DEBUG
    pprint_tokenized_program(tp);
#endif

    struct program* p = create_program();
    parse_tokenized_program(p, tp);

    free_tokenized_program(tp);

#ifdef DEBUG
    pprint_program(p);
#endif

    init_emulator(p);
    compute_labels(p);
    reset_state(p);
    interpreter_main(p);
    free_emulator(p);

    free_program(p);

    return 0;
}
