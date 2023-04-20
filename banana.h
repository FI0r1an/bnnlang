/*
MIT License

Copyright (c) 2021 Cluck

	Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef BANANA_LANG
#define BANANA_LANG

#include <stdint.h>
#include <stdio.h>

#define STR_TABLE_LEN 16
#define STR_TABLE_STEP 2

typedef size_t str_order;

typedef struct str_table
{
	size_t rlen, len;

	char **sto;
	unsigned *hash_sto;
} str_table;

typedef struct token
{
	enum TOKEN_TYPE
	{
		TT_START_HERE = 0,

		TT_STRING,
		TT_NUMBER,
		TT_HEXNUMBER,
		TT_BINNUMBER,
		TT_OCTNUMBER,
		TT_IDENTIFIER,
		TT_EOF,

		TT_KEYWORD_AFTER,

		TT_IN,
		TT_OUT,

		TT_VAR,

		TT_RVAR,
		TT_LVAR,

		TT_FN,
		TT_IF,
		//TT_RETURN,
		TT_WHILE_DO,
		TT_DO_WHILE,
		TT_DO_UNTIL,
		TT_LEAVE,
		TT_CONTINUE,
		TT_DO,

		TT_YES,
		TT_NO,
		TT_NULL_KW,
		//TT_TYPEOF,

		TT_SYMBOL_AFTER,

		TT_IS,
		TT_EQ,
		TT_NEQ,
		TT_GE,
		TT_GT,
		TT_LE,
		TT_LT,
		TT_ADD,
		TT_SUB,
		TT_MUL,
		TT_DIV,
		TT_NOT,
		TT_AND,
		TT_OR,

		TT_CONTROL_AFTER,

		TT_LPARE,
		TT_RPARE,
		//TT_LBRACE,
		//TT_RBRACE,
		//TT_LBRACKET,
		//TT_RBRACKET,
		TT_SEMI, // for empty statement
		TT_COMMA,

		TT_PIPELINE,
		TT_EXPORT, // A => B, A will be the arguments of function B,
		// and return B with arguments A
		TT_EXPORT_LONG, // A ==> B, the same as A => B, but will call B.
		// return the results of B

		TT_SIGN_END,
	} tt;
	str_order val;
	size_t row, col;
} token;

// 64 - 1 (\0)
#define VAL_BUF_LEN 63
typedef struct lexer
{
	size_t col, row, idx, len;
	//len includes '\0'
	char *source;

	size_t val_buf_idx;
	char *val_buf;

	char *file_name;
	str_table *str_table;
} lexer;

#define DEFAULT_LEN 2

struct pfront_part;

typedef struct pcall_name
{
	enum CN_TYPE
	{
		CN_FRONT_PART = 0,
		CN_KEYWORD,
		CN_SYMBOL,
	} type;

	union
	{
		struct pfront_part *front_part;
		enum TOKEN_TYPE tt;
	};

	size_t row, col;
} pcall_name;

typedef struct pcall_stmt
{
	pcall_name *call_name;

	struct
	{
		struct pfront_part *front_parts;
		size_t fp_idx, fp_len;
	};

	size_t row, col;
} pcall_stmt;

typedef struct pfront_part
{
	enum FP_TYPE
	{
		FP_ANY_VALUE = 0,
		FP_CALL_STMT,
	} type;

	union
	{
		token *tk;
		pcall_stmt *call_stmt;
	};

	size_t row, col;
} pfront_part;

struct pstatement;

typedef struct poptional_part
{
	enum OP_TYPE
	{
		OP_SPEC_OPER_1,
		OP_SPEC_OPER_2,
		OP_SPEC_OPER_3,
	} type;

	pfront_part *fp;

	size_t row, col;
} poptional_part;

typedef struct pstatement
{
	struct
	{
		struct pfront_part *front_parts;
		size_t fp_idx, fp_len;
	};

	struct
	{
		poptional_part *optional_parts;
		size_t op_idx, op_len;
	};

	size_t row, col;
} pstatement;

typedef uint32_t BNN_CONST;
typedef double BNN_NUMBER;

#define STORAGE_MAX 128
#define STACK_STORAGE_MAX 16
#define REGISTER_STORAGE_MAX 32
#define REGISTER_STORAGE_AMOUNT 16
#define STORAGE_DEFAULT 16
#define STORAGE_STEP 2

struct bnn_vm;
typedef void ( *BNN_CFUNCTION )( struct bnn_vm * );

typedef struct bnn_value
{
	enum VALU_TYPE
	{
		VALU_CONST,
		VALU_STRING,
		VALU_NUMBER,
		VALU_FUNCTION,
		VALU_CFUNCTION,
	} type;

	union
	{
		BNN_CONST const_val;
		BNN_NUMBER number_val;
		str_order string_val;
		BNN_CFUNCTION cfunction_val;
	} val;
} bnn_value;

typedef struct vm_stack
{
	size_t len;
	int top;
	BNN_CONST *storage;
} vm_stack;

#define EOS ( -1 )

typedef struct vm_storage
{
	bnn_value *sto;
	size_t len;
} vm_storage;

typedef enum INST_TYPE
{
	INST_RA,   // R[A] 5+20 25bits
	INST_RAB,  // R[A] R[B] 5+5+5 15bits
	INST_RABC, // R[A] R[B] R[C] 5+5+5+5 20bits
	INST_RAIB, // R[A] C[B]/M[B]/IP=B 5+5+20 30bits
} INST_TYPE;

typedef uint32_t int_inst;

#define OPCODE_BITS 6
#define REGISTER_BITS 5
#define INTEGER_BITS 19
#define INST_TYPE_BITS 2
#define INTEGER_BITS_SHIFT ( 0b1111111111111111111 )
#define INST_TYPE_BITS_SHIFT ( 0b11 )
#define REGISTER_BITS_SHIFT ( 0b11111 )

#define bit_cat( x, shift, y ) ( x << shift | y )
#define bit_flag( x ) << INST_TYPE_BITS | x
#define INST_X_M( op ) ( ( int_inst ) op bit_flag( INST_X ) )
#define INST_RA_M( op, A ) ( bit_cat( ( int_inst ) op, INTEGER_BITS, A ) bit_flag( INST_RA ) )
#define INST_RAB_M( op, A, B ) ( bit_cat( bit_cat( ( int_inst ) op, REGISTER_BITS, A ), REGISTER_BITS, B ) bit_flag( INST_RAB ) )
#define INST_RABC_M( op, A, B, C ) \
	( bit_cat( bit_cat( bit_cat( ( int_inst ) op, REGISTER_BITS, A ), REGISTER_BITS, B ), REGISTER_BITS, C ) bit_flag( INST_RABC ) )
#define INST_RAIB_M( op, A, B ) \
	( bit_cat( bit_cat( ( int_inst ) op, REGISTER_BITS, A ), INTEGER_BITS, B ) bit_flag( INST_RAIB ) )

typedef struct bnn_inst
{
	enum OPCODE
	{
		// no args RA
		OP_HALT,

		// push A RA
		OP_PUSH,
		OP_PUSHR,

		// pop and save to R[A] RA
		OP_POP,

		// no args RA
		OP_DUP,

		// R[A] = M[B] RAIB
		OP_LOAD,

		// R[A] = C[B] RAIB
		OP_LOADC,

		// M[B] = R[A] RAIB
		OP_STORE,

		// R[A] = R[B] RAB
		OP_MOV,

		// R[C] = R[A] OP R[B] RABC
		OP_ADD,
		OP_SUB,
		OP_MUL,
		OP_DIV,
		OP_EQ,
		OP_NEQ,
		OP_GE,
		OP_GT,
		OP_LE,
		OP_LT,
		OP_AND,
		OP_OR,

		// R[B] = OP R[A] RAB
		OP_NOT,
		OP_INV,

		// IP = B RAIB
		OP_JMP,
		// IP = R[A] RAIB
		OP_JMPR,
		// IP = B if R[A] RAIB
		OP_JMPT,
		// IP = B if not R[A] RAIB
		OP_JMPF,

		// call R[A] RA
		OP_CALL,
		OP_CALLC,

		OP_SETI,

		OP_RET,

		// input/output R[A] RA
		OP_IN,
		OP_OUT,
	} op;

	uint32_t A, B, C;
} bnn_inst;

struct gen_var;

typedef struct vm_func
{
	BNN_CONST start, args;
	struct gen_var *default_args;
} vm_func;

typedef struct vm_func_storage
{
	size_t len, idx;
	vm_func *sto;
} vm_func_storage;

typedef struct inst_storage
{
	BNN_CONST ip, len, write_idx;

	vm_func_storage *func_sto;

	int_inst *storage;
} inst_storage;

#define INST_MIN 1
#define INST_MAX 65535
#define INST_STEP 1

typedef struct bnn_vm
{
	str_table *glb_str_table;
	vm_storage const_sto, memory_sto;
	bnn_value *registers;
	vm_stack *stack_sto;

	inst_storage *insts;
} bnn_vm;

#define NAMELESS ( TT_SUB )

enum REGISTER
{
	R_ADR = 0,
	R_GRB = 1,
	R_EBP = 2,
	R_ESP = 3,
	R_VLBF,

	R_RA,
	R_RB,
	R_RC,
	R_RD,
};

enum VAR_TYPE
{
	VAR_REGISTER = 0,
	VAR_MEMORY,
	VAR_CONST,

	VAR_TYPE_AMOUNT,
	VAR_LOCAL,
	VAR_INTERIOR,
};

typedef struct gen_var
{
	str_order identifier;
	enum VAR_TYPE type;
	BNN_CONST idx;
} gen_var;

#define SYM_TABLE_STEP 2

typedef struct sym_section
{
	size_t idx, len;
	gen_var *sto;
} sym_section;

typedef struct sym_table
{
	sym_section *sections;
} sym_table;

struct gen_field;

#define GLOBAL_FIELD NULL

typedef struct gen_field
{
	sym_section *locals;
} gen_field;

#define FIELD_STACK_MAX 16

typedef struct field_stack
{
	size_t len;
	int top;
	gen_field **storage;
} field_stack;

typedef struct bnn_state
{
	lexer *lex;

	char *file_name;

	str_table *glb_str_table;

	token tk_buffer;

	gen_field *cur_field;
	sym_table *glb_sym_table;
	field_stack *fields;
	inst_storage *opcodes;
} bnn_state;

#define YES 1
#define NO 0
#define NIL 2

#define YES_IDX 0
#define NO_IDX 1
#define NIL_IDX 2

#endif
