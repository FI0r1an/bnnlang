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

#include "banana.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined( _DEBUG ) || defined( BNN_SAFE_MODE )
#	include <assert.h>
#	define check_null( v ) assert( v )
#else
#	define check_null( v ) ( void ) 0
#endif

#define BNN_FN static

static const char *const reserved_words[] = {
	"#null",
	"#string",
	"#number",
	"#hexnumber",
	"#binnumber",
	"#octnumber",
	"#identifier",
	"#eof",
	"#kw_after",
	"in",
	"out",
	"var",
	"rvar",
	"lvar",
	"fn",
	"if",
	//"return",
	"whiledo",
	"dowhile",
	"dountil",
	"leave",
	"continue",
	"do",
	"yes",
	"no",
	"nil",
	//"typeof",
	"#sym_after",
	"=",
	"==",
	"!=",
	">=",
	">",
	"<=",
	"<",
	"+",
	"-",
	"*",
	"/",
	"!",
	"&&",
	"||",
	"#ctrl_after",
	"(",
	")",
	/*"{", "}", "[", "]",*/ ";",
	",",
	"|>",
	"=>",
	"==>",
	"#sign_end",
};

static const char *opcode_strings[] = {
	"HALT",

	"PUSH",
	"PUSHR",

	"POP",

	"DUP",

	"LOAD",

	"LOADC",

	"STORE",

	"MOV",

	"ADD",
	"SUB",
	"MUL",
	"DIV",
	"EQ",
	"NEQ",
	"GE",
	"GT",
	"LE",
	"LT",
	"AND",
	"OR",

	"NOT",
	"INV",

	"JMP",

	"JMPR",

	"JMPT",

	"JMPF",

	"CALL",
	"CALLC",

	"SETI",

	"RET",

	"IN",
	"OUT",
};

static token TOKEN_NULL = { TT_SIGN_END, 0, 0, 0 };
static gen_var NULL_VAR = { 0 };

#define str_table_get( t, pos ) ( t->sto[ pos ] )

#define bassert( stmt, msg, ... ) ( !!( stmt ) || berror( msg, __VA_ARGS__ ) )
#define bbad_char( c, row, col ) berror( "[%s %zd:%zd] Unexpected character '%c'", lex->file_name, row, col, c )

#define is_end( lex ) ( lex->idx >= lex->len - 1 )
#define not_end( lex ) ( lex->idx < lex->len - 1 )

#define is_line( c ) ( c == '\r' || c == '\n' )

#define is_alpha( c ) ( isalpha( c ) || c == '_' )

BNN_FN int get_num( char c )
{
	int rsl = tolower( c );

	return ( rsl >= 'a' ) ? ( rsl - 'a' + 10 ) : ( rsl - '0' );
}

BNN_FN BNN_NUMBER convert_num_to_str( const char *str )
{
	char sign = str[ 1 ];
	int num_sys = 10;
	double lpart = 0., rpart = 0.;

	switch ( sign )
	{
		case 'b':
			num_sys = 2;
		case 'o':
			num_sys = 8;
		case 'x':
			num_sys = 16;
	}

	size_t len = strlen( str );

	int meet_point = NO;

	for ( size_t i = 2; i < len; i++ )
	{
		char cur = str[ i ];

		if ( cur == '.' )
		{
			meet_point = YES;
			continue;
		}

		if ( meet_point )
		{
			rpart = ( rpart + get_num( cur ) ) / num_sys;
		}
		else
		{
			lpart = lpart * num_sys + get_num( cur );
		}
	}

	return lpart + rpart;
}

BNN_FN char *strclone( const char *source )
{
	size_t len = strlen( source ) + 1;
	char *dest = ( char * ) calloc( len, sizeof( char ) );

	check_null( dest );

	strcpy( dest, source );
	return dest;
}

BNN_FN unsigned int DJB_hash( char *str )
{
	unsigned int hash = 5381;

	while ( *str )
	{
		hash = ( ( hash << 5 ) + hash ) + ( *str );

		str++;
	}

	return hash;
}

BNN_FN str_table *new_str_table( )
{
	str_table *rsl = ( str_table * ) malloc( sizeof( str_table ) );
	assert( rsl );

	rsl->rlen = 0;
	rsl->len = DEFAULT_LEN;

	rsl->sto = ( char ** ) calloc( DEFAULT_LEN, sizeof( char * ) );
	assert( rsl->sto );
	rsl->hash_sto = ( unsigned * ) malloc( DEFAULT_LEN * sizeof( unsigned ) );
	assert( rsl->hash_sto );

	return rsl;
}

BNN_FN str_order str_table_add( str_table *tbl, char *str )
{
	unsigned str_hash = DJB_hash( str );

	for ( size_t i = 0; i < tbl->rlen; i++ )
	{
		unsigned tbl_hash = tbl->hash_sto[ i ];
		if ( tbl_hash == str_hash )
		{
			return ( str_order ) i;
		}
	}

	if ( tbl->rlen >= tbl->len )
	{
		tbl->len += STR_TABLE_STEP;

		void *temp;

		temp = realloc( tbl->sto, tbl->len * sizeof( char * ) );
		assert( temp );
		tbl->sto = ( char ** ) temp;

		temp = realloc( tbl->hash_sto, tbl->len * sizeof( unsigned ) );
		assert( temp );
		tbl->hash_sto = ( unsigned * ) temp;
	}

	// avoid warning
	*( tbl->sto + tbl->rlen ) = str;
	*( tbl->hash_sto + tbl->rlen ) = DJB_hash( str );

	return tbl->rlen++;
}

BNN_FN void free_str_table( str_table *tbl )
{
	for ( size_t i = 0; i < tbl->rlen; i++ )
	{
		free( tbl->sto[ i ] );
	}

	free( tbl->sto );
	free( tbl->hash_sto );

	free( tbl );
}

BNN_FN inline int berror( const char *msg, ... )
{
	va_list ap;

	va_start( ap, msg );

	vprintf( msg, ap );

	va_end( ap );
	abort( );

	return 0;
}

BNN_FN lexer *new_lexer( )
{
	lexer *lex = ( lexer * ) malloc( sizeof( lexer ) );

	check_null( lex );

	lex->row = lex->col = 1;
	lex->val_buf_idx = lex->idx = 0;

	lex->val_buf = ( char * ) calloc( VAL_BUF_LEN + 1, sizeof( char ) );
	check_null( lex->val_buf );

	return lex;
}

// only call once
BNN_FN void lexer_set_input( lexer *lex, const char *source, const char *file_name )
{
	lex->len = strlen( source ) + 1;
	lex->source = ( char * ) calloc( lex->len, sizeof( char ) );

	// this wont get free
	// state gotta use this
	lex->file_name = strclone( file_name );

	check_null( lex->source );

	strcpy( lex->source, source );
}

BNN_FN void free_lexer( lexer *lex )
{
	free( lex->source );
	free( lex->val_buf );
	free( lex );

	lex = NULL;
}

BNN_FN inline char bcurr( lexer *lex )
{
	return not_end( lex ) ? lex->source[ lex->idx ] : 0;
}

BNN_FN inline char bnext( lexer *lex )
{
	char rsl = bcurr( lex );

	lex->idx++, lex->col++;

	return rsl;
}

BNN_FN inline void bnext_line( lexer *lex )
{
	char old = bnext( lex );
	char cur = bcurr( lex );

	if ( ( cur == '\r' || cur == '\n' ) && cur != old )
	{
		bnext( lex );
	}

	lex->row++;
	lex->col = 1;
}

BNN_FN inline char blook_ahead( lexer *lex )
{
	return ( lex->idx < lex->len - 2 ) ? lex->source[ lex->idx + 1 ] : 0;
}

BNN_FN void bwrite( lexer *lex, char c )
{
	bassert( lex->val_buf_idx < VAL_BUF_LEN, "[%s %zd:%zd] Too long token",
			 lex->file_name, lex->row, lex->col );
	lex->val_buf[ lex->val_buf_idx++ ] = c;
}

BNN_FN str_order bsave( lexer *lex )
{
	size_t len = lex->val_buf_idx;
	char *str = ( char * ) calloc( len + 1, sizeof( char ) );

	check_null( str );

	strncpy( str, lex->val_buf, len );

	lex->val_buf_idx = 0;

	return str_table_add( lex->str_table, str );
}

BNN_FN int bget_num( lexer *lex, char c )
{
	bassert( isxdigit( c ), "[%s %zd:%zd] Unknown escape content", lex->file_name, lex->row, lex->col );

	return get_num( c );
}

BNN_FN void bread_string( lexer *lex, str_order *rsl )
{
	bwrite( lex, '\\' );

	char sign = bnext( lex );
	size_t row = lex->row, col = lex->col;

	int is_esc_char = 0;

	while ( bcurr( lex ) != sign )
	{
		if ( is_end( lex ) )
			berror( "[%s %zd %zd] Unfinished string", lex->file_name, row, col );
		char c = bnext( lex );

		if ( c == '\\' )
		{
			is_esc_char = 1;
			c = bnext( lex );
		}
		else if ( c == '\r' || c == '\n' )
		{
			bnext_line( lex );
		}

		if ( is_esc_char )
		{
			is_esc_char = 0;

			switch ( c )
			{
				case 'n':
					c = '\n';
					break;
				case 'a':
					c = '\a';
					break;
				case 'b':
					c = '\b';
					break;
				case 'f':
					c = '\f';
					break;
				case 'r':
					c = '\r';
					break;
				case 't':
					c = '\t';
					break;
				case 'v':
					c = '\v';
					break;
				case '\\':
					c = '\\';
					break;
				case '\'':
					c = '\'';
					break;
				case '"':
					c = '"';
					break;
				case 'x': {
					// \x00 ~ \x80
					// at least 2 characters
					// hex to ascii

					bassert( isxdigit( bcurr( lex ) ), "[%s %zd:%zd] Unknown escape sign '%c'",
							 lex->file_name, row, col, bcurr( lex ) );

					c = bcurr( lex );

					int num = 0;

					for ( int i = 0; i < 2 && isxdigit( c ); i++ )
					{
						num = ( num << 4 ) + bget_num( lex, c );
						bnext( lex );
						c = bcurr( lex );
					}

					bassert( num >= 0 && num <= 0xFF,
							 "[%s %zd:%zd] Escape character out of range", lex->file_name, row, col );

					c = ( char ) num;

					break;
				}
				case 'u': // utf8
				{

					break;
				}
				default: {
					// decimal ascii
					// \000 ~ \127

					bassert( c >= '0' && c <= '9', "[%s %zd:%zd] Unknown escape sign '%c'",
							 lex->file_name, row, col, c );

					int num = 0;

					for ( int i = 0; i < 3 && isdigit( c ); i++ )
					{
						num = 10 * num + bget_num( lex, c );
						c = bnext( lex );
					}

					lex->idx--; // oh no
					lex->col--;

					bassert( num >= 0 && num <= 0xFF,
							 "[%s %zd:%zd] Escape character out of range", lex->file_name, row, col );

					c = ( char ) num;

					break;
				}
			}
		}

		bwrite( lex, c );
	}

	bnext( lex );
	*rsl = bsave( lex );
}

BNN_FN enum TOKEN_TYPE bread_number( lexer *lex, str_order *rsl )
{
	// $ represents number
	bwrite( lex, '$' );

	int has_dot = 0;

	enum TOKEN_TYPE typ = TT_NUMBER;

	char n = blook_ahead( lex );
	if ( bcurr( lex ) == '0' )
	{
		switch ( n )
		{
			case 'b':
			case 'B':
				bwrite( lex, 'b' );
				typ = TT_BINNUMBER;
				goto skip;
			case 'x':
			case 'X':
				bwrite( lex, 'x' );
				typ = TT_HEXNUMBER;
				goto skip;
			case 'o':
			case 'O':
				bwrite( lex, 'o' );
				typ = TT_OCTNUMBER;
				goto skip;
			skip:
				lex->idx += 2;
				lex->col += 2;
				break;
		}
	}
	else
	{
		bwrite( lex, 'd' );
	}

	for ( ;; )
	{
		char c = bcurr( lex );

		if ( c == '.' )
		{
			has_dot ? ( bbad_char( c, lex->row, lex->col ) ) : ( has_dot = 1 );
		}
		else if ( c == '_' )
		{
			bnext( lex );
			continue;
		}
		else if ( !isxdigit( c ) )
			break;

		bwrite( lex, c );

		bnext( lex );
	}
	*rsl = bsave( lex );

	return typ;
}

BNN_FN enum TOKEN_TYPE bread_alpha( lexer *lex, str_order *rsl )
{
	char c = bcurr( lex );
	while ( is_alpha( c ) || ( c >= '0' && c <= '9' ) )
	{
		bwrite( lex, bnext( lex ) );
		c = bcurr( lex );
	}
	*rsl = bsave( lex );

	return *rsl <= TT_SYMBOL_AFTER ? ( enum TOKEN_TYPE )( *rsl ) : TT_IDENTIFIER;
}

BNN_FN enum TOKEN_TYPE bread_symbol( lexer *lex )
{
	size_t row = lex->row, col = lex->col;
	size_t step = 0;
	enum TOKEN_TYPE rsl = 0;
	char c = bnext( lex );
	char n = bcurr( lex );

	switch ( c )
	{
		case '=': {
			//c == n ? (rsl = TT_EQ, step = 1) : (rsl = TT_IS);
			if ( c == n )
			{
				step = 1;
				rsl = TT_EQ;

				if ( blook_ahead( lex ) == '>' )
				{
					step = 2;
					rsl = TT_EXPORT_LONG;
				}
			}
			else if ( n == '>' )
			{
				step = 1;
				rsl = TT_EXPORT;
			}
			else
				rsl = TT_IS;
			break;
		}
		case '!':
			n == '=' ? ( rsl = TT_NEQ, step = 1 ) : ( rsl = TT_NOT );
			break;
		case '>':
			n == '=' ? ( rsl = TT_GE, step = 1 ) : ( rsl = TT_GT );
			break;
		case '<':
			n == '=' ? ( rsl = TT_LE, step = 1 ) : ( rsl = TT_LT );
			break;
		case '+':
			rsl = TT_ADD;
			break;
		case '-':
			rsl = TT_SUB;
			break;
		case '*':
			rsl = TT_MUL;
			break;
		case '/':
			rsl = TT_DIV;
			break;
		case '(':
			rsl = TT_LPARE;
			break;
		case ')':
			rsl = TT_RPARE;
			break;
			/*case '[':
					rsl = TT_LBRACKET;
					break;
				case ']':
					rsl = TT_RBRACKET;
					break;
				case '{':
					rsl = TT_LBRACE;
					break;
				case '}':
					rsl = TT_RBRACE;
					break;*/
		case '&':
			bassert( n == c, "[%s %zd:%zd] Expected '&' but got '%c'", lex->file_name, row, col + 1, n );
			step = 1;
			rsl = TT_AND;
			break;
		case '|':
			step = 1;

			if ( n == '>' )
			{
				rsl = TT_PIPELINE;
				break;
			}

			bassert( n == c, "[%s %zd:%zd] Expected '|' but got '%c'", lex->file_name, row, col + 1, n );
			rsl = TT_OR;
			break;
		case ',':
			rsl = TT_COMMA;
			break;
		case ';':
			rsl = TT_SEMI;
			break;
	}

	lex->idx += step;
	lex->col += step;

	bassert( rsl, "[%s %zd:%zd] Unrecongized symbol '%c'", lex->file_name, row, col, c );

	return rsl;
}

BNN_FN void skip_line_comment( lexer *lex )
{
	char c = bcurr( lex );

	while ( c != '\r' && c != '\n' )
	{
		if ( is_end( lex ) )
			return;

		bnext( lex );

		c = bcurr( lex );
	}
}

BNN_FN void skip_block_comment( lexer *lex )
{
	char c = 0;
	size_t row = lex->row, col = lex->col;

	while ( bcurr( lex ) != '*' || blook_ahead( lex ) != '/' )
	{
		if ( is_end( lex ) )
			berror( "[%s %zd:%zd] Unfinished comment", lex->file_name, row, col );
		c = bcurr( lex );
		if ( is_line( c ) )
		{
			bnext_line( lex );
			continue;
		}
		bnext( lex );
	}

	bnext( lex );
	bnext( lex );
}

BNN_FN token lexer_next( lexer *lex )
{
	str_order rsl = 0;
	size_t row = lex->row, col = lex->col;

	for ( ;; )
	{
		char c = bcurr( lex ), n = blook_ahead( lex );

		switch ( c )
		{
			case 0:
				return ( token ){
					TT_EOF,
					0,
					row,
					col,
				};
			case '\r':
			case '\n':
				bnext_line( lex );
				break;
			case ' ':
			case '\t':
				bnext( lex );
				break;
			case '/':
				if ( c == n )
				{
					skip_line_comment( lex );
					break;
				}
				else if ( n == '*' )
				{
					skip_block_comment( lex );
					break;
				}
				else
				{
					goto fallback;
				}
			case '\'':
			case '"':
				bread_string( lex, &rsl );
				return ( token ){ TT_STRING, rsl, row, col };
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				goto number;
			default:
			fallback : {
				if ( is_alpha( c ) )
				{
					enum TOKEN_TYPE tt = bread_alpha( lex, &rsl );
					return ( token ){ tt, rsl, row, col };
				}
				else if ( c == '.' )
				{
					goto number;
				}
				else
				{
					enum TOKEN_TYPE tt;
					if ( ( tt = bread_symbol( lex ) ) < TT_SYMBOL_AFTER )
					{
						bbad_char( c, lex->row, lex->col );
					}
					return ( token ){ tt, rsl, row, col };
				}
			}
			number : {
				enum TOKEN_TYPE tt = bread_number( lex, &rsl );
				return ( token ){ tt, rsl, row, col };
			}
		}
	}
}

#define pnext( ) ( state->tk_buffer = lexer_next( state->lex ) )
#define pcurr( ) ( state->tk_buffer.tt == TT_SIGN_END ? pnext( ) : state->tk_buffer )

BNN_FN token *tkval_to_pointer( token *tkval )
{
	token *tkptr = ( token * ) malloc( sizeof( token ) );

	check_null( tkptr );

	tkptr->col = tkval->col;
	tkptr->row = tkval->row;
	tkptr->tt = tkval->tt;
	tkptr->val = tkval->val;

	return tkptr;
}

BNN_FN pcall_name *new_pcall_name( enum CN_TYPE type, size_t row, size_t col )
{
	pcall_name *cn = ( pcall_name * ) malloc( sizeof( pcall_name ) );

	check_null( cn );

	cn->col = col;
	cn->row = row;
	cn->type = type;

	cn->front_part = NULL;

	return cn;
}

BNN_FN pcall_stmt *new_pcall_stmt( pcall_name *cn, size_t row, size_t col )
{
	pcall_stmt *cs = ( pcall_stmt * ) malloc( sizeof( pcall_stmt ) );

	check_null( cs );

	cs->call_name = cn;
	cs->row = row;
	cs->col = col;

	cs->front_parts = NULL;

	return cs;
}

BNN_FN pfront_part *new_pfront_part( enum FP_TYPE type, size_t row, size_t col )
{
	pfront_part *fp = ( pfront_part * ) malloc( sizeof( pfront_part ) );

	check_null( fp );

	fp->col = col;
	fp->row = row;
	fp->type = type;

	fp->tk = NULL;
	fp->call_stmt = NULL;

	return fp;
}

BNN_FN poptional_part *new_poptional_part( enum OP_TYPE type, size_t row, size_t col )
{
	poptional_part *op = ( poptional_part * ) malloc( sizeof( poptional_part ) );

	check_null( op );

	op->col = col;
	op->row = row;
	op->type = type;

	op->fp = NULL;

	return op;
}

BNN_FN pstatement *new_pstatement( size_t row, size_t col )
{
	pstatement *stmt = ( pstatement * ) malloc( sizeof( pstatement ) );

	check_null( stmt );

	stmt->row = row;
	stmt->col = col;

	stmt->front_parts = NULL;
	stmt->optional_parts = NULL;

	return stmt;
}

BNN_FN void free_pfront_part( pfront_part *fp, int free_self );

BNN_FN void free_all_pfront_parts( pfront_part *ptr, size_t len )
{
	for ( size_t i = 0; i < len; i++ )
	{
		pfront_part fp = ptr[ i ];

		free_pfront_part( &fp, NO );
	}

	free( ptr );
}

BNN_FN void free_pcall_name( pcall_name *cn );

BNN_FN void free_pcall_stmt( pcall_stmt *stmt )
{
	if ( stmt->call_name )
		free_pcall_name( stmt->call_name );

	if ( stmt->front_parts )
		free_all_pfront_parts( stmt->front_parts, stmt->fp_idx );

	free( stmt );
}

BNN_FN void free_pfront_part( pfront_part *fp, int free_self )
{
	if ( fp->type == FP_ANY_VALUE )
	{
		if ( fp->tk )
			free( fp->tk );
	}
	else if ( fp->call_stmt )
	{
		free_pcall_stmt( fp->call_stmt );
	}

	!free_self || ( free( fp ), 0 );
}

BNN_FN void free_pcall_name( pcall_name *cn )
{
	if ( !cn )
		return;

	if ( cn->type == CN_FRONT_PART && cn->front_part )
		free_pfront_part( cn->front_part, YES );

	free( cn );
}

BNN_FN void free_poptional_part( poptional_part *op, int free_self );

BNN_FN void free_pstatement( pstatement *stmt, int free_self )
{
	if ( stmt->front_parts )
		free_all_pfront_parts( stmt->front_parts, stmt->fp_idx );

	if ( stmt->optional_parts )
	{
		for ( size_t i = 0; i < stmt->op_idx; i++ )
		{
			free_poptional_part( &stmt->optional_parts[ i ], NO );
		}

		free( stmt->optional_parts );
	}

	!free_self || ( free( stmt ), 0 );
}

BNN_FN void free_poptional_part( poptional_part *op, int free_self )
{
	if ( op->fp )
		free_pfront_part( op->fp, YES );

	!free_self || ( free( op ), 0 );
}

#define make_list( type, ptr, idx, len )                     \
	ptr = ( type * ) malloc( DEFAULT_LEN * sizeof( type ) ); \
	check_null( ptr );                                       \
	idx = 0;                                                 \
	len = DEFAULT_LEN

BNN_FN inline pfront_part *add_to_pfront_part_list( pfront_part *ptr, size_t *idx,
													size_t *len, pfront_part *ele )
{
	if ( *idx + 1 >= *len )
	{
		*len <<= 1;
		pfront_part *temp = realloc( ptr, *len * sizeof( pfront_part ) );

		check_null( temp );

		ptr = temp;
	}

	check_null( ptr );

	ptr[ *idx ] = *ele;
	( *idx )++;

	return ptr;
}

BNN_FN inline poptional_part *add_to_poptional_part_list( poptional_part *ptr, size_t *idx,
														  size_t *len, poptional_part *ele )
{
	if ( *idx + 1 >= *len )
	{
		*len = *len << 2;
		poptional_part *temp = realloc( ptr, *len * sizeof( poptional_part ) );

		check_null( temp );

		ptr = temp;
	}

	check_null( ptr );

	ptr[ *idx ] = *ele;
	( *idx )++;

	return ptr;
}

BNN_FN pfront_part *parse_front_part( bnn_state *state );

// call_name ::= front_part | KEYWORD | SYMBOL
BNN_FN pcall_name *parse_call_name( bnn_state *state )
{
	token tk = pcurr( );

	enum CN_TYPE type = CN_FRONT_PART;

	if ( tk.tt == TT_SEMI )
	{
		pnext( );

		return NULL;
	}

	if ( tk.tt > TT_SYMBOL_AFTER && tk.tt < TT_CONTROL_AFTER ) // symbol, definitely is
	{
		type = CN_SYMBOL;
	}
	else if ( tk.tt > TT_KEYWORD_AFTER && tk.tt < TT_SYMBOL_AFTER )
	{
		type = CN_KEYWORD;
	}

	pcall_name *rsl = new_pcall_name( type, tk.row, tk.col );

	if ( type == CN_FRONT_PART )
	{
		pfront_part *fp = parse_front_part( state );

		rsl->front_part = fp;
	}
	else
	{
		rsl->tt = tk.tt;

		// current token is not used now
		// fetch the next one
		pnext( );
	}

	return rsl;
}

// call_stmt ::= '(' call_name {front_part} ')'
// call stmt is the last choice of front part
BNN_FN pcall_stmt *parse_call_stmt( bnn_state *state )
{
	token tk = pcurr( );

	if ( tk.tt == TT_EOF )
	{
		return NULL;
	}

	if ( tk.tt != TT_LPARE )
	{
		berror( "[%s %zd:%zd] Expected '('", state->file_name, tk.row, tk.col );

		return NULL;
	}

	// skip the '('
	pnext( );

	pcall_name *cn = parse_call_name( state );

	/*if ( state->status == BAD_TRY )
	{
		state->err = ER_MISSING_WHAT_NQ;
		state->tk_buffer = ( token ){
			.row = tk.row,
			.col = tk.col,
			.val = ER_DESC_CALL_NAME, // "call name"
			.tt = TT_SIGN_END,
		};

		return NULL;
	}*/

	pcall_stmt *rsl = new_pcall_stmt( cn, tk.row, tk.col );
	make_list( pfront_part, rsl->front_parts, rsl->fp_idx, rsl->fp_len );

	if ( pcurr( ).tt == TT_RPARE )
	{
		pnext( );

		return rsl;
	}

	// read a lot of front parts
	pfront_part *fp;

	while ( fp = parse_front_part( state ) )
	{
		rsl->front_parts = add_to_pfront_part_list( rsl->front_parts,
													&rsl->fp_idx, &rsl->fp_len, fp );

		free( fp );

		tk = pcurr( );

		if ( tk.tt == TT_RPARE )
			break;
		else if ( tk.tt == TT_EOF )
		{
			berror( "[%s %zd:%zd] Expected ')'", state->file_name, tk.row, tk.col );
			return NULL;
		}
	}

	pnext( );

	return rsl;
}

// front_part ::= call_stmt | ANY_VALUE
BNN_FN pfront_part *parse_front_part( bnn_state *state )
{
	token tk = pcurr( );

	enum TOKEN_TYPE tt = tk.tt;

	pfront_part *rsl = new_pfront_part( FP_CALL_STMT, tk.row, tk.col );

	if ( tt == TT_NOT || tt == TT_SUB ) // TT_SUB means minus
	{
		pnext( );

		pfront_part *fp = parse_front_part( state );

		if ( fp == NULL )
		{
			berror( "[%s %zd:%zd] Expected front part", state->file_name, pcurr( ).row, pcurr( ).col );
			return NULL;
		}

		pcall_name *cn = new_pcall_name( CN_SYMBOL, tk.row, tk.col );

		cn->tt = tt;

		pcall_stmt *stmt = rsl->call_stmt = new_pcall_stmt( cn, tk.row, tk.col );

		stmt->front_parts = ( pfront_part * ) malloc( sizeof( pfront_part ) );
		check_null( stmt->front_parts );
		stmt->fp_idx = stmt->fp_len = 1;
		stmt->front_parts[ 0 ] = *fp;

		free( fp );

		rsl->call_stmt = stmt;

		return rsl;
	}
	// ANY_VALUE
	if ( ( tt > TT_START_HERE && tt < TT_EOF ) || ( tt >= TT_YES && tt <= TT_NULL_KW ) )
	{
		rsl->type = FP_ANY_VALUE;
		rsl->tk = tkval_to_pointer( &tk );

		// current token is not used now
		pnext( );
	}
	else if ( tt != TT_EOF ) // call_stmt
	{
		//if ( tt != TT_LPARE )
		//	return NULL;
		pcall_stmt *cs = parse_call_stmt( state );

		if ( cs == NULL )
		{
			berror( "[%s %zd:%zd] Unrecongized statement",
					state->file_name, pcurr( ).row, pcurr( ).col );
		}

		rsl->call_stmt = cs;
	}

	return rsl;
}

// special_oper :: = "|>" | "=>" | "==>"
BNN_FN int is_special_oper( bnn_state *state )
{
	int tt = pcurr( ).tt;

	if ( tt >= TT_PIPELINE && tt <= TT_EXPORT_LONG )
	{
		return tt;
	}

	return 0;
}

// optional_part ::= special_oper front_part
BNN_FN poptional_part *parse_optional_part( bnn_state *state )
{
	int type = is_special_oper( state );
	token tk = pcurr( );
	size_t row = tk.row, col = tk.col;

	if ( !type )
	{
		//ER_UNRECONGIZED_WHAT_ONE;
		/*state->tk_buffer = ( token ){
			.val = TT_SIGN_END + 3,
			.row = row,
			.col = col,
		};*/

		return NULL;
	}

	pnext( );

	pfront_part *fp = parse_front_part( state );
	tk = pcurr( );

	if ( fp == NULL )
	{
		berror( "[%s %zd:%zd] Missing front part", state->file_name, tk.row, tk.col );

		return NULL;
	}

	poptional_part *rsl = new_poptional_part( type - TT_PIPELINE, row, col );
	rsl->fp = fp;

	return rsl;
}

// statement ::= front_part {',' front_part} [optional_part]
BNN_FN pstatement *parse_statement( bnn_state *state )
{
	token tk = pcurr( );

	if ( tk.tt == TT_SEMI )
	{
		pnext( );

		return NULL;
	}

	pstatement *rsl = new_pstatement( tk.row, tk.col );
	make_list( pfront_part, rsl->front_parts, rsl->fp_idx, rsl->fp_len );

	pfront_part *fp;

	fp = parse_front_part( state );

	rsl->front_parts = add_to_pfront_part_list( rsl->front_parts,
												&rsl->fp_idx, &rsl->fp_len, fp );
	free( fp );

	for ( ;; )
	{
		tk = pcurr( );
		if ( tk.tt == TT_EOF )
		{
			return rsl;
		}
		else if ( tk.tt != TT_COMMA )
		{
			if ( is_special_oper( state ) )
			{
				break;
			}
			else
			{
				return rsl;
			}

			//berror( "[%s %zd:%zd] Expected is ','", state->file_name, tk.row, tk.col );

			return NULL;
		}
		pnext( );

		fp = parse_front_part( state );

		if ( fp == NULL )
			return NULL;

		/*if ( fp == NULL )
		{
			tk = pcurr( );
			state->status = BAD_TRY;
			state->err = ER_MISSING_WHAT_NQ;
			state->tk_buffer = ( token ){
				.val = TT_SIGN_END + 2,
				.row = tk.row,
				.col = tk.col,
			};

			free_pstatement( rsl, YES );
			return NULL;
		}*/

		rsl->front_parts = add_to_pfront_part_list( rsl->front_parts,
													&rsl->fp_idx, &rsl->fp_len, fp );
		free( fp );
	}

	make_list( poptional_part, rsl->optional_parts, rsl->op_idx, rsl->op_len );

	poptional_part *op;

	while ( op = parse_optional_part( state ) )
	{
		rsl->optional_parts = add_to_poptional_part_list( rsl->optional_parts,
														  &rsl->op_idx, &rsl->op_len, op );
		free( op );
	}

	return rsl;
}

/* BNN_FN void vm_stack_resize( vm_stack *stack, size_t len )
{
	BNN_CONST *temp = ( BNN_CONST * ) realloc( stack->storage, len * sizeof( BNN_CONST ) );
	check_null( temp );

	stack->storage = temp;
	stack->len = len;

	if ( stack->top >= ( int ) len )
		stack->top = len - 1;
}

BNN_FN vm_stack *new_vm_stack( size_t len )
{
	vm_stack *rsl = ( vm_stack * ) malloc( sizeof( vm_stack ) );
	check_null( rsl );

	rsl->top = EOS;
	rsl->storage = NULL;

	vm_stack_resize( rsl, len );

	return rsl;
}

BNN_FN void free_vm_stack( vm_stack *stack )
{
	if ( stack->storage )
		free( stack->storage );

	free( stack );
}

BNN_FN BNN_CONST vm_stack_peek( vm_stack *stack )
{
	if ( stack->top == EOS )
		berror( "[VM] Stack is empty" );

	return stack->storage[ stack->top ];
}

BNN_FN BNN_CONST vm_stack_pop( vm_stack *stack )
{
	if ( stack->top == EOS )
		berror( "[VM] Stack is empty" );

	BNN_CONST rsl = vm_stack_peek( stack );

	stack->top--;

	return rsl;
}

BNN_FN void vm_stack_push( vm_stack *stack, BNN_CONST val )
{
	if ( stack->top + 1 >= ( int ) stack->len )
		berror( "[VM] Stack overflowed" );

	stack->storage[ ++stack->top ] = val;
}*/


BNN_FN void inst_storage_expand( inst_storage *sto )
{
	size_t new_len = sto->storage == NULL
						 ? INST_MIN
						 : ( sto->len += INST_STEP );

	int_inst *temp = ( int_inst * ) realloc( sto->storage, new_len * sizeof( int_inst ) );
	check_null( temp );

	sto->storage = temp;
	sto->len = new_len;
}

//BNN_FN vm_func_storage *new_vm_func_storage( );
//BNN_FN void free_vm_func_storage( vm_func_storage *sto );

BNN_FN inst_storage *new_inst_storage( )
{
	inst_storage *rsl = ( inst_storage * ) malloc( sizeof( inst_storage ) );
	check_null( rsl );

	rsl->ip = rsl->write_idx = 0;
	rsl->storage = NULL;

	inst_storage_expand( rsl );

	//rsl->func_sto = new_vm_func_storage( );

	return rsl;
}

BNN_FN void free_inst_storage( inst_storage *sto )
{
	if ( sto->storage )
		free( sto->storage );

	//free_vm_func_storage( sto->func_sto );

	free( sto );
}

BNN_FN int_inst inst_storage_read( inst_storage *sto )
{
	if ( sto->ip < sto->len )
		return sto->storage[ sto->ip++ ];

	return 0;
}

BNN_FN inline BNN_CONST inst_storage_append( inst_storage *sto, int_inst inst )
{
	if ( sto->write_idx >= sto->len )
	{
		inst_storage_expand( sto );
	}

	sto->storage[ sto->write_idx ] = inst;

	return sto->write_idx++;
}


/* BNN_FN void vm_func_storage_resize( vm_func_storage *sto, size_t len )
{
	sto->len = len;

	vm_func *temp = ( vm_func * ) realloc( sto->sto, len * sizeof( vm_func ) );
	check_null( temp );

	sto->sto = temp;
}

BNN_FN vm_func_storage *new_vm_func_storage( )
{
	vm_func_storage *rsl = ( vm_func_storage * ) malloc( sizeof( vm_func_storage ) );
	check_null( rsl );

	rsl->sto = NULL;
	rsl->idx = 0;

	vm_func_storage_resize( rsl, STORAGE_DEFAULT );

	return rsl;
}

BNN_FN void free_vm_func_storage( vm_func_storage *sto )
{
	free( sto->sto );
	free( sto );
}

BNN_FN vm_func *vm_func_storage_get( vm_func_storage *sto, BNN_CONST idx )
{
	if ( idx >= sto->len )
		return NULL;

	return &sto->sto[ idx ];
}

BNN_FN BNN_CONST vm_func_storage_add( vm_func_storage *sto, vm_func func )
{
	if ( sto->idx >= sto->len )
	{
		sto->len += STORAGE_STEP;
		vm_func *temp = ( vm_func * ) realloc( sto->sto, sizeof( vm_func ) * sto->len );
		check_null( temp );
		sto->sto = temp;
	}

	sto->sto[ sto->idx ] = func;

	return sto->idx++;
}

BNN_FN vm_func new_vm_func( BNN_CONST args, BNN_CONST start )
{
	return ( vm_func ){
		.default_args = NULL,
		.args = args,
		.start = start
	};
}

BNN_FN void vm_func_set_arg( vm_func *func, BNN_CONST cnt, gen_var *list )
{
	if ( func->default_args == NULL )
	{
		func->default_args = ( gen_var * ) malloc( func->args * sizeof( gen_var ) );
		check_null( func->default_args );
	}

	memset( func->default_args, 0, func->args * sizeof( bnn_value ) );

	size_t i = 0;

	while ( cnt-- )
	{
		gen_var v = list[ i ];

		func->default_args[ i++ ] = v;
	}
}*/

bnn_vm *new_vm( bnn_state *state )
{
	bnn_vm *rsl = ( bnn_vm * ) malloc( sizeof( bnn_vm ) );
	check_null( rsl );

	str_table *tbl = rsl->glb_str_table = state->glb_str_table;
	//rsl->insts = new_inst_storage( );
	rsl->insts = state->opcodes;
	//rsl->stack_sto = new_vm_stack( STACK_STORAGE_MAX );

	rsl->const_sto = rsl->memory_sto = ( vm_storage ){ NULL, 0 };

	rsl->registers = ( bnn_value * ) calloc( REGISTER_STORAGE_AMOUNT, sizeof( bnn_value ) );
	check_null( rsl->registers );

	vm_storage *const_sto = &rsl->const_sto;
	size_t rlen = tbl->rlen;

	const size_t sto_len = const_sto->len = rlen - TT_SIGN_END - 1 + 3; // not include reserved words

	assert( ( int ) sto_len >= 3 );

	const_sto->sto = ( bnn_value * ) malloc( sizeof( bnn_value ) * sto_len );
	check_null( const_sto->sto );

	const_sto->sto[ YES_IDX ] = ( bnn_value ){
		.type = VALU_CONST,
		.val.const_val = YES,
	};

	const_sto->sto[ NO_IDX ] = ( bnn_value ){
		.type = VALU_CONST,
		.val.const_val = NO,
	};

	const_sto->sto[ NIL_IDX ] = ( bnn_value ){
		.type = VALU_CONST,
		.val.const_val = NIL,
	};

	for ( size_t i = TT_SIGN_END + 1; i < rlen; i++ )
	{
		char *str = str_table_get( tbl, i );

		enum VALU_TYPE type = *str == '$' ? VALU_NUMBER : VALU_STRING;

		bnn_value val = { type };

		if ( type == VALU_STRING )
		{
			val.val.string_val = i;
		}
		else
		{
			val.val.number_val = convert_num_to_str( str );
		}

		assert( i - TT_SIGN_END - 1 + 3 < sto_len ); // weird warning

		const_sto->sto[ i - TT_SIGN_END - 1 + 3 ] = val;
	}

	return rsl;
}

BNN_FN bnn_value *vm_load( vm_storage *sto, uint32_t idx )
{
	if ( idx < sto->len )
	{
		return &sto->sto[ idx ];
	}

	berror( "[VM] Out of range" );
	return NULL;
}

BNN_FN void vm_set( vm_storage *stog, uint32_t idx, bnn_value val )
{
	if ( idx >= stog->len )
	{
		if ( stog->len >= STORAGE_MAX )
		{
			berror( "[VM] Out of range" );
			return;
		}

		size_t new_len = ( stog->sto == NULL ? stog->len = STORAGE_DEFAULT : ( stog->len += STORAGE_STEP ) );
		bnn_value *temp = ( bnn_value * ) realloc(
			stog->sto,
			sizeof( bnn_value ) * new_len );
		check_null( temp );

		stog->sto = temp;
	}

	stog->sto[ idx ] = val;
}

#define VM_MATH( oper )                                                            \
	if ( regs[ A ].type != VALU_NUMBER || regs[ B ].type != VALU_NUMBER )          \
		berror( "[VM] Can't perform mathematic operations on non-number values" ); \
	regs[ C ] = ( bnn_value )                                                      \
	{                                                                              \
		.type = VALU_NUMBER,                                                       \
		.val.number_val = regs[ A ].val.number_val oper regs[ B ].val.number_val,  \
	}

#define VM_COMPARE( oper )                                                         \
	if ( regs[ A ].type != VALU_NUMBER || regs[ B ].type != VALU_NUMBER )          \
		berror( "[VM] Can't perform mathematic operations on non-number values" ); \
	regs[ C ] = ( bnn_value ){                                                     \
		.type = VALU_CONST,                                                        \
		.val.const_val = regs[ A ].val.number_val oper regs[ B ].val.number_val,   \
	};

BNN_FN BNN_CONST bnn_value_equal( bnn_value *l, bnn_value *r, enum VALUE_TYPE type )
{
	switch ( type )
	{
		case VALU_NUMBER:
			return l->val.number_val == r->val.number_val;
		case VALU_STRING:
			return l->val.string_val == r->val.string_val;
	}
	return l->val.const_val == r->val.const_val;
}

#define VM_EQ_OPER( oper )                                                           \
	{                                                                                \
		bnn_value l = regs[ A ], r = regs[ B ];                                      \
		BNN_CONST v = oper( l.type == r.type && bnn_value_equal( &l, &r, l.type ) ); \
		regs[ C ] = ( bnn_value ){                                                   \
			.type = VALU_CONST,                                                      \
			.val.const_val =                                                         \
				v,                                                                   \
		};                                                                           \
		break;                                                                       \
	}

BNN_FN BNN_CONST vm_is_true( bnn_value *v )
{
	if ( v->type == VALU_CONST )
	{
		return v->val.const_val == YES;
	}
	else if ( v->type == VALU_NUMBER )
	{
		return v->val.number_val == 1.;
	}
	else
	{
		return YES;
	}
}

BNN_FN inline bnn_inst vm_parse_inst( int_inst inst )
{
	unsigned typ = inst & INST_TYPE_BITS_SHIFT;

	switch ( typ )
	{
		case INST_RA:
			return ( bnn_inst ){
				.op = inst >> ( INST_TYPE_BITS + INTEGER_BITS ),
				.A = inst >> INST_TYPE_BITS & INTEGER_BITS_SHIFT,
			};
		case INST_RAB:
			return ( bnn_inst ){
				.op = inst >> ( INST_TYPE_BITS + REGISTER_BITS + REGISTER_BITS ),
				.A = ( inst >> ( INST_TYPE_BITS + REGISTER_BITS ) ) & REGISTER_BITS_SHIFT,
				.B = inst >> INST_TYPE_BITS & REGISTER_BITS_SHIFT,
			};
		case INST_RABC:
			return ( bnn_inst ){
				.op = inst >> ( INST_TYPE_BITS + REGISTER_BITS + REGISTER_BITS + REGISTER_BITS ),
				.A = ( inst >> ( INST_TYPE_BITS + REGISTER_BITS + REGISTER_BITS ) ) & REGISTER_BITS_SHIFT,
				.B = ( inst >> ( INST_TYPE_BITS + REGISTER_BITS ) ) & REGISTER_BITS_SHIFT,
				.C = inst >> INST_TYPE_BITS & REGISTER_BITS_SHIFT,
			};
		case INST_RAIB:
			return ( bnn_inst ){
				.op = inst >> ( INST_TYPE_BITS + REGISTER_BITS + INTEGER_BITS ),
				.A = ( inst >> ( INST_TYPE_BITS + INTEGER_BITS ) ) & REGISTER_BITS_SHIFT,
				.B = inst >> INST_TYPE_BITS & INTEGER_BITS_SHIFT,
			};
	}

	return ( bnn_inst ){ 0 };
}

BNN_FN void vm_step( bnn_vm *vm )
{
	int_inst cur = inst_storage_read( vm->insts );
	bnn_inst inst = vm_parse_inst( cur );

	enum OPCODE op = inst.op;
	uint32_t A = inst.A, B = inst.B, C = inst.C;

	//vm_stack *stk = vm->stack_sto;
	bnn_value *regs = vm->registers;

	vm_storage *mem = &vm->memory_sto, *cst = &vm->const_sto;

	switch ( op )
	{
		case OP_HALT:
			vm->insts->ip = vm->insts->len;
			break;
		/* case OP_PUSH:
			vm_stack_push( stk, A );
			break;
		case OP_PUSHR:
			vm_stack_push( stk, regs[ A ].val.const_val );
			break;
		case OP_POP:
			regs[ A ] = ( bnn_value ){
				.type = VALU_CONST,
				.val.const_val = vm_stack_pop( stk ),
			};
			break;
		case OP_DUP:
			vm_stack_push( stk, vm_stack_peek( stk ) );
			break;*/
		case OP_LOAD:
			regs[ A ] = *vm_load( mem, B );
			break;
		case OP_LOADC:
			regs[ A ] = *vm_load( cst, B );
			break;
		case OP_STORE:
			vm_set( mem, B, regs[ A ] );
			break;
		case OP_MOV:
			regs[ A ] = regs[ B ];
			break;
		case OP_ADD:
			VM_MATH( +);
			break;
		case OP_SUB:
			VM_MATH( -);
			break;
		case OP_MUL:
			VM_MATH( * );
			break;
		case OP_DIV:
			if ( regs[ B ].val.number_val == 0. )
				berror( "[VM] Can't divide with 0" );
			VM_MATH( / );
			break;
		case OP_EQ:
			VM_EQ_OPER( ( BNN_CONST ) );
			break;
		case OP_NEQ:
			VM_EQ_OPER( !);
			break;
		case OP_GE:
			VM_COMPARE( >= );
			break;
		case OP_GT:
			VM_COMPARE( > );
			break;
		case OP_LE:
			VM_COMPARE( <= );
			break;
		case OP_LT:
			VM_COMPARE( < );
			break;
		case OP_AND:
			VM_COMPARE( &&);
			break;
		case OP_OR:
			VM_COMPARE( || );
			break;
		case OP_NOT: {
			bnn_value a = regs[ A ];
			BNN_CONST v = NO;

			if ( a.type == VALU_CONST )
			{
				v = a.val.const_val == NIL ? YES : !a.val.const_val;
			}

			regs[ B ] = ( bnn_value ){
				.type = VALU_CONST,
				.val.const_val = v,
			};
			break;
		}
		case OP_INV: {
			regs[ B ].type = VALU_NUMBER;
			regs[ B ].val.number_val = -regs[ A ].val.number_val;
			break;
		}
		case OP_JMP:
			vm->insts->ip = B;
			break;
		case OP_JMPR:
			vm->insts->ip = regs[ A ].val.const_val;
			break;
		case OP_JMPT:
			if ( vm_is_true( &regs[ A ] ) )
				vm->insts->ip = B;
			break;
		case OP_JMPF:
			if ( !vm_is_true( &regs[ A ] ) )
				vm->insts->ip = B;
			break;
		case OP_CALL: {
			break;
		}
#if defined( _DEBUG ) || defined( BNN_SAFE_MODE )
		case OP_IN: {
			bnn_value *val = &regs[ A ];

			val->type = VALU_NUMBER;

			BNN_NUMBER num = 0.;
			printf( "> " );
			int ignore = scanf( "%lf", &num );

			val->val.number_val = num;

			ignore = getchar( );

			break;
		}
		case OP_OUT: {
			bnn_value val = regs[ A ];

			printf( "R[%u] : ", A );

			if ( val.type == VALU_NUMBER )
			{
				printf( "%f\n", val.val.number_val );
			}
			else if ( val.type == VALU_STRING )
			{
				printf( "%s\n", str_table_get( vm->glb_str_table, val.val.string_val ) + 1 );
			}
			else
			{
				printf( "%d\n", val.val.const_val );
			}
			break;
		}
#endif
	}
}

void vm_run( bnn_vm *vm )
{
	inst_storage *insts = vm->insts;

	while ( insts->ip < insts->write_idx )
	{
		vm_step( vm );
	}
}

void free_vm( bnn_vm *vm )
{
	free( vm->registers );
	//free_vm_stack( vm->stack_sto );

	free( vm->const_sto.sto );
	free( vm->memory_sto.sto );

	free( vm );
}

#define is_null_var( v )( v.identifier == 0 )

BNN_FN size_t sym_table_add( sym_table *tbl, enum VAR_TYPE type, gen_var v );

BNN_FN sym_table *new_sym_table( )
{
	sym_table *rsl = ( sym_table * ) malloc( sizeof( sym_table ) );
	check_null( rsl );

	sym_section *sections = ( sym_section * ) malloc(
		sizeof( sym_section ) * VAR_TYPE_AMOUNT );
	check_null( sections );

	rsl->sections = sections;

	for ( int i = 0; i < VAR_TYPE_AMOUNT; i++ )
	{
		gen_var *sto = ( gen_var * ) calloc( STORAGE_DEFAULT, sizeof( gen_var ) );
		check_null( sto );

		rsl->sections[ i ] = ( sym_section ){ 0, STORAGE_DEFAULT, sto };
	}

	// adding const: yes no nil
	for ( BNN_CONST i = 0; i < 3; i++ )
	{
		sym_table_add( rsl, VAR_CONST, ( gen_var ){
										   .identifier = TT_YES + i,
										   .idx = i,
									   } );
	}

	for ( BNN_CONST i = 0; i < R_RA; i++ )
	{
		sym_table_add( rsl, VAR_REGISTER, ( gen_var ){
											  .identifier = NAMELESS,
											  .idx = i,
										  } );
	}

	return rsl;
}

BNN_FN void sym_table_expand( sym_table *tbl, enum VAR_TYPE type )
{
	sym_section *section = &tbl->sections[ type ];

	section->len += SYM_TABLE_STEP;

	gen_var *sto = ( gen_var * ) realloc( section->sto, sizeof( gen_var ) * section->len );
	check_null( sto );
	// fill with NULL_VAR (0)
	memset( sto + ( section->len - SYM_TABLE_STEP - 1 ), 0, sizeof( gen_var ) * SYM_TABLE_STEP );

	section->sto = sto;
}

// return NULL if not found
BNN_FN gen_var *sym_table_get( sym_table *tbl, str_order id )
{
	for ( size_t i = 0; i < VAR_TYPE_AMOUNT; i++ )
	{
		for ( size_t j = 0; j < tbl->sections[ i ].len; j++ )
		{
			gen_var *rsl = &tbl->sections[ i ].sto[ j ];
			if ( rsl->identifier == id )
			{
				return rsl;
			}
		}
	}

	return NULL;
}

BNN_FN size_t sym_table_add( sym_table *tbl, enum VAR_TYPE type, gen_var v )
{
	v.type = type;

	sym_section *section = &tbl->sections[ type ];

	if ( section->idx + 1 > section->len )
	{
		sym_table_expand( tbl, type );
	}

	gen_var cur = section->sto[ section->idx ];

	if ( cur.identifier ) // has value
	{
		do
		{
			section->idx++;
			if ( section->idx >= section->len )
				sym_table_expand( tbl, type );

		} while ( is_null_var( section->sto[ section->idx ] ) );
	}

	section->sto[ section->idx++ ] = v;
	return v.idx;
}

BNN_FN void sym_table_remove( sym_table *tbl, enum VAR_TYPE type, size_t *arr, size_t len )
{
	sym_section *section = &tbl->sections[ type ];

	for ( size_t i = 0; i < len; i++ )
	{
		size_t idx = arr[ i ];

		tbl->sections[ type ].sto[ idx ] = NULL_VAR;
	}

	free( arr );
}


BNN_FN gen_var *sym_table_get_const( sym_table *tbl, size_t idx )
{
	sym_section section = tbl->sections[ VAR_CONST ];
	size_t len = section.idx;

	if ( idx < len )
	{
		gen_var *var = &section.sto[ idx ];

		if ( var->identifier == 0 )
		{
			var->identifier = NAMELESS;
			//var->pos = idx;
			var->idx = idx;
		}

		return var;
	}

	return NULL;
}

BNN_FN void free_sym_table( sym_table *tbl )
{
	for ( int i = 0; i < VAR_TYPE_AMOUNT; i++ )
	{
		free( tbl->sections[ i ].sto );
	}

	free( tbl->sections );

	free( tbl );
}

BNN_FN gen_field *new_gen_field( )
{
	gen_field *rsl = ( gen_field * ) malloc( sizeof( gen_field ) );
	check_null( rsl );

	rsl->locals = ( sym_section * ) malloc( sizeof( sym_section ) );

	sym_section *locals = rsl->locals;
	check_null( locals );

	locals->idx = 0;
	locals->len = STORAGE_DEFAULT;
	locals->sto = ( gen_var * ) malloc( sizeof( gen_var ) * STORAGE_DEFAULT );
	check_null( locals->sto );

	//rsl->local_fields.len = rsl->local_fields.idx = 0;
	//rsl->local_fields.sto = NULL;

	return rsl;
}

BNN_FN void gen_field_insert( gen_field *field, gen_var v )
{
	sym_section *locals = field->locals;

	if ( locals->idx >= locals->len )
	{
		locals->len++;
		gen_var *temp = ( gen_var * ) realloc( locals->sto, sizeof( gen_var ) * locals->len );
		check_null( temp );

		locals->sto = temp;
	}

	locals->sto[ locals->idx++ ] = v;
}

BNN_FN void free_gen_field( gen_field *field );

BNN_FN gen_field *field_stack_pop( field_stack *stack );

BNN_FN void gen_field_leave( gen_field *field, bnn_state *state )
{
	if ( state->fields->top == EOS )
		state->cur_field = GLOBAL_FIELD;
	else
		state->cur_field = field_stack_pop( state->fields );

	free_gen_field( field );
}

BNN_FN gen_var *gen_field_get( gen_field *field, str_order id )
{
	sym_section *section = field->locals;

	for ( size_t i = 0; i < section->idx; i++ )
	{
		gen_var *v = &section->sto[ i ];

		if ( v->identifier == id )
			return v;
	}

	return NULL;
}

BNN_FN gen_var *gen_field_alloc( gen_field *field )
{
	sym_section *section = field->locals;

	if ( section->idx >= section->len )
	{
		section->len += SYM_TABLE_STEP;
		gen_var *temp = ( gen_var * ) realloc( section->sto, sizeof( gen_var ) * section->len );
		check_null( temp );
		section->sto = temp;
	}

	size_t idx = section->idx;

	gen_var var = {
		.identifier = NAMELESS,
		.idx = idx,
		.type = VAR_LOCAL,
	};

	section->sto[ section->idx++ ] = var;

	return &section->sto[ idx ];
}

BNN_FN void free_gen_field( gen_field *field )
{
	free( field->locals->sto );
	free( field->locals );
	/*if ( field->local_fields.len > 0 )
	{
		size_t len = field->local_fields.len;
		gen_field **sto = field->local_fields.sto;

		for ( size_t i = 0; i < len; i++ )
		{
			free_gen_field( sto[ i ] );
		}
	}*/
	free( field );
}

BNN_FN void field_stack_resize( field_stack *stack, size_t len )
{
	gen_field **temp = ( gen_field ** ) realloc( stack->storage, len * sizeof( gen_field * ) );
	check_null( temp );

	stack->storage = temp;
	stack->len = len;

	if ( stack->top >= ( int ) len )
		stack->top = len - 1;
}

BNN_FN field_stack *new_field_stack( size_t len )
{
	field_stack *rsl = ( field_stack * ) malloc( sizeof( field_stack ) );
	check_null( rsl );

	rsl->top = EOS;
	rsl->storage = NULL;

	field_stack_resize( rsl, len );

	return rsl;
}

BNN_FN void free_field_stack( field_stack *stack )
{
	if ( stack->storage )
		free( stack->storage );

	free( stack );
}

BNN_FN gen_field *field_stack_peek( field_stack *stack )
{
	if ( stack->top == EOS )
		return NULL;

	return stack->storage[ stack->top ];
}

BNN_FN gen_field *field_stack_pop( field_stack *stack )
{
	if ( stack->top == EOS )
		return NULL;

	gen_field *rsl = field_stack_peek( stack );

	stack->top--;

	return rsl;
}

BNN_FN void field_stack_push( field_stack *stack, gen_field *val )
{
	if ( stack->top + 1 >= ( int ) stack->len )
	{
		berror( "[VM] Field stack overflowed" );
	}

	stack->storage[ ++stack->top ] = val;
}

BNN_FN gen_field *field_stack_fetch( bnn_state *state, field_stack *stack )
{
	return state->cur_field = field_stack_pop( stack );
}

#define ENTER_FIELD( f )  \
	state->cur_field = f; \
	field_stack_push( state->fields, f );

#define LEAVE_FIELD( f )              \
	field_stack_pop( state->fields ); \
	gen_field_leave( f, state );

BNN_FN gen_var *codegen_find_var( bnn_state *state, str_order id )
{
	gen_var *rsl = state->cur_field == GLOBAL_FIELD
					   ? sym_table_get( state->glb_sym_table, id )
					   : gen_field_get( state->cur_field, id );

	field_stack *stk = state->fields;

	if ( !rsl && stk->top != EOS )
	{
		size_t limit = ( size_t ) stk->top;
		for ( size_t i = 0; i <= limit; i++ )
		{
			if ( rsl = gen_field_get( stk->storage[ i ], id ) )
				break;
		}
	}

	if ( !rsl )
	{
		rsl = sym_table_get( state->glb_sym_table, id );
	}

	return rsl;
}

/*
	符号表分为三个部分
		常量
		内存（有标识符）
		寄存器（保留寄存器和寄存器变量）
	虚拟机内存分为四个部分
		常量
		内存（存储符号表中内存和作用域的局部变量）
		寄存器
		栈
	作用域存储局部变量
	全局作用域下的局部变量为全局变量
*/

BNN_FN gen_var *codegen_try_alloc( bnn_state *state, enum VAR_TYPE type, str_order id )
{
	gen_var *rsl = NULL;

	if ( type == VAR_LOCAL )
	{
		if ( state->cur_field == GLOBAL_FIELD )
			type = VAR_MEMORY;
		else
		{
			rsl = gen_field_alloc( state->cur_field );
			rsl->identifier = id;
			return rsl;
		}
	}

	sym_section *section = &state->glb_sym_table->sections[ type ];
	gen_var *sto = section->sto;

	size_t cur_idx = section->idx, len = section->len;

	for ( size_t i = 0; i < cur_idx; i++ )
	{
		gen_var *v = &section->sto[ i ];

		v->idx = i;

		if ( v->identifier == 0 )
		{
			rsl = v;
			rsl->identifier = id;
			return rsl;
		}
	}

	if ( cur_idx + 1 == len )
	{
		// sym_table is very long but vm isn't
		sym_table_expand( state->glb_sym_table, type );
	}

	// fetch the variable at cur_idx
	if ( is_null_var( sto[ cur_idx ] ) )
	{
		sto[ cur_idx ] = ( gen_var ){
			.identifier = NAMELESS,
			.idx = cur_idx,
			.type = type,
		};

		section->idx++;

		rsl = sto + cur_idx;
		rsl->identifier = id;
		return rsl;
	}

	return rsl;
}

// identifier
BNN_FN gen_var *codegen_get_l_val( bnn_state *state, const pfront_part *fp )
{
	if ( fp->type == FP_CALL_STMT )
	{
		berror( "[%s %zd:%zd] call_stmt is not a l-val", state->file_name, fp->row, fp->col );

		return NULL;
	}

	token *tk = fp->tk;
	enum TOKEN_TYPE tt = tk->tt;

	if ( tt != TT_IDENTIFIER )
	{
		berror( "[%s %zd:%zd] %s is not a l-val", state->file_name, tk->row, tk->col, reserved_words[ tt ] );

		return NULL;
	}

	return codegen_find_var( state, tk->val );
}

BNN_FN void codegen_call_stmt( bnn_state *state, pcall_stmt *stmt );

BNN_FN gen_var codegen_get_r_val( bnn_state *state, const pfront_part *fp )
{
	if ( fp == NULL )
	{
		return state->glb_sym_table->sections[ VAR_CONST ].sto[ NIL_IDX ];
	}

	if ( fp->type == FP_CALL_STMT )
	{
		codegen_call_stmt( state, fp->call_stmt );

		//return state->glb_sym_table->sections[ VAR_REGISTER ].sto[ R_VLBF ];
		return ( gen_var ){
			.type = VAR_REGISTER,
			.identifier = NAMELESS,
			.idx = R_VLBF,
		};
	}

	token *tk = fp->tk;
	enum TOKEN_TYPE tt = tk->tt;

	switch ( tt )
	{
		case TT_YES:
		case TT_NO:
		case TT_NULL_KW:
			return state->glb_sym_table->sections[ VAR_CONST ].sto[ tt - TT_YES ];
		case TT_IDENTIFIER: {
			gen_var *rsl = codegen_find_var( state, tk->val );
			return rsl == NULL
					   ? state->glb_sym_table->sections[ VAR_CONST ].sto[ NIL_IDX ]
					   : *rsl;
		}
		default:
			// string and number
			return ( gen_var ){
				.type = VAR_CONST,
				.identifier = NAMELESS,
				.idx = tk->val - TT_SIGN_END - 1 + 3,
			};
	}
}

BNN_FN void codegen_load( bnn_state *state, const gen_var *src )
{
	inst_storage *output = state->opcodes;
	BNN_CONST idx = src->idx;

	switch ( src->type )
	{
		case VAR_CONST:
			inst_storage_append( output, INST_RAIB_M( OP_LOADC, R_VLBF, idx ) );
			return;
		case VAR_LOCAL:
		case VAR_MEMORY:
			inst_storage_append( output, INST_RAIB_M( OP_LOAD, R_VLBF, idx ) );
			return;
		case VAR_REGISTER:
			inst_storage_append( output, INST_RAB_M( OP_MOV, R_VLBF, idx ) );
			return;
	}
}

BNN_FN void codegen_store( bnn_state *state, const gen_var *dest )
{
	inst_storage *output = state->opcodes;
	BNN_CONST idx = dest->idx;

	switch ( dest->type )
	{
		case VAR_LOCAL:
		case VAR_MEMORY:
			inst_storage_append( output, INST_RAIB_M( OP_STORE, R_VLBF, idx ) );
			return;
		case VAR_REGISTER:
			inst_storage_append( output, INST_RAB_M( OP_MOV, idx, R_VLBF ) );
			return;
			//case VAR_CONST:
			//	return;
	}
}

BNN_FN void codegen_assign( bnn_state *state, const pfront_part *left, const pfront_part *right, int alloc, enum VAR_TYPE type_if_alloc )
{
	gen_var *lv = codegen_get_l_val( state, left );

	if ( lv == NULL )
	{
		if ( alloc )
		{
			lv = codegen_try_alloc( state, type_if_alloc, left->tk->val );
		}
		else
		{
			berror( "[%s %zd:%zd] Variable need to be allocated", state->file_name, left->row, left->col );
			return;
		}
	}

	gen_var rv = codegen_get_r_val( state, right );

	if ( lv->type != rv.type || lv->idx != rv.idx )
	{
		codegen_load( state, &rv );
		codegen_store( state, lv );
	}
}

#define reach( n ) \
	if ( len < n ) \
		berror( "[%s %zd:%zd] Missing arguments", state->file_name, stmt->row, stmt->col );

// get r-values from front_parts
#define load_operand( n )                                             \
	gen_var operand_##n = codegen_get_r_val( state, &args[ n - 1 ] ); \
	if ( is_null_var( operand_##n ) )                                 \
	{                                                                 \
		return;                                                       \
	}

// allocate a register
#define alloc_local( n )                                                    \
	gen_var *local_##n;                                                     \
	if ( operand_##n.type == VAR_REGISTER && operand_##n.idx != R_VLBF ) \
	{                                                                       \
		local_##n = &operand_##n;                                           \
	}                                                                       \
	else                                                                    \
	{                                                                       \
		local_##n = codegen_try_alloc( state, VAR_REGISTER, NAMELESS );     \
		if ( !local_##n )                                                   \
		{                                                                   \
			berror( "[VM] Storage overflowed" );                            \
			return;                                                         \
		}                                                                   \
                                                                            \
		codegen_load( state, &operand_##n );                                \
		codegen_store( state, local_##n );                                  \
	}

#define gen_var_destroy( var, sym_tbl ) \
	var->identifier = NO;

// arithmetic or logic
#define gen_oper( op )                                                                  \
	{                                                                                   \
		reach( 2 );                                                                     \
                                                                                        \
		load_operand( 1 );                                                              \
		alloc_local( 1 );                                                               \
                                                                                        \
		load_operand( 2 );                                                              \
		alloc_local( 2 );                                                               \
                                                                                        \
		inst_storage_append( output, INST_RABC_M(                                       \
										 op, local_1->idx, local_2->idx, R_VLBF ) ); \
                                                                                        \
		if ( operand_1.type != VAR_REGISTER )                                           \
		{                                                                               \
			gen_var_destroy( local_1, sym_tbl );                                        \
		}                                                                               \
		if ( operand_2.type != VAR_REGISTER )                                           \
		{                                                                               \
			gen_var_destroy( local_2, sym_tbl );                                        \
		}                                                                               \
	}

#define gen_una_oper( op )                                             \
	{                                                                  \
		reach( 1 );                                                    \
                                                                       \
		load_operand( 1 );                                             \
		codegen_load( state, &operand_1 );                             \
                                                                       \
		inst_storage_append( output, INST_RAB_M(                       \
										 op, R_VLBF, R_VLBF ) ); \
	}

BNN_FN void codegen_block( bnn_state *state, const pfront_part *blk, size_t len )
{
	size_t row = blk->row, col = blk->col;

	gen_field *field = new_gen_field( );
	ENTER_FIELD( field );

	for ( size_t i = 0; i < len; i++ )
	{
		const pfront_part *fp = &blk[ i ];

		if ( fp->type == FP_CALL_STMT )
		{
			codegen_call_stmt( state, fp->call_stmt );
		}
	}

	LEAVE_FIELD( field );
}

#define codegen_block_arg( fp )                                               \
	pfront_part body_part_##idx = *( fp );                                    \
                                                                              \
	if ( body_part_##idx.type != FP_CALL_STMT )                               \
	{                                                                         \
		berror( "[%s %zd:%zd] Expected call stmt",                            \
				state->file_name, body_part_##idx.row, body_part_##idx.col ); \
		return;                                                               \
	}                                                                         \
                                                                              \
	pcall_stmt *body_stmt_##idx = body_part_##idx.call_stmt;                  \
                                                                              \
	codegen_block( state, body_stmt_##idx->front_parts, body_stmt_##idx->fp_idx );

BNN_FN void codegen_cond_loop( bnn_state *state, pfront_part *cond, pfront_part *body, enum OPCODE jmp_type )
{
	inst_storage *output = state->opcodes;

	sym_table *sym_tbl = state->glb_sym_table;

	BNN_CONST start_inst = inst_storage_append( output, 0 );
	BNN_CONST end_inst = inst_storage_append( output, 0 );

	BNN_CONST start_pos = output->write_idx;

	output->storage[ start_inst ] = INST_RA_M( OP_PUSH, start_pos );

	gen_var expr = codegen_get_r_val( state, cond );

	// if its not a expr
	if ( expr.type != VAR_REGISTER || expr.idx != R_VLBF )
	{
		codegen_load( state, &expr );
		expr = sym_tbl->sections[ VAR_REGISTER ].sto[ R_VLBF ];
	}

	BNN_CONST jmpf_inst = inst_storage_append( output, 0 );

	codegen_block_arg( body );

	inst_storage_append( output, INST_RAIB_M( OP_JMP, 0, start_pos ) );

	BNN_CONST end_pos = output->write_idx;

	inst_storage_append( output, INST_RA_M( OP_POP, R_GRB ) );
	inst_storage_append( output, INST_RA_M( OP_POP, R_GRB ) );

	output->storage[ end_inst ] = INST_RA_M( OP_PUSH, end_pos );
	output->storage[ jmpf_inst ] = INST_RAIB_M( jmp_type, R_VLBF, end_pos );
}

BNN_FN void codegen_call( bnn_state *state, pcall_stmt *stmt )
{
	pcall_name *call_name = stmt->call_name;

	if ( call_name->type != CN_FRONT_PART )
		return;

	pfront_part *args = stmt->front_parts;
	size_t len = stmt->fp_idx;
	size_t arg_len = len - 1;

	inst_storage *output = state->opcodes;

}

BNN_FN void codegen_call_stmt( bnn_state *state, pcall_stmt *stmt )
{
	pcall_name *call_name = stmt->call_name;

	pfront_part *args = stmt->front_parts;
	size_t len = stmt->fp_idx;

	inst_storage *output = state->opcodes;

	sym_table *sym_tbl = state->glb_sym_table;

	if ( call_name->type == CN_FRONT_PART )
	{
		codegen_call( state, stmt );

		return;
	}

	switch ( call_name->tt )
	{
		case TT_VAR:
			reach( 1 );

			codegen_assign( state, args, len == 1 ? NULL : ( args + 1 ), YES, VAR_MEMORY );

			return;
		case TT_LVAR:
			reach( 1 );

			codegen_assign( state, args, len == 1 ? NULL : ( args + 1 ), YES, VAR_LOCAL );

			return;
		case TT_RVAR:
			reach( 1 );

			codegen_assign( state, args, len == 1 ? NULL : ( args + 1 ), YES, VAR_REGISTER );

			return;
		case TT_IS:
			reach( 2 );

			codegen_assign( state, args, args + 1, NO, NO );

			return;
		/* case TT_FN : {
			reach( 1 );

			BNN_CONST jmp_idx = inst_storage_append( output, 0 );

			size_t arg_len = len - 1;
			
			vm_func func = new_vm_func( arg_len, jmp_idx );

			

			return;
		}*/
		case TT_WHILE_DO: {
			/*
			0 PUSH 2      START
			1 PUSH 10     END
			2 LOADC 4 0   EXPR
			3 LOADC 5 0
			4 LT 4 5 4
			5 JMPF 4 10
			6 OUT 4		  BODY
			7 JMP 2       REWIND
			8 POP         END
			9 POP
			10 HALT       

			end
			start
			*/
			reach( 2 );

			codegen_cond_loop( state, args, args + 1, OP_JMPF );

			return;
		}
		case TT_DO_WHILE: {
			//   BODY   + WHILE_DO(EXPR,   BODY)

			reach( 2 );

			codegen_block_arg( args + 1 );

			codegen_cond_loop( state, args, args + 1, OP_JMPF );

			return;
		}

		case TT_DO_UNTIL: {
			//   BODY   + WHILE_DO(!EXPR,  BODY)

			reach( 2 );

			codegen_block_arg( args + 1 );

			codegen_cond_loop( state, args, args + 1, OP_JMPT );

			return;
		}
		case TT_LEAVE: {
			if ( len > 1 )
			{
				gen_var rsl = codegen_get_r_val( state, args );
				codegen_load( state, &rsl );
			}

			inst_storage_append( output, INST_RA_M( OP_DUP, 0 ) );
			inst_storage_append( output, INST_RA_M( OP_POP, R_VLBF ) );
			inst_storage_append( output, INST_RAIB_M( OP_JMPR, R_VLBF, 0 ) );

			return;
		}
		case TT_CONTINUE:
			inst_storage_append( output, INST_RA_M( OP_POP, R_ADR ) );
			inst_storage_append( output, INST_RA_M( OP_DUP, 0 ) );
			inst_storage_append( output, INST_RA_M( OP_POP, R_VLBF ) );
			inst_storage_append( output, INST_RA_M( OP_PUSHR, R_ADR ) );
			inst_storage_append( output, INST_RAIB_M( OP_JMPR, R_VLBF, 0 ) );

			return;
		case TT_IF: {
			reach( 2 );

			gen_var expr = codegen_get_r_val( state, args );

			// if its not a expr
			if ( expr.type != VAR_REGISTER || expr.idx != R_VLBF )
			{
				codegen_load( state, &expr );
				expr = sym_tbl->sections[ VAR_REGISTER ].sto[ R_VLBF ];
			}

			size_t jmp_idx = output->write_idx;

			inst_storage_append( output, 0 );

			codegen_block_arg( args + 1 );

			output->storage[ jmp_idx ] =
				INST_RAIB_M( OP_JMPF, R_VLBF, ( len > 2 ? output->write_idx + 1 : output->write_idx ) );

			if ( len > 2 )
			{
				jmp_idx = output->write_idx;

				inst_storage_append( output, 0 );

				codegen_block_arg( args + 2 );

				output->storage[ jmp_idx ] =
					INST_RAIB_M( OP_JMP, 0, output->write_idx );
			}

			return;
		}
		case TT_DO:
			codegen_block( state, args, len );

			return;
		case TT_EQ:
		case TT_NEQ:
		case TT_GE:
		case TT_GT:
		case TT_LE:
		case TT_LT:
			gen_oper( ( call_name->tt - TT_EQ + OP_EQ ) );

			return;
		case TT_ADD:
			gen_oper( OP_ADD );

			return;
		case TT_SUB:
			if ( len == 1 )
			{
				gen_una_oper( OP_INV );
			}
			else
			{
				gen_oper( OP_SUB );
			}

			return;
		case TT_MUL:
			gen_oper( OP_MUL );

			return;
		case TT_DIV:
			gen_oper( OP_DIV );

			return;
		case TT_AND:
		case TT_OR:
			gen_oper( ( call_name->tt - TT_AND + OP_AND ) );

			return;
		case TT_NOT:
			gen_una_oper( OP_NOT );

			return;
#if defined( _DEBUG ) || defined( BNN_SAFE_MODE )
		case TT_IN:
			reach( 1 );

			gen_var *lv = codegen_get_l_val( state, args );

			inst_storage_append( output, INST_RA_M( OP_IN, R_VLBF ) );

			codegen_store( state, lv );

			return;
		case TT_OUT:
			reach( 1 );

			gen_var rv = codegen_get_r_val( state, args );
			codegen_load( state, &rv );

			inst_storage_append( output, INST_RA_M( OP_OUT, R_VLBF ) );

			return;
#endif
	}
}

BNN_FN void codegen_statement( bnn_state *state, pstatement *stmt )
{
	if ( stmt->optional_parts )
	{
		return;
	}

	pfront_part *fp_list = stmt->front_parts;
	size_t len = stmt->fp_idx;

	for ( size_t i = 0; i < len; i++ )
	{
		pfront_part fp = fp_list[ i ];

		if ( fp.type == FP_CALL_STMT )
			codegen_call_stmt( state, fp.call_stmt );
	}
}

BNN_FN void parse_and_gen( bnn_state *state )
{
	pstatement *stmt;

	while ( pcurr( ).tt != TT_EOF )
	{
		stmt = parse_statement( state );

		if ( stmt )
		{
			codegen_statement( state, stmt );

			free_pstatement( stmt, YES );
		}
	}
}

bnn_state *new_state( const char *source, const char *file_name )
{
	bnn_state *s = ( bnn_state * ) malloc( sizeof( bnn_state ) );

	check_null( s );

	s->glb_str_table = new_str_table( );
	s->lex = new_lexer( );

	lexer_set_input( s->lex, source, file_name );

	s->file_name = s->lex->file_name;

	str_table *tbl = s->glb_str_table;

	s->lex->str_table = tbl;

	for ( size_t i = 0; i <= TT_SIGN_END; i++ )
	{
		str_table_add( tbl, strclone( reserved_words[ i ] ) );
	}

	s->tk_buffer = TOKEN_NULL;

	s->cur_field = NULL;
	s->fields = new_field_stack( FIELD_STACK_MAX );
	s->opcodes = new_inst_storage( );
	s->glb_sym_table = new_sym_table( );

	return s;
}

void free_state( bnn_state *s )
{
	free_lexer( s->lex );
	free_str_table( s->glb_str_table );
	free( s->file_name );

	free_field_stack( s->fields );
	free_inst_storage( s->opcodes );
	free_sym_table( s->glb_sym_table );

	free( s );
}

BNN_FN char *bread_file( const char *file_name )
{
	FILE *f = fopen( file_name, "r" );

	if ( f )
	{
		fseek( f, 0, SEEK_END );
		size_t len = ( size_t ) ftell( f ) + 1;
		rewind( f );

		char *str = ( char * ) calloc( len, sizeof( char ) );
		if ( str == NULL )
			return 0;

		size_t cnt = 0;

		for ( ;; )
		{
			int c = fgetc( f );

			if ( c == EOF )
				break;

			str[ cnt++ ] = ( char ) c;
		}

		fclose( f );

		return str;
	}

	return NULL;
}

int main( )
{
	const char *fn = "test.bnn";

	bnn_state *state = new_state( bread_file( fn ), fn );

	parse_and_gen( state );

	bnn_vm *vm = new_vm( state );

	/*for ( size_t i = 0; i < state->glb_str_table->rlen; i++ )
	{
		printf( "%-15s %3u\n", str_table_get( state->glb_str_table, i ), i );
	}
	printf( "%u\n", state->glb_str_table->rlen );*/

	for ( size_t i = 0; i < vm->insts->write_idx; i++ )
	{
		int_inst cur = vm->insts->storage[ i ];

		bnn_inst inst = vm_parse_inst( cur );

		enum OPCODE op = inst.op;
		uint32_t A = inst.A, B = inst.B, C = inst.C;

		printf( "%-5s %-3u %-3u %-3u\n", opcode_strings[ op ], A, B, C );
	}

	vm_run( vm );

	free_vm( vm );
	free_state( state );

	int ignore = getchar( );

	return 0;
}
