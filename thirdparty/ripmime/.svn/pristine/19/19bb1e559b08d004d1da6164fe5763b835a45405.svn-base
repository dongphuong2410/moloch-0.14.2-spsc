#ifndef BS_H
#define BS_H

#define BS_STRLEN_MAX 1024

struct BS_object {
	int count;
	int smallest_length;
	int have_empty_boundary;
	struct BS_node *boundarystack;
	char boundarystacksafe[BS_STRLEN_MAX];
};

int BS_init( void );
int BS_object_init( struct BS_object *bo);
int BS_set_verbose( int level );
int BS_set_debug( int level );
int BS_set_boundary_detect_limit( int limit );
int BS_set_hold_limit( int limit );

int BS_clear( struct BS_object *bo );
int BS_push( struct BS_object *bo, char *boundary );
char *BS_pop( struct BS_object *bo );
char *BS_top( struct BS_object *bo );
int BS_cmp( struct BS_object *bo, char *boundary, int len );
int BS_count( struct BS_object *bo );
#endif
