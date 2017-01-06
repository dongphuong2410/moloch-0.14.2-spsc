// API for external programs wanting to use TNEF decoding
//
#ifndef __TNEF_API__
#define __TNEF_API__

#define TNEF_PATH_SIZE 1024

#include "config.h"

struct TNEF_object {
	int file_num;
	char path[ TNEF_PATH_SIZE +1];
	uint8 *tnef_home;
	uint8 *tnef_limit;
};

int TNEF_init( void );
int TNEF_object_init( struct TNEF_object *to);
int TNEF_main( struct TNEF_object *to, char *filename );
int TNEF_set_filename_report_fn( int (*ptr_to_fn)(char *, char *));
int TNEF_set_verbosity( int level );
int TNEF_set_verbosity_contenttype( int level );
int TNEF_set_debug( int level );
int TNEF_set_path( struct TNEF_object *to, char *path );
int TNEF_set_decode( int level );
#endif
