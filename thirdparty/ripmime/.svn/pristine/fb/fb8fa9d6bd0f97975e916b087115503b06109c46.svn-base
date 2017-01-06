
struct RIPMIME_object
{
	char *mailpack;
	char *outputdir;
};

struct email_attach_file;

int RIPMIME_init(void);
int RIPMIME_decode( struct RIPMIME_object *rm, char *mailpack, char *outputdir );
int RIPMIME_IGL_decode(const char *path, struct email_attach_file **output);

