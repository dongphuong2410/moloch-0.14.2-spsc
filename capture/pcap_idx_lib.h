#include <sys/stat.h>
#include <stdint.h>

#define MAX_INDEX_FILE_NUM 100000                             ///< 분석리스트 최대 갯수
#define MAX_DIR_LENGTH 256
#define START_POS_FILE "latest_start_pos"
#define END_POS_FILE "latest_end_pos"

struct process_file_inform_st {
	char *from_idx_file;
	long pos_of_file;
	uint32_t num_of_file;
	char *file_path;
	struct process_file_inform_st *next, *prev;
};

struct index_inform_st {
	/* parameter */
	char *idx_base_dir;
	char *idx_file_prefix;

	/* information */
	char *idx_file_path;
	FILE *idx_fd;
	struct stat idx_stat;
	uint32_t idx_num;
	long latest_pcap_path_pos;
	uint32_t latest_pcap_path_num;
	FILE *spos_fd;
	FILE *epos_fd;
	struct process_file_inform_st *process_file_list;
};

struct index_inform_st *init_pcap_index(char *base_dir, char *prefix_of_idx_file);
int exist_file_list(struct index_inform_st *idx);
struct process_file_inform_st *get_file_inform(struct index_inform_st *idx);
void write_start_pos(struct index_inform_st *idx, struct process_file_inform_st *file_inform);
void write_end_pos(struct index_inform_st *idx, struct process_file_inform_st *file_inform);
void delete_file_inform(struct index_inform_st *idx, struct process_file_inform_st *inform);
void get_next_pcap_list(struct index_inform_st *idx);
void free_pcap_index(struct index_inform_st *idx);
