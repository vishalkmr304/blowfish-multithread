#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>	// for truncate()
#include <string.h>	// for memset()
#include "blowfish.h"
#include "debug.h"

#define BENCHMARK



char mode;
int max_threads;
int *thread_args;
long int input_file_length;
long int block_size;
int frame_number;
int frame_size;
const int frame_threshold = 700000;

FILE *input_file;
FILE *output_file;

BLOWFISH_CTX *ctx;

pthread_mutex_t read_mutex;
pthread_mutex_t write_mutex;


inline void compute_frame_parameters(void);

/**
 * @brief Blowfish thread function
 * 
 * @param args Block number
 */
void *Blowfish_thread(void *args)
{
	int block_number = *((int *)args);
	long int base = block_size * block_number;
	long int offset = 0;
	
	uint64_t in_data = 0;
	uint64_t out_data = 0;
	
	for(offset = 0; offset<block_size; offset += 8)
	{
		pthread_mutex_lock(&read_mutex);
			fseek(input_file, base+offset, SEEK_SET);
			fread(&in_data, 1, 8, input_file);
#ifdef DEBUG
			printf("Thread read: base=%d\toffset=%d\tin_data=%08llX\n", base, offset, in_data);
#endif
		pthread_mutex_unlock(&read_mutex);
		
		if(mode == 'e')
		{
			out_data = BlowfishEncryption(ctx, in_data);
		}
		else
		{
			out_data = BlowfishDecryption(ctx, in_data);
		}
		
		pthread_mutex_lock(&write_mutex);
			fseek(output_file, base+offset, SEEK_SET);
			fwrite(&out_data, 1, 8, output_file);
			if(ferror(output_file))
			{
				perror("Writing error\n");
				exit(EXIT_FAILURE);
			}
		pthread_mutex_unlock(&write_mutex);
	}
	
	in_data = 0;
	out_data = 0;
	pthread_exit(NULL);
}



/**
 * @brief Usage: blowfish-multithread (e|d) input_filename key output_filename max_threads
 * 
 * @param argc Argument count.
 * @param argv Argument vector.
 */
int main(int argc, char **argv) 
{
	
	///////////////////////////////////////////////////////////////////////
	// Preliminary setup
	///////////////////////////////////////////////////////////////////////
	
	if(argc == 1)
	{
		int q = 0;
		for(q = 0; q < argc; q++)
		{
			printf("%s",argv[q]);
			printf("\n");
		}
		perror("Usage: blowfish-multithread (e|d) input_filename key output_filename max_threads\n");
		exit(EXIT_FAILURE);
	}
	
	if(argc != 6)
	{
		perror("Wrong number of arguments\n");
		exit(EXIT_FAILURE);
	}
	
	mode = argv[1][0];
	char *input_filename = argv[2];
	char *key = argv[3];
	char *output_filename = argv[4];
	max_threads = atoi(argv[5]);
	
	if((mode != 'e')&&(mode != 'd'))
	{
		printf("%c\n",mode);
		perror("Wrong mode\n");
		exit(EXIT_FAILURE);
	}
	
	if(max_threads < 1)
	{
		perror("The number of threads must be greater than zero\n");
		exit(EXIT_FAILURE);
	}
	
	
	input_file = fopen(input_filename, "r");
	if(input_file == NULL)
	{
		perror("Problem opening the input file\n");
		exit(EXIT_FAILURE);
	}
	
	output_file = fopen(output_filename, "w+");	// Overwrite existing file
	if(output_file == NULL)
	{
		perror("Problem creating the output file\n");
		exit(EXIT_FAILURE);
	}
	

#ifdef BENCHMARK
	clock_t start = clock();
#endif	
	
	
	///////////////////////////////////////////////////////////////////////
	// Key reading
	///////////////////////////////////////////////////////////////////////
	
	int key_length = strlen(key);	// Go back to the beginning
	
	if((key_length<4) || (key_length>56))
	{
		// Out of 32-448 bits range
		perror("Wrong key size (4-56 characters)\n");
		exit(EXIT_FAILURE);
	}
	
	ctx = (BLOWFISH_CTX *) malloc(sizeof(BLOWFISH_CTX));
	Blowfish_Init(ctx, key, key_length);
	//TODO: Test if could be usefull perform this step in a separate thread
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Block subdivision
	///////////////////////////////////////////////////////////////////////
	
	input_file_length = 0;
	
	fseek(input_file, 0L, SEEK_END);		// Go to file end
	input_file_length = ftell(input_file);	// Get the length
	rewind(input_file);		// Go back to the beginning
	
	if(input_file_length < 8)
	{
		perror("Input file is too short\n");
		exit(EXIT_FAILURE);
	}
	
	block_size = input_file_length / max_threads;
	if(0 != (block_size%8))
	{
		// Make the block size multiple of 64 bits
		block_size -= (block_size%8);
	}
	long int reminder_size = input_file_length - (block_size * max_threads);
	long int reminder_size_alligned = reminder_size - (reminder_size%8);
	int padding_size = 8 - (reminder_size%8);
	
	compute_frame_parameters();
	
#ifdef DEBUG
		printf("Block subdivision: input_file_length=%d\tblock_size=%d\nreminder_size=%d\treminder_size_alligned=%d\tpadding_size=%d\n\n", input_file_length, block_size, reminder_size, reminder_size_alligned, padding_size);
#endif
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Thread creation
	///////////////////////////////////////////////////////////////////////
	
	//pthread_t thread_pool[max_threads];
	pthread_t *thread_pool = (pthread_t *) malloc(max_threads * sizeof(pthread_t));
	thread_args = (int *) malloc(max_threads * sizeof(int));
	pthread_mutex_init(&read_mutex, NULL);
	pthread_mutex_init(&write_mutex, NULL);
	
	int i = 0;
	for(i = 0; i < max_threads; ++i)
	{
		thread_args[i] = i;
	}
	
	for(i = 0; i < max_threads; i++)
	{
		int result;
		result = pthread_create(&thread_pool[i], NULL, Blowfish_thread, (void *)(&thread_args[i]));
		
		if(result != 0)
		{
			perror("Thread creation error\n");
			exit(EXIT_FAILURE);
		}
	}
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Reminder
	///////////////////////////////////////////////////////////////////////
	long int base_rem = block_size * max_threads;
	uint64_t in_data_rem = 0;
	uint64_t out_data_rem = 0;
	
	for(i = 0; i<reminder_size_alligned; i += 8)
	{
		pthread_mutex_lock(&read_mutex);
			fseek(input_file, base_rem+i, SEEK_SET);
			fread(&in_data_rem, 8, 1, input_file);
		pthread_mutex_unlock(&read_mutex);
		
		if(mode == 'e')
		{
			out_data_rem = BlowfishEncryption(ctx, in_data_rem);
		}
		else
		{
			out_data_rem = BlowfishDecryption(ctx, in_data_rem);
#ifdef TRACE
			printf("Reminder_dec: i=%d\tout_data_rem=%08llX\twrite at: %d\n", i, out_data_rem, base_rem+i);
#endif
		}
		
		pthread_mutex_lock(&write_mutex);
			fseek(output_file, base_rem+i, SEEK_SET);
			fwrite(&out_data_rem, 8, 1, output_file);
			if(ferror(output_file))
			{
				perror("Writing error\n");
				exit(EXIT_FAILURE);
			}
		pthread_mutex_unlock(&write_mutex);
	}
	
	
	///////////////////////////////////////////////////////////////////////
	// Threads Rendez-vous
	///////////////////////////////////////////////////////////////////////
	int j = 0;
	for(j = 0; j < max_threads; ++j)
	{
		pthread_join(thread_pool[j], NULL);
	}
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Padding
	///////////////////////////////////////////////////////////////////////
	if(mode == 'e')
	{
		fseek(input_file, base_rem+i, SEEK_SET);
		fread(&in_data_rem, reminder_size-reminder_size_alligned, 1, input_file);
		
#ifdef TRACE
		printf("Padding_enc: in_data_rem=%08llX\n", in_data_rem);
#endif
		
		for(j = reminder_size-reminder_size_alligned; j < 8; ++j)
		{
			in_data_rem = in_data_rem & ~( (uint64_t)(0xFF) << 8*j);
#ifdef TRACE
			printf("Padding_enc: in_data_rem=%08llX\tj+1=%d\t~( (0xFF) << 8*j)=%08llX\n", in_data_rem, j+1, ~( (uint64_t)(0xFF) << 8*j));
#endif
		}
		
		for(j = reminder_size-reminder_size_alligned; j < 8; ++j)
		{
			in_data_rem = in_data_rem | ( ((uint64_t)padding_size) << 8*j);
#ifdef TRACE
			printf("Padding_enc: in_data_rem=%08llX\tj+1=%d\t((uint64_t)padding_size) << 8*(j+1))=%08llX\n", in_data_rem, j+1, ((uint64_t)padding_size) << 8*(j+1));
#endif
		}
		
		out_data_rem = BlowfishEncryption(ctx, in_data_rem);
		
		fseek(output_file, base_rem+i, SEEK_SET);
		fwrite(&out_data_rem, 1, 8, output_file);
		if(ferror(output_file))
		{
			perror("Writing error\n");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		// Last 8 bytes already decrypted  along with the padding which have to be trimmed, its length is written as padding data (at most 8 byte)
		fseek(output_file, input_file_length-1, SEEK_SET);
		fread(&out_data_rem, 1, 1, output_file);
		
		unsigned int trim_len = out_data_rem & (uint64_t)0xFF;
		fclose(output_file);
		truncate(output_filename, input_file_length-trim_len);
#ifdef DEBUG
		printf("Trimming: out_data_rem=%08lX\tinput_file_length-trim_len=%d\n", out_data_rem, input_file_length-trim_len);
#endif
	}
	
	
	
	
	
#ifdef BENCHMARK
	clock_t stop = clock();
	unsigned long milliseconds = (stop - start) * 1000 / CLOCKS_PER_SEC;
	printf("Elapsed time: %lu ms.\n\n", milliseconds);
#endif
	
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Memory free
	///////////////////////////////////////////////////////////////////////
	
	free(thread_pool);
	free(thread_args);
	
	pthread_mutex_destroy(&read_mutex);
	pthread_mutex_destroy(&write_mutex);
	
	ctx = memset(ctx, 0, sizeof(BLOWFISH_CTX));
	in_data_rem = 0;
	out_data_rem = 0;
	input_file_length = 0;
	key_length = 0;
	block_size = 0;
	reminder_size = 0;
	reminder_size_alligned = 0;
	
	fcloseall();	// Close all files
	
	
	///////////////////////////////////////////////////////////////////////
	// End
	///////////////////////////////////////////////////////////////////////
	
	exit(EXIT_SUCCESS);
}


/**
 * @brief Compute optimal frame number and size
 */
inline void compute_frame_parameters(void)
{
	frame_size = block_size;
	frame_number = 0;
	for(frame_number = 1; frame_size < frame_threshold; ++i)
	{
		frame_size /= 8*frame_number;	// Maintain frame_size multiple of 8 (block_size already is)
	}
}


