#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include "blowfish.h"



char mode;
int max_threads;
int *thread_args;
long int input_file_length;
long int block_size;

FILE *input_file;
FILE *key_file;
FILE *output_file;

BLOWFISH_CTX *ctx;

pthread_mutex_t read_mutex;
pthread_mutex_t write_mutex;


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
			fread(&in_data, 8, 1, input_file);
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
			fwrite(&out_data, 8, 1, output_file);
			if(ferror(output_file))
			{
				perror("Writing error\n");
				exit(EXIT_FAILURE);
			}
		pthread_mutex_unlock(&write_mutex);
	}
	
	pthread_exit(NULL);
}



/**
 * @brief Usage: blowfish-multithread (e|d) input_filename key_filename output_filename max_threads
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
		perror("Usage: blowfish-multithread (e|d) input_filename key_filename output_filename max_threads\n");
		exit(EXIT_FAILURE);
	}
	
	if(argc != 6)
	{
		perror("Wrong number of arguments\n");
		exit(EXIT_FAILURE);
	}
	
	mode = argv[1][0];
	char *input_filename = argv[2];
	char *key_filename = argv[3];
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
	
	key_file = fopen(key_filename, "r");
	if(key_file == NULL)
	{
		perror("Problem opening the key file\n");
		exit(EXIT_FAILURE);
	}
	
	output_file = fopen(output_filename, "w+");	// Overwrite existing file
	if(output_file == NULL)
	{
		perror("Problem creating the output file\n");
		exit(EXIT_FAILURE);
	}
	
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Key reading
	///////////////////////////////////////////////////////////////////////
	
	int key_file_length = 0;
	
	fseek(key_file, 0L, SEEK_END);		// Go to file end
	key_file_length = ftell(key_file);	// Get the length
	rewind(key_file);					// Go back to the beginning
	
	if((key_file_length<4) || (key_file_length>56))
	{
		// Out of 32-448 bits range
		perror("Wrong key size (4-56 characters)\n");
		exit(EXIT_FAILURE);
	}
	
	char key[key_file_length];
	fscanf(key_file, "%s", key);
	
	Blowfish_Init(ctx, key, key_file_length);
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
	long int reminder_size = (block_size * max_threads) - input_file_length;
	long int reminder_size_alligned = reminder_size - (reminder_size%8);
	int padding_size = 8 - (reminder_size%8);
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Thread creation
	///////////////////////////////////////////////////////////////////////
	
	//pthread_t thread_pool[max_threads];
	pthread_t *thread_pool = (pthread_t *) malloc(max_threads * sizeof(pthread_t));
	thread_args = (int *) malloc(max_threads * sizeof(int));
	
	int i = 0;
	for(i = 0; i < max_threads; ++i)
	{
		thread_args[i] = i;
	}
	
	
	////////////////
	// Benchmark
		clock_t start = clock();
	////////////////
	//TODO: Move benchmark marker
	//TODO: implement it as a compile flag
	
	pthread_mutex_init(&read_mutex, NULL);
	pthread_mutex_init(&write_mutex, NULL);
	

	
	for(i = 0; i < max_threads; i++)
	{
		int result;
		//TODO: Start threads
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
	
	
	
	if(mode == 'e')
	{
		pthread_mutex_lock(&read_mutex);
			fseek(input_file, base_rem+i, SEEK_SET);
			fread(&in_data_rem, reminder_size-reminder_size_alligned, 1, input_file);
		pthread_mutex_unlock(&read_mutex);
		
		int j = 0;
		for(j = 0; j < padding_size; ++j)
		{
			in_data_rem = (in_data_rem<<8) || (uint8_t)padding_size;
		}
		
		out_data_rem = BlowfishEncryption(ctx, in_data_rem);
		
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
	else
	{
		unsigned int trim_len = out_data_rem & (uint64_t)0xFF;
		ftruncate(output_file, input_file_length-trim_len);
	}
	
	
	
	//TODO: join threads
	
	
	////////////////
	// Benchmark
		clock_t stop = clock();
		unsigned long milliseconds = (stop - start) * 1000 / CLOCKS_PER_SEC;
		printf("Elapsed time: %lu ms.\n\n", milliseconds);
	////////////////
	//TODO: Move benchmark marker
	
	
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Memory free
	///////////////////////////////////////////////////////////////////////
	
	for(i = 0; i < block_number; i++)
	{
// 		free(block_pool[i]);
// 		free(block_pool_binary[i]);
// 		free(output_pool_binary[i]);
	}
// 	free(block_pool);
// 	free(block_pool_binary);
// 	free(output_pool_binary);
// 	free(key_binary);
	free(thread_pool);	
// 	free(args_pool);
	
	fcloseall();	// Close all files
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// End
	///////////////////////////////////////////////////////////////////////
	
	exit(EXIT_SUCCESS);
}





