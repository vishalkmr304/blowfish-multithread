#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include "blowfish.h"





/**
 * @brief Usage: blowfish-multithread (e|d) input_filename key_filename output_filename max_threads
 * 
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return int
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
	
	char mode = argv[1][0];
	char *input_filename = argv[2];
	char *key_filename = argv[3];
	char *output_filename = argv[4];
	int max_threads = atoi(argv[5]);
	
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
	
	FILE *input_file;
	FILE *key_file;
	FILE *output_file;
	
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
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Block subdivision
	///////////////////////////////////////////////////////////////////////
	
	int block_number = 0;
	int input_file_length = 0;
	
	fseek(input_file, 0L, SEEK_END);		// Go to file end
	input_file_length = ftell(input_file);	// Get the length
	rewind(input_file);		// Go back to the beginning
	
	if(input_file_length < 1)
	{
		perror("Empty input file\n");
		exit(EXIT_FAILURE);
	}
	
	block_number = (int)(((float)input_file_length/8) + 0.9); // Cannot sum 1 because if input_file_length is divisible by 8 nothing have to be summed
	
	//uint8_t block_pool[block_number][8];
	uint8_t **block_pool = (uint8_t **) malloc(block_number * sizeof(uint8_t *));
	int i = 0;
	for(i = 0; i < block_number; i++)
	{
		block_pool[i] = (uint8_t *) malloc(8 * sizeof(uint8_t));
	}
	
	
	uint8_t temp = 0;
	
	for(i = 0; i < block_number; i++)
	{
		for(c = 0; (c < 8) && !feof(input_file); c++)
		{
			fread(&block_pool[i][c], 1, 1, input_file);
		}
	}
	
	if(feof(input_file))
	{
		c--;	// Remove the EOF
	}
	
	for(; c < 8; c++)
	{
		block_pool[block_number-1][c] = ' ';	// Padding
	}
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Thread creation
	///////////////////////////////////////////////////////////////////////
	
	//pthread_t thread_pool[block_number];
	pthread_t *thread_pool = (pthread_t *) malloc(block_number * sizeof(pthread_t));
	
	//Des_args args_pool[block_number];
	Des_args *args_pool = (Des_args *) malloc(block_number * sizeof(Des_args));
	
	//uint8_t output_pool_binary[block_number][64];
	uint8_t **output_pool_binary = (uint8_t **) malloc(block_number * sizeof(uint8_t *));
	for(i = 0; i < block_number; i++)
	{
		output_pool_binary[i] = (uint8_t *) malloc(64 * sizeof(uint8_t));
	}
	
	for(i = 0; i < block_number; i++)
	{
		args_pool[i].input = block_pool_binary[i];
		args_pool[i].key = key_binary;
		args_pool[i].output = output_pool_binary[i];
	}
	
	////////////////
	// Benchmark
		clock_t start = clock();
	////////////////
	
	pthread_mutex_init(&mutex, NULL);
	int temp_running_thread;
	running_thread = 0;
	
	for(i = 0; i < block_number; i++)
	{
		int result;
		if(mode == 'e')
		{
			pthread_mutex_lock(&mutex);
			running_thread++;
			pthread_mutex_unlock(&mutex);
			result = pthread_create(&thread_pool[i], NULL, DES_enc, (void *)(&args_pool[i]));
		}
		else
		{
			pthread_mutex_lock(&mutex);
			running_thread++;
			pthread_mutex_unlock(&mutex);
			result = pthread_create(&thread_pool[i], NULL, DES_dec, (void *)(&args_pool[i]));
		}
		
		if(result != 0)
		{
			perror("Thread creation error\n");
			exit(EXIT_FAILURE);
		}
		
		pthread_mutex_lock(&mutex);
		temp_running_thread = running_thread;
		pthread_mutex_unlock(&mutex);
		
		while(temp_running_thread >= max_threads)
		{
			pthread_mutex_lock(&mutex);
			temp_running_thread = running_thread;
			pthread_mutex_unlock(&mutex);
		}
	}
	
	while(temp_running_thread > 0)
	{
		pthread_mutex_lock(&mutex);
		temp_running_thread = running_thread;
		pthread_mutex_unlock(&mutex);
	}
	
	
	////////////////
	// Benchmark
		clock_t stop = clock();
		unsigned long milliseconds = (stop - start) * 1000 / CLOCKS_PER_SEC;
		printf("Elapsed time: %lu ms.\n\n", milliseconds);
	////////////////
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Output binary renconstruction
	///////////////////////////////////////////////////////////////////////
	
	uint8_t output_pool[block_number][8];
	
	for(i = 0; i < block_number; i++)
	{
		for(c = 0; c < 8; c++)
		{
			output_pool[i][c] = 0;
		}
	}
	
	for(i = 0; i < block_number; i++)
	{
		for(c = 0; c < 64; c++)
		{
			output_pool[i][c/8] |= ( output_pool_binary[i][c] << (7 - (c%8)) );
		}
	}
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Output file writing
	///////////////////////////////////////////////////////////////////////
	
	fwrite(output_pool, 8, block_number, output_file);
	//putc(EOF, output_file);
	
	//TODO: ferror() to check for writing errors
	
	///////////////////////////////////////////////////////////////////////
	// Memory free
	///////////////////////////////////////////////////////////////////////
	
	for(i = 0; i < block_number; i++)
	{
		free(block_pool[i]);
		free(block_pool_binary[i]);
		free(output_pool_binary[i]);
	}
	free(block_pool);
	free(block_pool_binary);
	free(output_pool_binary);
	free(key_binary);
	free(thread_pool);	
	free(args_pool);
	
	fcloseall();	// Close all files
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// End
	///////////////////////////////////////////////////////////////////////
	
	exit(EXIT_SUCCESS);
}





