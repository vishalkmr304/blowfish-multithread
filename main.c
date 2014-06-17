#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <time.h>
#include <string.h>	// for memset()
#include "blowfish.h"
#include "debug.h"

#define BENCHMARK



char mode;					//! Mode flag for Enc/Dec.
int max_threads;			//! Thread number to be used.
int *thread_args;			//! Threads argument array.
							//! Composed of one entry per thread in which the thread number is stored, the reference to the entry will be passed to the thread. Ex: {0,1,2,3,4,5,6,7} 
							
long int input_file_length;	//! Input file length in bytes.
long int block_size;		//! Block size in bytes.
							//! The input file is divided in blocks, one per thread, this is always a multiple of the Blowfish's block size (8 bytes), the remaining bytes will be handled by the main thread.
							
long int frame_number;		//! Number of frames per block.
							//! Each block is subdivided in frames which will be buffered in RAM to gain betteer performances.
							//! This is always a multiple of 8, so that the resulting frame size is aligned to the Blowfish's block size (8 bytes).
							
long int frame_size;		//! Frame size in bytes.
							//! This is always a multiple of 8.
							
const int frame_threshold = 2000000;	//! Maximum size of a frame.

FILE *input_file;	//! Input file descriptor.
FILE *output_file;	//! Output file descriptor.

BLOWFISH_CTX *ctx;	//! Context for the Blowfish algorithm generated using the provided key.

pthread_mutex_t read_mutex;		//! Mutex to protect frame reading
								//! There is the need of protection even if the frames are non-overlapping because the file cursor is only one and global, so the fseek() calls would interfere with each others.
								
pthread_mutex_t write_mutex;	//! Mutex to protect frame writing
								//! There is the need of protection even if the frames are non-overlapping because the file cursor is only one and global, so the fseek() calls would interfere with each others.


inline void compute_frame_parameters(void);
inline void compute_block_size(void);

/**
 * @brief Blowfish thread function
 * Each thread work on its own block, divided in frames. Frames are loaded in RAM one at a time, once loaded each frame is "(enc|dec)rypted" considering 64 bits per iteration (Blowfish's block size), then the frame is written out to the output file and the next frame is loaded.
 * 
 * @param args Thread number, which correspond also to block number.
 */
void *Blowfish_thread(void *args)
{
	int block_number = *((int *)args);			//! Block number on which the thread will work.
	long int base = block_size * block_number;	//! Base address of the block.
	long int offset = 0;						//! Frame offset within the block.
	int intra_frame_counter = 0;				//! Current Blowfish's block within the frame.
	
	uint64_t *buffer = (uint64_t *)calloc(frame_size, 1);	//! Buffer to temporary store the frame.
	if(buffer == NULL)
	{
		perror("Failed to allocate buffer, exiting");
		exit(EXIT_FAILURE);
	}
	
	for(offset = 0; offset<block_size; offset += frame_size)
	{
		///////////////////////////////////////////////
		// Read the frame and store it into the buffer
		///////////////////////////////////////////////
		pthread_mutex_lock(&read_mutex);
			fseek(input_file, base+offset, SEEK_SET);
			fread(buffer, frame_size, 1, input_file);
		pthread_mutex_unlock(&read_mutex);
		
		
		
		///////////////////////////////////////////////
		// Work on each Blowfish's block
		///////////////////////////////////////////////
		for(intra_frame_counter = 0; intra_frame_counter < (frame_size/sizeof(uint64_t)); ++intra_frame_counter)
		{
#ifdef DEBUG
			printf("Thread input: base=%d\toffset=%d\tintra_frame_counter=%d\tbuffer[%d]=%08llX\n", base, offset, intra_frame_counter, intra_frame_counter, buffer[intra_frame_counter]);
#endif
			if(mode == 'e')
			{
				buffer[intra_frame_counter] = BlowfishEncryption(ctx, buffer[intra_frame_counter]);
			}
			else
			{
				buffer[intra_frame_counter] = BlowfishDecryption(ctx, buffer[intra_frame_counter]);
			}
#ifdef DEBUG
			printf("Thread output: base=%d\toffset=%d\tintra_frame_counter=%d\tbuffer[%d]=%08llX\n", base, offset, intra_frame_counter, intra_frame_counter, buffer[intra_frame_counter]);
#endif
		}
		
		
		
		///////////////////////////////////////////////
		// Write out the frame
		///////////////////////////////////////////////
		pthread_mutex_lock(&write_mutex);
			fseek(output_file, base+offset, SEEK_SET);
			fwrite(buffer, frame_size, 1, output_file);
			if(ferror(output_file))
			{
				perror("Writing error\n");
				exit(EXIT_FAILURE);
			}
		pthread_mutex_unlock(&write_mutex);
	}
	
	buffer = (uint64_t *) memset(buffer, 0, frame_size);	// For security reasons overwrite memory before exiting
	free(buffer);
	pthread_exit(NULL);
}


#ifdef BENCHMARK
/**
 * @brief Perform the difference between two time instant expressed with the timespec structure.
 * 
 * @param timeA_p Time instant A.
 * @param timeB_p Time instant B.
 */
int64_t timespecDiff(struct timespec *timeA_p, struct timespec *timeB_p)
{
  return ((timeA_p->tv_sec * 1000000000) + timeA_p->tv_nsec) -
           ((timeB_p->tv_sec * 1000000000) + timeB_p->tv_nsec);
}
#endif


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
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);	// Start here to measure the execution time
#endif	
	
	
	///////////////////////////////////////////////////////////////////////
	// Key reading
	///////////////////////////////////////////////////////////////////////
	
	int key_length = strlen(key);
	
	if((key_length<4) || (key_length>56))
	{
		// Out of 32-448 bits range
		perror("Wrong key size (4-56 characters)\n");
		exit(EXIT_FAILURE);
	}
	
	ctx = (BLOWFISH_CTX *) malloc(sizeof(BLOWFISH_CTX));
	Blowfish_Init(ctx, key, key_length);	// Create Blowfish's context for the session.
	
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
	
	compute_block_size();
	
	long int reminder_size = input_file_length - (block_size * max_threads);	//! Reminder size in bytes, which in turn may be not multiple of 64 bits (8 bytes).
	long int reminder_size_aligned = reminder_size - (reminder_size%8);			//! Reminder size multiple of 64 bits, the remaining bytes will be padded.
	int padding_size = 8 - (reminder_size%8);									//! Padding size in bytes, if the reminder size is already aligned the padding will be 64 bits (added anyway) to be consistent with the protocol.
	
	compute_frame_parameters();
	
#ifdef DEBUG
		printf("Block subdivision: input_file_length=%d\tblock_size=%d\nreminder_size=%d\treminder_size_aligned=%d\tpadding_size=%d\n\n", input_file_length, block_size, reminder_size, reminder_size_aligned, padding_size);
#endif
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Thread creation
	///////////////////////////////////////////////////////////////////////
	
	pthread_t *thread_pool = (pthread_t *) malloc(max_threads * sizeof(pthread_t));	//! This array will contains all the threads that will be created.
	thread_args = (int *) malloc(max_threads * sizeof(int));
	pthread_mutex_init(&read_mutex, NULL);
	pthread_mutex_init(&write_mutex, NULL);
	
	int i = 0;
	for(i = 0; i < max_threads; ++i)
	{
		/**
		 * Initialize the threads arguments vector that will be used to pass the thread number to each thread (that is also the block number on which the thread will work)
		 * {0,1,2,3,4,5,6,7,...,max_threads-1}
		 */
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
	long int base_rem = block_size * max_threads;	//! Base address of the reminder.
	uint64_t in_data_rem = 0;						//! Blwowfish's block read from input file.
	uint64_t out_data_rem = 0;						//! Blwowfish's block written to output file.
	
	for(i = 0; i<reminder_size_aligned; i += 8)
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
		pthread_join(thread_pool[j], NULL);	// Wait all the thread to finish their work before proceeding.
	}
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Padding
	///////////////////////////////////////////////////////////////////////
	/**
	 * The padding is added to complete the last Blowfish's block and make it 8 bytes long.
	 * The convention is to pad with the number of remaining bytes to reach 8 so that while decrypting it is possible to distinguish the padding from the user data.
	 * For example: XXXXX333 or XXXX4444 or XXXXXX22
	 * If the reminder size is already multiple of 8 the padding will be added anyway and will be a block of 8s: 88888888.
	 * This is necessary to be consistent with the convention and be able to distinguish the padding from the user data and correctly decrypt the file.
	 * If we don't add this last block of 8s, while decrypting, we have no means to know if there is a padding or not, this means that the padding is always present, its minumum length is 1 and the maximum is 8.
	 * Given the last property of the protocol the decryption is easy, it is sufficient to read the very last byte to know the padding length (if the padding was allowed to be of zero length this would be not possible) and trim the file to the right length.
	 */
	if(mode == 'e')
	{
		fseek(input_file, base_rem+i, SEEK_SET);	// Go to the end of the aligned reminder
		fread(&in_data_rem, reminder_size-reminder_size_aligned, 1, input_file);	// Read the last bytes to be padded
		
#ifdef TRACE
		printf("Padding_enc: in_data_rem=%08llX\n", in_data_rem);
#endif
		
		for(j = reminder_size-reminder_size_aligned; j < 8; ++j)
		{
			in_data_rem = in_data_rem & ~( (uint64_t)(0xFF) << 8*j);	// Clear the bytes to be padded with a "walking zeros" mask: 0xFFFFFFFFFFFFFF00
#ifdef TRACE
			printf("Padding_enc: in_data_rem=%08llX\tj+1=%d\t~( (0xFF) << 8*j)=%08llX\n", in_data_rem, j+1, ~( (uint64_t)(0xFF) << 8*j));
#endif
		}
		
		for(j = reminder_size-reminder_size_aligned; j < 8; ++j)
		{
			in_data_rem = in_data_rem | ( ((uint64_t)padding_size) << 8*j);	// Write the padding
#ifdef TRACE
			printf("Padding_enc: in_data_rem=%08llX\tj+1=%d\t((uint64_t)padding_size) << 8*(j+1))=%08llX\n", in_data_rem, j+1, ((uint64_t)padding_size) << 8*(j+1));
#endif
		}
		
		out_data_rem = BlowfishEncryption(ctx, in_data_rem);	// Encrypt the last padded block
		
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
		// Last 8 bytes already decrypted  along with the padding which have to be trimmed, its length is written as padding data (at most 8 byte).
		fseek(output_file, input_file_length-1, SEEK_SET);
		fread(&out_data_rem, 1, 1, output_file);
		
		unsigned int trim_len = out_data_rem & (uint64_t)0xFF;	//! Number of bytes to be trimmed from the decrypted file to cut out the padding.
		fclose(output_file);	// The truncate() function work on closed files. (There is also the couterpart ftruncate() that take the open file descriptor, but during the test it failed)
		truncate(output_filename, input_file_length-trim_len);	// Trim the file to a specific length.
#ifdef DEBUG
		printf("Trimming: out_data_rem=%08lX\tinput_file_length-trim_len=%d\n", out_data_rem, input_file_length-trim_len);
#endif
	}
	
	
	
	
	
#ifdef BENCHMARK	
	clock_gettime(CLOCK_MONOTONIC, &end);	// Stop to measure the execution time.
	double timeElapsed = (double)timespecDiff(&end, &start);		// Compute the elapsed time.
	printf("Elapsed time: %f seconds.\n", timeElapsed/1000000000);	// Print the elapsed time.
#endif
	
	
	
	
	
	///////////////////////////////////////////////////////////////////////
	// Memory free
	///////////////////////////////////////////////////////////////////////
	
	free(thread_pool);
	free(thread_args);
	
	pthread_mutex_destroy(&read_mutex);
	pthread_mutex_destroy(&write_mutex);
	
	// For security reasons overwrite memory before exiting
	ctx = (BLOWFISH_CTX *) memset(ctx, 0, sizeof(BLOWFISH_CTX));
	in_data_rem = 0;
	out_data_rem = 0;
	input_file_length = 0;
	key_length = 0;
	block_size = 0;
	reminder_size = 0;
	reminder_size_aligned = 0;
	frame_number = 0;
	frame_size = 0;
	
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
	frame_number = 1;
	
	if(frame_size < frame_threshold)
	{
		return;	// Frame size already within the limit, no need to reduce it.
	}
	
	for(frame_number = 8; frame_size < frame_threshold; frame_number+=8)
	{
		frame_size = block_size / frame_number;	// Maintain frame_size multiple of 8 (block_size already is)
	}
}


/**
 * @brief Compute block size to distribute the load among threads
 */
inline void compute_block_size(void)
{
	block_size = input_file_length / max_threads;	// Distribute equally the load to the threads.
	if(0 != (block_size%8))
	{
		// Make the block size multiple of 64 bits, the main thread will take care of the reminder.
		block_size -= (block_size%8);
	}
}



