// rchaney@pdx.edu
// Henry Sides, hsides@pdx.edu, CS333, Lab4

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <crypt.h>
#include <pthread.h>

#include "thread_crypt.h"

static int is_verbose = 0;
static FILE * op_file = NULL;
static char *ip_string = NULL;
static char *ip_string_alias = NULL;
// ...
// a plethora of global variables

static char *read_input_file(char *);
static char *get_next_word(void);
static void *hash_pass(void *);
// a couple more functions
// see below

int
main(int argc, char *argv[])
{
	char hash_algo;	
    char *ip_filename = NULL;
    char *op_filename = NULL;
	char crypt_rounds_str[20] = {'\0'};
	char *yescrypt_params = YESCRIPT_PARMS_DEFAULT;
    int num_threads = 1;
	int salt_len = 0;
    int result = 0;
	int crypt_rounds = SHA_ROUNDS_DEFAULT;
	unsigned int pseed = 3;	
	char output[100] = {'\0'};	


    {
        int opt = 0;
        
        while((opt = getopt(argc, argv, OPTIONS)) != -1) {
            switch(opt) {
            case 'i':
                if(is_verbose) {
                    fprintf(stderr, "input file: %s\n", optarg);
                }
                ip_filename = optarg;
                break;
            case 'o':
                if(is_verbose) {
                    fprintf(stderr, "output file: %s\n", optarg);
                }
                op_filename = optarg;
                break;
            case 't':
                num_threads = atoi(optarg);
                if ((num_threads < 1) || (num_threads > 20)) {
                    printf("invalid thread count %d\n", num_threads);
                    exit(1);
                }
                if(is_verbose) {
                    fprintf(stderr, "thread count: %d\n", num_threads);
                }
                break;
            case 'R':
                // store the seed
				pseed = atoi(optarg);

                //if (result != 1) {
                //    fprintf(stderr, "incorrect seed %s\n", optarg);
                //    exit(1);
                //}
                break;
            case 'a':
                // i stored the first letter so i could use in switch statements
                // ...
			
				hash_algo = optarg[0];

                if (is_verbose) {
                    fprintf(stderr, "hash_algo is %c\n", hash_algo);
                }
                // validate the hash algorithm
                switch (hash_algo) {
					case '0':
						break;
					case '1':
						break;
					case '3':
						break;
					case '5':
						break;
					case '6':
						break;
					case 'b':
						break;
					case 'y':
						break;
					case 'g':
						break;
                	default:
						fprintf(stderr, "invalid hashing algorithm: %s\n", optarg);
						exit(1);
						break;
                }
                break;
            case 'p':
                // the params for yescrypt and gost-yescrypt
                // ...
				yescrypt_params = optarg;

                if (is_verbose) {
                    fprintf(stderr, "yescript/gost-yescript params: %s\n"
                            , yescrypt_params);
                }
                break;
            case 'r':
                // rounds for sha* and bcrypt
                // ...
				crypt_rounds = atoi(optarg);
				//if(rounds < ) rounds = 1000;
				//if(rounds > 999999999) rounds = 999999999;
                break;
            case 'l':
				salt_len = atoi(optarg);
                break;
            case 'v':
                is_verbose++;
                break;
            case 'h':
                fprintf(stderr, "%s ...\n\tOptions: %s\n"
                        , argv[0], OPTIONS);
                fprintf(stderr, "\t-i file\t\tinput file name (required)\n");
                fprintf(stderr, "\t-o file\t\toutput file name (default stdout)\n");
                fprintf(stderr, "\t-a %s\talgorithm to use for hashing\n"
                        , ALGORITHMS);
                fprintf(stderr, "\t\t\tsee \'man 5 crypt\' for more information\n");
                fprintf(stderr, "\t\t\t0: DES - the default\n");
                fprintf(stderr, "\t\t\t1: md5\n");
                fprintf(stderr, "\t\t\t3: NT\n");
                fprintf(stderr, "\t\t\t5: SHA-256\n");
                fprintf(stderr, "\t\t\t6: SHA-512\n");
                fprintf(stderr, "\t\t\tb: bcrypt\n");
                fprintf(stderr, "\t\t\ty: yescrypt\n");
                fprintf(stderr, "\t\t\tg: gost-yescrypt\n");
                fprintf(stderr, "\t-l #\t\tlength of salt\n");
                fprintf(stderr, "\t\t\tvalid length depends on algorithm\n");
                fprintf(stderr, "\t-r #\t\trounds (SHA-256, SHA-512, bcrypt)\n");
                fprintf(stderr, "\t\t\tvalid rounds depends on algorithm\n");
                fprintf(stderr, "\t-p str\t\tparameters to use for"
                        " yescript or gost-yescript\n\t\t\t(default is \"%s\")\n"
                        , YESCRIPT_PARMS_DEFAULT);
                fprintf(stderr, "\t-R #\t\tseed for rand_r() (default %d)\n"
                        , DEFAULT_SEED);
                fprintf(stderr, "\t-t #\t\tnumber of threads to create (default 1)\n");
                fprintf(stderr, "\t-v\t\tenable verbose mode\n");
                fprintf(stderr, "\t-h\t\thelpful text\n");
                exit(EXIT_SUCCESS);
                break;
            default:
                fprintf(stderr, "oopsie - unrecognized command line option \"%s\"\n"
                        , argv[optind]);
                break;
            }
        }
    }
    if(op_filename != NULL) {
        // open the output file
       	op_file = fopen(op_filename, "w"); 
		if (op_file == NULL) {
            fprintf(stderr, "failed to open output file: %s\n", op_filename);
            exit(1);
        }
    }
    else {
        // WHAT!!!??? A global variable!!!??? These are hard to init
        op_file = stdout;
    }
    if(ip_filename == NULL) {
        fprintf(stderr, "must provide input file name\n");
        exit(EXIT_FAILURE);
    }

    // validate salt length
    switch (hash_algo) {
    case '0':
        salt_len = DES_SALT_LEN;
        break;
    case '1':
		if(salt_len > MAX_MD5_SALT_LEN) salt_len = MAX_MD5_SALT_LEN;
        // ...
        // think about MAX_MD5_SALT_LEN
        break;
    case '5':
    case '6':
		if(salt_len > MAX_SHA_SALT_LEN) salt_len = MAX_SHA_SALT_LEN;
		else if(salt_len < MIN_SHA_SALT_LEN) salt_len = MIN_SHA_SALT_LEN;
        break;
    case 'y':
    case 'g':
		if(salt_len > MAX_YES_SALT_LEN) salt_len = MAX_YES_SALT_LEN;
		else if(salt_len < MIN_YES_SALT_LEN) salt_len = MIN_YES_SALT_LEN;
        break;
    case 'b':
		salt_len = MAX_BCRYPT_SALT_LEN;
        break;
    case '3':
        salt_len = 0;
        break;
    default:
        break;
    }

    // take care of the rounds
    if ((hash_algo == '5') || (hash_algo == '6')) {		// SHA ROUNDS
		if(crypt_rounds > SHA_ROUNDS_MAX) crypt_rounds = SHA_ROUNDS_MAX;
		else if(crypt_rounds < SHA_ROUNDS_MIN) crypt_rounds = SHA_ROUNDS_MIN;
    }
    if (hash_algo == 'b') {								// BCRYPT ROUNDS
		if(crypt_rounds == SHA_ROUNDS_DEFAULT) crypt_rounds = BCRYPT_ROUNDS_DEFAULT;
		else if(crypt_rounds > BCRYPT_ROUNDS_MAX) crypt_rounds = BCRYPT_ROUNDS_MAX;
		else if(crypt_rounds < BCRYPT_ROUNDS_MIN) crypt_rounds = BCRYPT_ROUNDS_MIN;
    }

    // take care of the rounds string
    // i have a string that represnts the string used for rounds.
    // i want to generate it ONCE
    switch (hash_algo) {
    case '5':
    case '6':
       	sprintf(crypt_rounds_str, "rounds=%d", crypt_rounds);
        if (is_verbose) {
            fprintf(stderr, "Rounds = %d Rounds string %s\n", crypt_rounds
                    , (crypt_rounds_str ? crypt_rounds_str : "none"));
        }
        break;
    case 'y':
    case 'g':
		sprintf(crypt_rounds_str, "%s", yescrypt_params);
        if (is_verbose) {
            fprintf(stderr, "y/g = Params string %s\n"
                    , (crypt_rounds_str ? crypt_rounds_str : "none"));
        }
        break;
    case 'b':
       	sprintf(crypt_rounds_str, "rounds=%d", crypt_rounds);
        if (is_verbose) {
            fprintf(stderr, "bcrypt rounds %s\n", crypt_rounds_str);
        }
        break;
    default:
        break;
    }
    if (is_verbose) {
        fprintf(stderr, "Length of salt = %d\n", salt_len);
    }
	

	// Output test
	sprintf(output, "%c$%s$", hash_algo, crypt_rounds_str);
	fprintf(stderr, "\n%s\n\n", output);


    // read the input file as a big gulp
    // ...
	ip_string = read_input_file(ip_filename);
	ip_string_alias = ip_string;
	fprintf(stderr, "%s\n", ip_string);

	char * word = NULL;
	while((word = get_next_word()) != NULL) 
	{
		fprintf(stderr, "%s\n", word);
	}

    // allocate thread stuff
    // ...
    // ...
    
	// spin up the threads
    // ...
	
    if (is_verbose) {
        fprintf(stderr, "Threads spun up\n");
    }

    // spin down the threads
    if (is_verbose) {
        fprintf(stderr, "Threads joined\n");
    }
    // ...
    
    // show per thread hash count
    // ...

    // free allocated memory
    // ...
	free(ip_string_alias);
    if (op_filename != NULL) {
        fclose(op_file);
    }
    
    pthread_exit(EXIT_SUCCESS);
    //return EXIT_SUCCESS;
}

// big gulp
static char *
read_input_file(char *ip_filename)
{
    struct stat file_stat; // what would a stat structure do here?
    char *ip_string = NULL;
    int ipfd = -1;
    ssize_t bytes_read = 0;
	
	if(lstat(ip_filename, &file_stat) != 0)
	{
		perror("stat failed");
		exit(EXIT_SUCCESS);
	}

	ipfd = open(ip_filename, O_RDONLY);
	if(ipfd < 0) 
	{
		perror("open failed");
		exit(EXIT_SUCCESS);
	}
	
	ip_string = calloc(file_stat.st_size + 1, sizeof(char));
	bytes_read = read(ipfd, ip_string, file_stat.st_size * sizeof(char));
	if(ipfd) close(ipfd);
	// swallow the whole file in one swell foop
    
    return ip_string;
}

// step through the words
static char *
get_next_word(void)
{
    // teenage mutant ninja Texans
    // strtok() is a cool thing, with the right locks
    char *word = NULL;
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&lock);
	word = strsep(&ip_string, "\n");
	pthread_mutex_unlock(&lock);
  	
	if(word && strcmp(word, "\0") == 0) return NULL; 
	return word;
}

// done some actual work
static void *
hash_pass(void *arg)
{
    struct crypt_data crypt_stuff;

    memset(&crypt_stuff, 0, sizeof(crypt_stuff));

    // loop through all the words, using get_next_word()
    
    pthread_exit(EXIT_SUCCESS);
}

// generate the salt/settings for each word

	//	static void
	//	gen_salt(char *settings)
	//	{
	//		static const char salt_chars[] = {SALT_CHARS};
	//		static const size_t len = sizeof(salt_chars) - 1;
	//		int rand_value = 0;
	//		char hash_algo;
	//		// ...
    //
	//		switch(hash_algo)
	//		{
	//		case '1':
	//		case '5':
	//		case '6':
	//		case 'y':
	//		case 'g':
	//		case 'b':
	//			memset(salt, 0, CRYPT_OUTPUT_SIZE);
	//			// ...
	//			for(int i = 0; i < salt_len; ++i) {
	//				// ...
	//			}
	//			// ...
	//			break;
	//		case '3':
	//			// NT ALGORITHM
	//			// NO SALT
	//			sprintf(salt, "$%s$", hash_str);
	//			break;
	//		default:
	//			salt[0] = salt_chars[...];
	//			salt[1] = salt_chars[...];
	//			break;
	//		}
	//		if (is_verbose > 1) {
	//			fprintf(stderr, "salt %s\n", salt);
	//		}
	//	}
