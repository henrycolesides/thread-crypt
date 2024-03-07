// rchaney@pdx.edu

#ifndef _THREAD_CRYPT_H
# define _THREAD_CRYPT_H 1

# ifndef FALSE
#  define FALSE 0
# endif // FALSE
# ifndef TRUE
#  define TRUE 1
# endif // TRUE

# define SALT_CHARS "./ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"


# define OPTIONS "i:o:hva:l:R:t:r:p:"

# define ALGORITHMS "[01356byg]"

# define DEFAULT_SEED 3

# define DES_SALT_LEN 2
# define MIN_MD5_SALT_LEN 4
# define MAX_MD5_SALT_LEN 8

# define MIN_SHA_SALT_LEN 4
# define MAX_SHA_SALT_LEN 16

# define MIN_YES_SALT_LEN 4
# define MAX_YES_SALT_LEN 64

// all salts for bcrypt are 22 characters long
# define MAX_BCRYPT_SALT_LEN 22

# define SHA_ROUNDS_MIN 1000
# define SHA_ROUNDS_MAX 999999999
# define SHA_ROUNDS_DEFAULT 5000

# define BCRYPT_ROUNDS_MIN 4
# define BCRYPT_ROUNDS_MAX 31
# define BCRYPT_ROUNDS_DEFAULT 12

# define YESCRIPT_PARMS_DEFAULT "j9T"

#endif // _THREAD_CRYPT_H
