#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<stdarg.h>
#include<errno.h>
#include <unistd.h>

char *LOCKDOWND_PATH="/usr/libexec/lockdownd";

typedef struct a_patch_ {
    unsigned long offset;
    unsigned char orig_byte;
    unsigned char new_byte;
} a_patch;

typedef struct os_fixes_ {
	  char *file_id;
    char major;
    char minor;
    char sub;
    unsigned long orig_crc;
    unsigned long new_crc;
    a_patch *patches;
} os_fixes;

a_patch lockdownd_112_patches[] =
{
            {0x4B3B, 0x1A, 0xEA},
            {0xC5C8, 0x04, 0x00},
            {0xC5CA, 0x00, 0xA0},
            {0xC5CB, 0x1A, 0xE1},
            {0xC5CC, 0x01, 0x00},
            {0xC5D4, 0x88, 0xEC},
            {0xFFFFFFFF, 0x00, 0x00}
};

a_patch lockdownd_111_patches[] =
{
    {0x0000482F, 0x1A, 0xEA},
    {0x0000B810, 0x04, 0x00},
    {0x0000B812, 0x00, 0xA0},
    {0x0000B813, 0x1A, 0xE1},
    {0x0000B814, 0x24, 0x54},
    {0x0000B818, 0x01, 0x00},
    {0xFFFFFFFF, 0x00, 0x00}
};

a_patch lockdownd_110_patches[] =
{
    {0x000094C4, 0x01, 0x00},
    {0x000094C7, 0x03, 0xE3},
    {0x000094C8, 0x3C, 0x68},
    {0x000094CB, 0x05, 0xE5},
    {0x000094D3, 0x0A, 0xEA},
    {0xFFFFFFFF, 0x00, 0x00}
};

os_fixes lockdownd_fixes[] =
{
    {
    	  "lockdownd",
        1,1,2,
        0x44FCC4E8,
        0x4CA880A2,
        lockdownd_112_patches
    },
    {
    	  "lockdownd",
        1,1,1,
        0x749267AE,
        0x3ECE8EFD,
        lockdownd_111_patches
    },
    {
    	  "lockdownd",
        1,1,0,
        0xBEEA7BE6,
        0x03440468,
        lockdownd_110_patches
    }
};

typedef unsigned long CRC32_t;
#define POLY 0xEDB88320
#define ALL1 0xFFFFFFFF

static CRC32_t *table = NULL;
unsigned long REPORTING_LEVEL = 0xFFFFFFFF;

void CRC32_Init(CRC32_t *value);
void CRC32_Update(CRC32_t *value, void *data, unsigned int size);
void CRC32_Final(unsigned char *out, CRC32_t value);
unsigned long get_file_crc(char *path);
int handle_patching(char *path, os_fixes *records, int num_records);
void inform(int level, char *fmt, ...);

void usage(char *path)
{
	  printf("iPatcher 0.0.0 by\t79b1caf2c95695e0af0e6216216eec54, kiwi66\n");
	  printf("\t\t\tBlaCkBirD, and b1llyb0y\n");
    printf("Usage: %s [options]\n",path);
    printf("Options:\n");
    printf("\t-l [file]\tpatch lockdownd at the path\n");
    printf("\t-v [level]\tset verbosity to level\n");
    printf("\t-a\t\tautomatically perform all patches\n");
    printf("\t-h\t\tprint this help\n");
}

int main(int argc, char *argv[])
{
  int ch;
  int do_lockdownd = 0;
  int do_makepatch = 0;
  char *new_path = NULL;
  char *orig_path = NULL;
  unsigned char *lockdownd_path = LOCKDOWND_PATH;
  int ret_check;
  
    while ((ch = getopt(argc, argv, "a:h?v:l:mn:o:")) != -1)
    {
            switch (ch) {
            case 'v':
            	  REPORTING_LEVEL = strtoul(optarg, NULL, 0);
                break;
            case 'l':
                do_lockdownd = 1;
                lockdownd_path = optarg;            	
                break;
            case 'a':
            	  do_lockdownd = 1;
            	  break;
            case 'm':
            	  do_makepatch = 1;
            	  break;
            case 'n':
            	  new_path = optarg;
            	  break;
            case 'o':
            	  orig_path = optarg;
            	  break;
            case 'h':
            case '?':
            default:
                    usage(argv[0]);
                    return(0);
            }
    }
    argc -= optind;
    argv += optind;
    if ( do_makepatch == 1 )
    {
    	  if ( new_path == NULL || orig_path == NULL )
    	  {
    	      inform(1, "[e] must supply an original and new file");
    	      return(0);
    	  }
    	  inform(1, "[i] generating patches\n");
	      ret_check = generate_patches(orig_path, new_path);
	      if ( ret_check == 1 )
	      {
	      	  inform(1, "[i] patch generation succeeded\n");
	      }
	      else
	      {
	      	  inform(1, "[i] patch generation failed\n");
	      }
	      return(0);
	  }
	  if ( do_lockdownd )
	  {
	      inform(1, "[i] Performing the lockdownd patch\n");
	      ret_check = handle_patching(lockdownd_path, lockdownd_fixes,
	                                  sizeof(lockdownd_fixes) / sizeof(os_fixes));
	      if ( ret_check == 1 )
	      {
	      	  inform(1, "[i] Lockdownd patch succeeded\n");
	      }
	      else
	      {
	      	  inform(1, "[i] Lockdownd patch failed\n");
	      }
	      
	  }
	  return(0);
}

void inform(int level, char *fmt, ...)
{
	if ( level <= REPORTING_LEVEL) {
    	va_list ap;
    	va_start(ap, fmt);
    	vprintf(fmt, ap);
    	va_end(ap);
    	if ( errno != 0 && level > 1)
    		perror("last system error");
  }
}

int generate_patches(char *orig_path, char *new_path)
{
	FILE *o_file;
	FILE *n_file;
	unsigned char o_byte;
	unsigned char n_byte;
  unsigned long offset;
  unsigned long o_crc;
  unsigned long n_crc;

	  o_file = fopen(orig_path, "rb");
	  if ( o_file == NULL )
	  {
	  	  inform(2, "[e] generate_patches->fopen(orig) failed on %s", orig_path);
	  	  return(0);
	  }
	  n_file = fopen(new_path, "rb");
	  if ( n_file == NULL )
	  {
	  	  inform(2, "[e] generate_patches->fopen(new) failed on %s", new_path);
	  	  return(0);
	  }
	  printf("a_patch new_patches[] =\n{\n");
	  while( (!feof(o_file)) && (!feof(n_file)) )
	  {
	  	  o_byte = fgetc(o_file);
	  	  n_byte = fgetc(n_file);
	  	  if ( o_byte != n_byte )
	  	  {
	  	  	  offset = ftell(o_file) - 1;
	  	  	  if ( offset == -1 )
	  	  	  {
	  	  	      inform(2,"[e] generate_patches->ftell failed");
	  	  	      return(0);
	  	  	  }
	  	      printf("    {0x%8.8X, 0x%2.2X, 0x%2.2X},\n", offset, o_byte, 
	  	             n_byte);
	  	  }
	  }
	  printf("    {0xFFFFFFFF, 0x00, 0x00}\n};\n");
	  fclose(o_file);
	  fclose(n_file);
    o_crc = get_file_crc(orig_path);
    n_crc = get_file_crc(new_path);
    printf("original crc: 0x%8.8X\n", o_crc);
    printf("new crc: 0x%8.8X\n", n_crc);
	  return(1);
	  
}

int handle_patching(char *path, os_fixes *records, int num_records)
{
	unsigned long orig_crc;
	unsigned long new_crc;
	a_patch *patches;
	os_fixes *a_fix;
	int cnt;
	int ret_val;
	
	  a_fix = records;
	  for(cnt = 0; cnt < num_records; cnt++)
	  {
      patches = a_fix->patches;
      orig_crc = get_file_crc(path);
      if ( orig_crc == a_fix->new_crc )
      {
          inform(2, "[i] found patched %d.%d.%d %s, no need to patch\n",
                 a_fix->major, a_fix->minor, a_fix->sub,a_fix->file_id);
          return(1);
      }
      if ( orig_crc == a_fix->orig_crc )
      {
          inform(2, "[i] found unpatched %d.%d.%d %s, patching\n", a_fix->major, 
                 a_fix->minor, a_fix->sub,a_fix->file_id);
          break;
      }
      a_fix++;
    }
    if ( cnt >= num_records )
    {
        inform(2, "[e] could not match file to a known signature\n");
        return(0);
    }
    ret_val = do_patches(path, patches);
    if ( ret_val == 0 )
    {
    	  inform(2, "[e] couldn't perform the patch\n");
    	  return(0);
    }
    new_crc =  get_file_crc(path);
    if ( new_crc != a_fix->new_crc )
    {
        inform(2, "[e] documented crc: %8.8X actual crc: %8.8X\n", a_fix->orig_crc, orig_crc);
        return(0);
    }
    inform(2, "[i] patch succeeded\n");
    return(1);
}

int do_patches(unsigned char *path, a_patch *patches)
{
	FILE *patch_file;
	a_patch *current_patch;
	unsigned char current_byte;
	int ret_val;
	
	  patch_file = fopen(path, "r+b");
	  if( patch_file == NULL )
	  {
	  	  inform(2,"[e] do_patches->fopen failure on %s\n", path);
	  	  return(0);
	  }
	  current_patch = patches;
	  while(current_patch->offset != 0xFFFFFFFF)
	  {
	      ret_val = fseek(patch_file, current_patch->offset, SEEK_SET);
	      if(ret_val != 0)
	      {
	      	  inform(2,"[e] do_patches->fseek failure\n");
	      	  fclose(patch_file);
	      	  return(0);
	      }
	      current_byte = fgetc(patch_file);
	      if(current_byte != current_patch->orig_byte)
	      {
	      	  inform(2,"[e] do_patches: original byte does not match\n");
	      	  fclose(patch_file);
	      	  return(0);
	      }
	      ret_val = fseek(patch_file, current_patch->offset, SEEK_SET);
	      if(ret_val != 0)
	      {
	      	  inform(2,"[e] do_patches->fseek failure\n");
	      	  fclose(patch_file);
	      	  return(0);
	      }
	      ret_val = fwrite(&current_patch->new_byte, 1, 1, patch_file);
        if (ret_val != 1 )
        {
	      	  inform(2,"[e] do_patches->fputc failure\n");
	      	  fclose(patch_file);
	      	  return(0);
        }
        current_patch++;
	  }
	  ret_val = fclose(patch_file);
	  if ( ret_val != 0 )
	  {
      	inform(2,"[e] do_patches->fclose failed\n");
	  }
	  return(1);
}

unsigned long get_file_crc(char *path)
{
	unsigned char inbuff[1024];
	FILE *in_file;
	CRC32_t crc32;
	unsigned long ret_val;
	int ret_check;
	
	  in_file = fopen(path, "rb");
	  if ( in_file == NULL )
	  {
	  	inform(2, "[e] get_file_crc->fopen failed on %s", path);
	  	return(0);
	  }
	  CRC32_Init(&crc32);
	  while(!feof(in_file))
	  {
	  	fread(inbuff, sizeof(unsigned char), sizeof(inbuff), in_file);
	  	CRC32_Update(&crc32, inbuff, sizeof(inbuff));
	  }
	  ret_check = fclose(in_file);
	  if ( ret_check != 0 )
	  {
      	inform(2, "[e] get_file_crc->fclose failed");
	  }
	  CRC32_Final((unsigned char *)&ret_val, crc32);
	  return(ret_val);
}

void CRC32_Init(CRC32_t *value)
{
	unsigned int index, bit;
	CRC32_t entry;

	*value = ALL1;

	if (table) return;
/* mem_alloc() doesn't return on failure.  If replacing this with plain
 * malloc(3), error checking would need to be added. */
	table = malloc(sizeof(*table) * 0x100);
	if ( table == NULL )
	{
		inform(1,"[e] CRC32_Init->malloc failed\n");
		exit(-1);
	}

	for (index = 0; index < 0x100; index++) {
		entry = index;

		for (bit = 0; bit < 8; bit++)
		if (entry & 1) {
			entry >>= 1;
			entry ^= POLY;
		} else
			entry >>= 1;

		table[index] = entry;
	}
}

void CRC32_Update(CRC32_t *value, void *data, unsigned int size)
{
	unsigned char *ptr;
	unsigned int count;
	CRC32_t result;

	result = *value;
	ptr = data;
	count = size;

	if (count)
	do {
		result = (result >> 8) ^ table[(result ^ *ptr++) & 0xFF];
	} while (--count);

	*value = result;
}

void CRC32_Final(unsigned char *out, CRC32_t value)
{
	value = ~value;
	out[0] = value;
	out[1] = value >> 8;
	out[2] = value >> 16;
	out[3] = value >> 24;
}
