/* Private definitions for libsepol. */

/* Endian conversion for reading and writing binary policies */

#include <byteswap.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* Policy compatibility information. */
struct policydb_compat_info {
	int version;
	int sym_num;
	int ocon_num;
};

extern struct policydb_compat_info *policydb_lookup_compat(int version);
extern void __sepol_debug_printf(const char *fmt, ...);

/* Reading from a policy "file". */
static inline void *next_entry(struct policy_file * fp, size_t bytes)
{
	static unsigned char buffer[BUFSIZ];
	size_t nread;

	if (bytes > sizeof buffer)
		return NULL;

	switch (fp->type) {
	case PF_USE_STDIO:
		nread = fread(buffer, bytes, 1, fp->fp);
		if (nread != 1)
			return NULL;
		break;
	case PF_USE_MEMORY:
		if (bytes > fp->len) 
			return NULL;
		memcpy(buffer, fp->data, bytes);
		fp->data += bytes;
		fp->len -= bytes;
		break;
	default:
		return NULL;
	}
	return buffer;
}

extern int mls_enabled;
