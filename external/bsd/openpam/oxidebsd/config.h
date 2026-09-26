/*
 * OpenPAM's config.h for OxideBSD, written by hand in place of autoconf's:
 * build.rs compiles lib/libpam with musl into a static libpam.a.
 */

#define LIB_MAJ 2

/* No dlopen(3): modules are linked in, and found in openpam_static_modules[]. */
#define OPENPAM_STATIC_MODULES 1
#define OPENPAM_OXIDEBSD 1
#define OPENPAM_MODULES_DIR "/usr/lib/"
#define LOCALBASE "/usr/local"

/* What musl provides. */
#define HAVE_CRYPT_H 1
#define HAVE_ASPRINTF 1
#define HAVE_VASPRINTF 1
#define HAVE_STRLCAT 1
#define HAVE_STRLCPY 1
