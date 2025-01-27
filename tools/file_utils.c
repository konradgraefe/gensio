
#include "gtlssh.h"

#ifdef _WIN32

#include <stdio.h>
#include <windows.h>
#include <aclapi.h>
#include <Lmcons.h>

static int
check_sid(const char *filename, const PSID osid, const PSID sid)
{
    if (!(EqualSid(sid, osid) ||
	  IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
	  IsWellKnownSid(sid, WinLocalSystemSid))) {
	fprintf(stderr, "%s is accessible by others, giving up\n",
		filename);
	return 1;
    }
    return 0;
}

static int
i_checkout_file(const char *filename, bool expect_dir, bool check_private,
		bool pr_on_no_file)
{
    DWORD attr;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION;
    PSID osid = NULL, psid = NULL;
    ACL *dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL, sd2 = NULL;
    DWORD err = 0;
    char errbuf[128];

    attr = GetFileAttributesA(filename);

    if (attr == INVALID_FILE_ATTRIBUTES) {
	if (pr_on_no_file) {
	    err = GetLastError();
	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  err, 0, errbuf, sizeof(errbuf), NULL);
	    fprintf(stderr, "Unable to examine %s: %s\n",
		    filename, errbuf);
	}
	goto out_err;
    }

    if (expect_dir) {
	if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	    fprintf(stderr, "%s is not a directory\n", filename);
	    goto out_err;
	}
    } else {
	if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) {
	    fprintf(stderr, "%s is not a regular file\n", filename);
	    goto out_err;
	}
    }

    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
			OWNER_SECURITY_INFORMATION, &psid,
			NULL, NULL, NULL, &sd2)) {
	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to get my process security info: %s\n",
		errbuf);
	goto out_err;
    }

    if (check_private)
	si |= DACL_SECURITY_INFORMATION;
    if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, si,
			      &osid, NULL, &dacl, NULL, &sd)) {
	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to get my security info for %s: %s\n",
		filename, errbuf);
	goto out_err;
    }

    if (!EqualSid(psid, osid)) {
	fprintf(stderr, "You do not own %s, giving up\n", filename);
	goto out_err;
    }

    if (check_private) {
	WORD i;

	for (i = 0; i < dacl->AceCount; i++) {
	    ACE_HEADER *a;

	    if (!GetAce(dacl, i, (void **) &a)) {
		err = GetLastError();
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			      err, 0, errbuf, sizeof(errbuf), NULL);
		fprintf(stderr, "Unable to get ACE %d for %s: %s\n",
			i, filename, errbuf);
		goto out_err;
	    }
	    switch (a->AceType) {
	    case ACCESS_ALLOWED_ACE_TYPE: {
		ACCESS_ALLOWED_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
		ACCESS_ALLOWED_CALLBACK_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
		ACCESS_ALLOWED_OBJECT_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: {
		ACCESS_ALLOWED_CALLBACK_OBJECT_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_DENIED_ACE_TYPE:
	    case ACCESS_DENIED_CALLBACK_ACE_TYPE:
	    case ACCESS_DENIED_OBJECT_ACE_TYPE:
	    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
		/* Denies are ok. */
		break;
	    default:
		fprintf(stderr, "%s is accessible by others, giving up\n",
			filename);
		goto out_err;
	    }
	}
    }

 out:
    if (sd)
	LocalFree(sd);
    if (sd2)
	LocalFree(sd2);
    return err;

 out_err:
    err = 1;
    goto out;
}

int
checkout_file(const char *filename, bool expect_dir, bool check_private)
{
    return i_checkout_file(filename, expect_dir, check_private, true);
}

bool
file_is_readable(const char *filename)
{
    PSID osid = NULL, psid = NULL;
    PSECURITY_DESCRIPTOR sd = NULL, sd2 = NULL;
    bool rv = false;

    /*
     * From what I can tell, if you are the owner you have read
     * access.  Nothing else matters.
     */
    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
			OWNER_SECURITY_INFORMATION, &psid,
			NULL, NULL, NULL, &sd2))
	goto out_false;

    if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT,
			      OWNER_SECURITY_INFORMATION,
			      &osid, NULL, NULL, NULL, &sd))
	goto out_false;

    if (!EqualSid(psid, osid))
	goto out_false;

    rv = true;
 out_false:
    if (sd)
	LocalFree(sd);
    if (sd2)
	LocalFree(sd2);
    return rv;
}

int
delete_file(const char *filename)
{
    return !DeleteFileA(filename);
}

int
move_file(const char *src, const char *dest)
{
    delete_file(dest);
    MoveFile(src, dest);
    return 0;
}

int
make_link(const char *link, const char *file, const char *name)
{
    DWORD err = 0;
    char errbuf[128];

    if (CreateHardLinkA(link, file, NULL) == 0) {
	err = GetLastError();
	if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS)
	    return LINK_EXISTS;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Error making link from %s to %s: %s\n", file, link,
		errbuf);
	return LINK_ERROR;
    }
    return 0;
}

void
make_dir(const char *dir, bool make_private)
{
    if (CreateDirectoryA(dir, NULL) == 0) {
	DWORD err = GetLastError();
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to create directory %s: %s\n", dir, errbuf);
	exit(1);
    }
}

bool
check_dir_exists(const char *dir, bool check_private)
{
    return !i_checkout_file(dir, true, check_private, false);
}

bool
check_file_exists(const char *filename)
{
    return file_is_readable(filename);
}

#else

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int
delete_file(const char *filename)
{
    return unlink(filename);
}

int
move_file(const char *src, const char *dest)
{
    unlink(dest);
    if (link(src, dest)) {
	fprintf(stderr, "Error making link (in move) from %s to %s: %s\n",
		src, dest, strerror(errno));
	return LINK_ERROR;
    }
    return 0;
}

int
make_link(const char *link, const char *file, const char *name)
{
    int err;

    err = symlink(name, link);
    if (!err)
	return 0;
    if (errno == EEXIST)
	return LINK_EXISTS;
    fprintf(stderr, "Error making link from %s to %s: %s\n", file, link,
	    strerror(errno));
    return LINK_ERROR;
}

void
make_dir(const char *dir, bool make_private)
{
    int rv;
    mode_t mode;

    if (make_private)
	mode = 0700;
    else
	mode = 0777;

    rv = mkdir(dir, mode);
    if (rv) {
	fprintf(stderr, "Unable to create directory %s: %s\n", dir,
		strerror(errno));
	exit(1);
    }
}

bool
check_dir_exists(const char *dir, bool check_private)
{
    struct stat sb;
    int rv;

    rv = stat(dir, &sb);
    if (rv == -1)
	return false;

    if (!S_ISDIR(sb.st_mode)) {
	fprintf(stderr, "%s is not a directory\n", dir);
	exit(1);
    }

    if (sb.st_uid != getuid()) {
	fprintf(stderr, "You do not own %s, giving up\n", dir);
	exit(1);
    }

    if (check_private && sb.st_mode & 077) {
	fprintf(stderr, "%s is accessible by others, giving up\n", dir);
	exit(1);
    }

    return true;
}

bool
check_file_exists(const char *file)
{
    struct stat sb;
    int rv;

    rv = stat(file, &sb);
    if (rv == -1)
	return false;

    return true;
}

int
checkout_file(const char *filename, bool expect_dir, bool check_private)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1) {
	fprintf(stderr, "Unable to examine %s: %s\n",
		filename, strerror(errno));
	return errno;
    }

    if (sb.st_uid != getuid()) {
	fprintf(stderr, "You do not own %s, giving up\n", filename);
	return EPERM;
    }

    if (check_private && sb.st_mode & 077) {
	fprintf(stderr, "%s is accessible by others, giving up\n", filename);
	return EPERM;
    }

    if (expect_dir) {
	if (!S_ISDIR(sb.st_mode)) {
	    fprintf(stderr, "%s is not a directory\n", filename);
	    return EINVAL;
	}
    } else {
	if (!S_ISREG(sb.st_mode)) {
	    fprintf(stderr, "%s is not a regular file\n", filename);
	    return EINVAL;
	}
    }

    return 0;
}

bool
file_is_readable(const char *filename)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1)
	return false;

    if (!S_ISREG(sb.st_mode))
	return false;

    if (sb.st_uid == getuid()) {
	if (sb.st_mode & 0400)
	    return true;
    }
    if (sb.st_gid == getgid()) {
	if (sb.st_mode & 0040)
	    return true;
    }
    if (sb.st_mode & 0004)
	return true;

    return false;
}

#endif
