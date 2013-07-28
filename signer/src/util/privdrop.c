/*
 * $Id: privdrop.c 7039 2013-02-15 08:10:15Z matthijs $
 *
 * Copyright (c) 2009 Nominet UK. All rights reserved.
 *
 * Based heavily on uidswap.c from openssh-5.2p1
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 *
 * Privileges.
 */

#define _GNU_SOURCE /* defines for setres{g|u}id */

#include "config.h"
#include "util/log.h"
#include "util/privdrop.h"
#include "util/status.h"

#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#ifndef _SC_GETPW_R_SIZE_MAX
#define _SC_GETPW_R_SIZE_MAX 16384
#endif /* _SC_GETPW_R_SIZE_MAX */

#ifndef _SC_GETGR_R_SIZE_MAX
#define _SC_GETGR_R_SIZE_MAX 16384
#endif /* _SC_GETGR_R_SIZE_MAX */

static const char* logstr = "privdrop";


/**
 * Get the user identifier from the username.
 *
 */
uid_t
privuid(const char* username)
{
    struct passwd pwd;
    struct passwd* result;
    long bufsize;
    char* buf;
    uid_t uid;
    int s;
    uid = geteuid();
    if (username) {
        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 16384; /* should be more than enough */
        }
        buf = (char*) calloc(bufsize, sizeof(char));
        if (!buf) {
            ods_log_crit("[%s] calloc failed: insufficient memory", logstr);
            return -1;
        }
        /* Lookup the user id in /etc/passwd */
        s = getpwnam_r(username, &pwd, buf, bufsize, &result); /* leaks? */
        if (s) {
            ods_log_error("[%s] unable to get user id for %s: %s",
                logstr, username, strerror(s));
        }
        if (result != NULL) {
            uid = pwd.pw_uid;
        }
        free(buf);
    } else {
        uid = -1;
    }
    return uid;
}


/**
 * Get the group identifier from the group name.
 *
 */
gid_t
privgid(const char *groupname)
{
    struct group grp;
    struct group* result;
    long bufsize;
    char* buf;
    gid_t gid;
    int s;
    gid = getegid();
    if (groupname) {
        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 16384; /* should be more than enough */
        }
        buf = (char*) calloc(bufsize, sizeof(char));
        if (!buf) {
            ods_log_crit("[%s] calloc failed: insufficient memory", logstr);
            return -1;
        }
        /* Lookup the group id in /etc/group */
        s = getgrnam_r(groupname, &grp, buf, bufsize, &result); /* leaks? */
        if (s) {
            ods_log_error("[%s] unable to get group id for %s: %s",
                logstr, groupname, strerror(s));
        }
        if (result != NULL) {
            gid = grp.gr_gid;
        }
        free(buf);
    } else {
        gid = -1;
    }
    return gid;
}


/**
 * Drop privileges.
 *
 */
ods_status
privdrop(const char *username, const char *groupname, const char *newroot,
    uid_t* puid, gid_t* pgid)
{
    int status;
    uid_t uid, olduid;
    gid_t gid;
    long ngroups_max;
    gid_t *final_groups;
    int final_group_len = -1;
    /* Save effective uid/gid */
    uid = olduid = geteuid();
    gid = getegid();
    /* Check if we're going to drop uid */
    if (username) {
        uid = privuid(username);
        if (uid == (uid_t)-1) {
            ods_log_error("[%s] user %s does not exist", logstr, username);
            return ODS_STATUS_PRIVUIDERR;
        }
    }
    /* Check if we're going to drop gid */
    if (groupname) {
        gid = privgid(groupname);
        if (gid == (gid_t)-1) {
            ods_log_error("[%s] group %s does not exist", logstr, groupname);
            return ODS_STATUS_PRIVGIDERR;
        }
    }
    /* Change root if requested */
    if (newroot) {
#ifdef HAVE_CHROOT
       status = chroot(newroot);
       if (status != 0 || chdir("/") != 0) {
            ods_log_error("[%s] chroot to %s failed: %.100s", logstr,
                newroot, strerror(errno));
            return ODS_STATUS_CHROOTERR;
       }
#else
       ods_log_error("[%s] chroot to %s failed: !HAVE_CHROOT", logstr,
           newroot);
       return ODS_STATUS_CHROOTERR;
#endif /* HAVE_CHROOT */
    }
    /* Do additional groups first */
    if (username != NULL && !olduid) {
#ifdef HAVE_INITGROUPS
        if (initgroups(username, gid) < 0) {
            ods_log_error("[%s] initgroups failed: %s: %.100s", logstr,
                username, strerror(errno));
            return ODS_STATUS_INITGROUPSERR;
        }
#else
        ods_log_error("[%s] initgroups failed: %s: !HAVE_INITGROUPS", logstr,
            username);
        return ODS_STATUS_INITGROUPSERR;
#endif /* HAVE_INITGROUPS */

        ngroups_max = sysconf(_SC_NGROUPS_MAX) + 1;
        final_groups = (gid_t *)malloc(ngroups_max *sizeof(gid_t));
        if (!final_groups) {
            return ODS_STATUS_MALLOCERR;
        }
#if defined(HAVE_GETGROUPS) && defined(HAVE_SETGROUPS)
        final_group_len = getgroups(ngroups_max, final_groups);
        /* If we are root then drop all groups other than the final one */
        if (!olduid) {
            setgroups(final_group_len, final_groups);
        }
#endif /* defined(HAVE_GETGROUPS) && defined(HAVE_SETGROUPS) */
        free((void*)final_groups);
    }
    else {
        /* If we are root then drop all groups other than the final one */
#if defined(HAVE_SETGROUPS)
        if (!olduid) setgroups(1, &(gid));
#endif /* defined(HAVE_SETGROUPS) */
    }
    /* Drop gid? */
    if (groupname) {
#if defined(HAVE_SETRESGID) && !defined(BROKEN_SETRESGID)
        status = setresgid(gid, gid, gid);
#elif defined(HAVE_SETREGID) && !defined(BROKEN_SETREGID)
        status = setregid(gid, gid);
#else

# ifndef SETEUID_BREAKS_SETUID
        status = setegid(gid);
        if (status != 0) {
           ods_log_error("[%s] setegid() for %s (%lu) failed: %s",
               logstr, groupname, (unsigned long) gid, strerror(errno));
           return ODS_STATUS_SETEGIDERR;
        }
# endif  /* SETEUID_BREAKS_SETUID */

        status = setgid(gid);
#endif

        if (status != 0) {
           ods_log_error("[%s] setgid() for %s (%lu) failed: %s",
               logstr, groupname, (unsigned long) gid, strerror(errno));
           return ODS_STATUS_SETGIDERR;
        } else {
            ods_log_debug("[%s] group set to %s (%lu)", logstr,
                groupname, (unsigned long) gid);
        }
    }
    /* Drop uid? */
    if (username) {
        /* Set the user to drop to if specified; else just set the uid as the real one */
#if defined(HAVE_SETRESUID) && !defined(BROKEN_SETRESUID)
        status = setresuid(uid, uid, uid);
#elif defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
        status = setreuid(uid, uid);
#else

# ifndef SETEUID_BREAKS_SETUID
        status = seteuid(uid);
        if (status != 0) {
           ods_log_error("[%s] seteuid() for %s (%lu) failed: %s",
               logstr, username, (unsigned long) uid, strerror(errno));
           return ODS_STATUS_SETEUIDERR;
        }
# endif  /* SETEUID_BREAKS_SETUID */
        status = setuid(uid);
#endif
        if (status != 0) {
           ods_log_error("[%s] setuid() for %s (%lu) failed: %s",
               logstr, username, (unsigned long) uid, strerror(errno));
           return ODS_STATUS_SETUIDERR;
        } else {
            ods_log_debug("[%s] user set to %s (%lu)", logstr,
                username, (unsigned long) uid);
        }
    }
    *puid = uid;
    *pgid = gid;
    return ODS_STATUS_OK;
}


/**
 * Close privdrop.
 *
 */
void
privclose(const char* username, const char* groupname)
{
    if (username) {
        endpwent();
    }
    if (groupname) {
        endgrent();
    }
    return;
}
