/*
 * $Id: file.c 6747 2012-10-19 10:32:45Z matthijs $
 *
 * Copyright (c) 2013 NLNet Labs. All rights reserved.
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
 * File utilities.
 *
 */

#include "config.h"
#include "util/file.h"
#include "util/log.h"
#include "util/str.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* logstr = "file";


/**
 * Convert file mode to readable string.
 *
 */
static const char*
ods_file_mode2str(const char* mode)
{
    if (!mode) {
        return "no mode";
    }
    if (ods_strcmp(mode, "a") == 0) {
        return "appending";
    } else if (ods_strcmp(mode, "r") == 0) {
        return "reading";
    } else if (ods_strcmp(mode, "w") == 0) {
        return "writing";
    }
    return "unknown mode";
}


/**
 * Open a file.
 *
 */
FILE*
ods_fopen(const char* file, const char* dir, const char* mode)
{
    FILE* fd = NULL;
    size_t len_file = 0;
    size_t len_dir = 0;
    size_t len_total = 0;
    char* openf = NULL;
    const char* readmode = "r";
    ods_log_deeebug("[%s] open file %s%s file=%s mode=%s", logstr,
        (dir?"dir=":""), (dir?dir:""), (file?file:"(null)"),
        ods_file_mode2str(mode?mode:readmode));
    if (dir) {
        len_dir= strlen(dir);
    }
    if (file) {
        len_file= strlen(file);
    }
    len_total = len_dir + len_file;
    if (len_total > 0) {
        openf = (char*) malloc(sizeof(char)*(len_total + 1));
        if (!openf) {
            ods_log_error("[%s] malloc failed: insufficient memory", logstr);
            return NULL;
        }
        if (dir) {
           (void)strncpy(openf, dir, len_dir);
           openf[len_dir] = '\0';
           if (file) {
               (void)strncat(openf, file, len_file);
           }
        } else if (file) {
           (void)strncpy(openf, file, len_file);
        }
        openf[len_total] = '\0';
        if (len_file) {
            fd = fopen(openf, mode?mode:readmode);
            if (!fd) {
                ods_log_debug("[%s] fopen %s for %s failed: %s", logstr,
                    openf?openf:"(null)", ods_file_mode2str(mode?mode:readmode),
                    strerror(errno));
            }
        }
        free(openf);
    }
    return fd;
}


/**
 * Close a file.
 *
 */
void
ods_fclose(FILE* fd)
{
    if (fd) {
        fclose(fd);
    }
    return;
}


/**
 * Get next character from file.
 *
 */
int ods_fgetc(FILE* fd, unsigned int* l)
{
    int c;
    ods_log_assert(fd);
    ods_log_assert(l);
    c = fgetc(fd);
    if (c == '\n') {
        (*l)++;
    }
    if (c == EOF && errno != 0) {
        ods_log_crit("[%s] fgetc() failed: %s", logstr, strerror(errno));
    }
    return c;
}


/**
 * Read one line from file.
 *
 */
int
ods_freadline(FILE* fd, char* line, unsigned int* l, int keep_comments)
{
    int i = 0;
    int li = 0;
    int in_string = 0;
    int depth = 0;
    int comments = 0;
    char c = 0;
    char lc = 0;
    for (i = 0; i < AD_FILE_MAXLINE; i++) {
        c = (char) ods_fgetc(fd, l);
        if (comments) {
            while (c != EOF && c != '\n') {
                c = (char) ods_fgetc(fd, l);
            }
        }
        if (c == EOF) {
            if (depth != 0) {
                ods_log_error("[%s] bracket mismatch discovered at line %i, "
                    "missing ')'", logstr, l&&*l?*l:0);
            }
            if (li > 0) {
                line[li] = '\0';
                return li;
            } else {
                return -1;
            }
        } else if (c == '"' && lc != '\\') {
            in_string = 1 - in_string; /* swap status */
            line[li] = c;
            li++;
        } else if (c == '(') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\') {
                depth++;
                line[li] = ' ';
                li++;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == ')') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\') {
                if (depth < 1) {
                    ods_log_error("[%s] bracket mismatch discovered at line "
                        "%i, missing '('", logstr, l&&*l?*l:0);
                    line[li] = '\0';
                    return li;
                }
                depth--;
                line[li] = ' ';
                li++;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == ';') {
            if (in_string) {
                line[li] = c;
                li++;
            } else if (lc != '\\' && !keep_comments) {
                comments = 1;
            } else {
                line[li] = c;
                li++;
            }
        } else if (c == '\n' && lc != '\\') {
            comments = 0;
            /* if no depth issue, we are done */
            if (depth == 0) {
                break;
            }
            line[li] = ' ';
            li++;
        } else if (c == '\t' && lc != '\\') {
            line[li] = ' ';
            li++;
        } else {
            line[li] = c;
            li++;
        }
        /* continue with line */
        lc = c;
    }
    /* done */
    if (depth != 0) {
        ods_log_error("[%s] bracket mismatch discovered at line %i, "
            "missing ')'", logstr, l&&*l?*l:0);
        return li;
    }
    line[li] = '\0';
    return li;
}



/**
 * Write to file descriptor.
 *
 */
ssize_t
ods_writen(int fd, const void* vptr, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char* ptr;
    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR) {
                nwritten = 0; /* and call write again */
            } else {
                return -1; /* error */
            }
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return n;
}


/**
 * Get directory part of filename.
 *
 */
char*
ods_dir_name(const char* file) {
    int l;
    char* dir = NULL;
    if (!file) {
        return NULL;
    }
    l = strlen(file);
    /* find seperator */
    while (l>0 && strncmp(file + (l-1), "/", 1) != 0) {
        l--;
    }
    /* now strip off (multiple seperators) */
    while (l>0 && strncmp(file + (l-1), "/", 1) == 0) {
        l--;
    }
    if (l) {
        dir = (char*) calloc(l+1, sizeof(char));
        if (dir) {
            dir = strncpy(dir, file, l);
        }
        return dir;
    }
    return NULL;
}


/**
 * (Create) and change ownership of directories
 *
 */
void
ods_chown(const char* file, uid_t uid, gid_t gid, int getdir)
{
    char* dir = NULL;
    if (!file) {
        ods_log_warning("[%s] no filename given for chown()", logstr);
        return;
    }
    if (!getdir) {
        ods_log_debug("[%s] create and chown %s with user=%ld group=%ld",
           logstr, file, (signed long) uid, (signed long) gid);
        if (chown(file, uid, gid) != 0) {
            ods_log_error("[%s] chown() %s failed: %s", logstr, file,
                strerror(errno));
        }
    } else if ((dir = ods_dir_name(file)) != NULL) {
        ods_log_debug("[%s] create and chown %s with user=%ld group=%ld",
            logstr, dir, (signed long) uid, (signed long) gid);
        if (chown(dir, uid, gid) != 0) {
            ods_log_error("[%s] chown() %s failed: %s", logstr,
                dir, strerror(errno));
        }
        free(dir);
    } else {
        ods_log_warning("[%s] use of relative path: %s", logstr, file);
    }
    return;
}


/**
 * Get file status.
 *
 */
time_t
ods_fstat(const char* file)
{
    int ret;
    struct stat buf;
    FILE* fd;
    ods_log_assert(file);
    if ((fd = ods_fopen(file, NULL, "r")) != NULL) {
        ret = stat(file, &buf);
        if (ret == -1) {
            ods_log_error("[%s] stat(%s) failed: %s", logstr, file,
                strerror(errno));
        }
        ods_fclose(fd);
        return buf.st_mtime;
    } else {
        ods_log_error("[%s] open file %s failed", logstr, file);
    }
    return 0;
}
