/*
 * $Id: util.c 6747 2012-10-19 10:32:45Z matthijs $
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
 * Useful utilities.
 *
 */

#include "config.h"
#include "util/file.h"
#include "util/log.h"
#include "util/str.h"
#include "util/util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char* logstr = "util";


/**
 * Looks up the table entry by name.
 *
 */
table_type*
table_lookup_by_name(table_type table[], const char* name)
{
    while (table->name != NULL) {
        if (ods_strcasecmp(name, table->name) == 0) {
            return table;
        }
        table++;
    }
    return NULL;
}


/**
 * Looks up the table entry by identifier.
 *
 */
table_type*
table_lookup_by_id(table_type table[], int id)
{
    while (table->name != NULL) {
        if (table->id == id) {
            return table;
        }
        table++;
    }
    return NULL;
}


/**
 * Simple max function.
 *
 */
int
ods_max(int a, int b)
{
    return a<b ? b : a;
}


/**
 * Read process id from file.
 *
 */
static pid_t
util_read_pidfile(const char* file)
{
    int fd;
    pid_t pid;
    char pidbuf[32];
    char *t;
    int l;
    if ((fd = open(file, O_RDONLY)) == -1) {
        return -1;
    }
    if (((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
        close(fd);
        return -1;
    }
    close(fd);
    /* Empty pidfile means no pidfile... */
    if (l == 0) {
        errno = ENOENT;
        return -1;
    }
    pid = (pid_t) strtol(pidbuf, &t, 10);
    if (*t && *t != '\n') {
        return -1;
    }
    return pid;
}


/**
 * Check process id file.
 *
 */
int
util_check_pidfile(const char* pidfile)
{
    pid_t oldpid;
    struct stat stat_ret;
    if (!pidfile) {
        return 1;
    }
    /**
     * If the file exists then either we didn't shutdown cleanly or
     * a signer daemon is already running: in either case shutdown.
     */
    if (stat(pidfile, &stat_ret) != 0) {
        if (errno != ENOENT) {
            ods_log_error("[%s] cannot stat pidfile %s: %s", logstr, pidfile,
                strerror(errno));
        } /* else: file does not exist: carry on */
    } else {
          if (S_ISREG(stat_ret.st_mode)) {
            /** The pidfile exists already */
            if ((oldpid = util_read_pidfile(pidfile)) == -1) {
                /** Consider stale pidfile */
                if (errno != ENOENT) {
                    ods_log_error("[%s] cannot read pidfile %s: %s", logstr,
                        pidfile, strerror(errno));
                }
            } else {
                if (kill(oldpid, 0) == 0 || errno == EPERM) {
                    ods_log_crit("[%s] pidfile %s already exists, "
                        "a process with pid %u is already running. "
                        "If no ods-signerd process is running, a previous "
                        "instance didn't shutdown cleanly, please remove this "
                        "file and try again.", logstr, pidfile, oldpid);
                    return 0;
                } else {
                    /** Consider state pidfile */
                    ods_log_warning("[%s] pidfile %s already exists, "
                        "but no process with pid %u is running. "
                        "A previous instance didn't shutdown cleanly, this "
                        "pidfile is stale.", logstr, pidfile, oldpid);
                }
            }
        }
    }
    /** All good, carry on */
    return 1;
}


/**
 * Write process id to file.
 *
 */
int
util_write_pidfile(const char* pidfile, pid_t pid)
{
    FILE* fd;
    char pidbuf[32];
    size_t result = 0, size = 0;
    if (!pidfile || !pid) {
        ods_log_error("[%s] write pid requires valid pidfile and pid", logstr);
        return -1;
    }
    ods_log_debug("[%s] writing pid %lu to pidfile %s", logstr,
        (unsigned long) pid, pidfile);
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    fd = ods_fopen(pidfile, NULL, "w");
    if (!fd) {
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0) {
        result = 1;
    } else {
        result = fwrite((const void*) pidbuf, 1, size, fd);
    }
    if (result == 0) {
        ods_log_error("[%s] write to pidfile %s failed: %s", logstr,
            pidfile, strerror(errno));
    } else if (result < size) {
        ods_log_error("[%s] short write to pidfile %s: disk full?", logstr,
            pidfile);
        result = 0;
    } else {
        result = 1;
    }
    ods_fclose(fd);
    if (!result) {
        return -1;
    }
    return 0;
}

