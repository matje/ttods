/*
 * $Id: file.h 6501 2012-08-06 10:52:03Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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

#ifndef UTIL_FILE_H
#define UTIL_FILE_H

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#define AD_FILE_MAXLINE 1024

/**
 * Open a file.
 * @param file: filename.
 * @param dir:  directory.
 * @param mode: file mode.
 * @return      (FILE*) file descriptor.
 *
 */
FILE* ods_fopen(const char* file, const char* dir, const char* mode);

/**
 * Close a file.
 * @param fd: file descriptor.
 *
 */
void ods_fclose(FILE* fd);

/**
 * Get next character from file.
 * @param fd: file descriptor.
 * @param l:  updated line number.
 * @return:   (int) next character.
 *
 */
int ods_fgetc(FILE* fd, unsigned int* l);

/**
 * Read one line from file.
 * @param fd:            file descriptor.
 * @param line:          one line.
 * @param l:             updated line number.
 * @param keep_comments: if true, keep comments.
 * @return:              (int) number of characters read.
 *
 */
int ods_freadline(FILE* fd, char* line, unsigned int* l, int keep_comments);

/**
 * Get directory part of filename.
 * @param file: file name.
 * @return:     (char*) directory part.
 *
 */
char* ods_dir_name(const char* file);

/**
 * (Create) and change ownership of directories.
 * @param file:   file name.
 * @param uid:    user id.
 * @param gid:    group id.
 * @param getdir: fetch directory part.
 *
 */
void ods_chown(const char* file, uid_t uid, gid_t gid, int getdir);

/**
 * Write to file descriptor.
 * @param fd:   file descriptor.
 * @param vptr: pointer to data.
 * @param n:    size of data.
 * @return:     (ssize_t) -1 on error, n otherwise.
 *
 */
ssize_t ods_writen(int fd, const void* vptr, size_t n);

/**
 * Get file status.
 * @param file: file name.
 * @return:     (time_t) last modified.
 *
 */
time_t ods_fstat(const char* file);


#endif /* UTIL_FILE_H */
