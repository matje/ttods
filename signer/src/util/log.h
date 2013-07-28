/*
 * $Id: log.h 3845 2010-08-31 14:19:24Z matthijs $
 *
 * Copyright (c) 2009 NLnet Labs. All rights reserved.
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
 * Log wrapper.
 *
 */

#ifndef UTIL_LOG_H
#define UTIL_LOG_H

#include <stdio.h>
#include <stdarg.h>

#ifdef HAVE_SYSLOG_H
#include <strings.h> /* strncasecmp() */
#include <syslog.h> /* openlog(), closelog(), syslog() */
#else /* !HAVE_SYSLOG_H */
#define LOG_EMERG   0 /* ods_fatal_exit */
#define LOG_ALERT   1 /* ods_log_alert */
#define LOG_CRIT    2 /* ods_log_crit */
#define LOG_ERR     3 /* ods_log_error */
#define LOG_WARNING 4 /* ods_log_warning */
#define LOG_NOTICE  5 /* ods_log_info */
#define LOG_INFO    6 /* ods_log_verbose */
#define LOG_DEBUG   7 /* ods_log_debug */
#endif /* HAVE_SYSLOG_H */
#define LOG_DEEEBUG 8 /* ods_log_deeebug */

/**
 * Initialize logging.
 * @param filename: logfile, if NULL use stderr.
 * @param use_syslog: use syslog(3) and ignore filename.
 * @param verbosity: log level.
 *
 */
void ods_log_init(const char *filename, int use_syslog, int verbosity);

/**
 * Close logging.
 *
 */
void ods_log_close(void);

/**
 * Get the facility by string.
 * @param facility: string-format facility.
 * @return:         (int) facility.
 *
 */
int ods_log_get_facility(const char* facility);

/**
 * Get the log level.
 * @return: (int) log_level.
 *
 */
int ods_log_get_level(void);

/**
 * Heavy debug logging.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_deeebug(const char *format, ...);

/**
 * Log debug.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_debug(const char *format, ...);

/**
 * Log verbose.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_verbose(const char *format, ...);

/**
 * Log informational messages.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_info(const char *format, ...);

/**
 * Log warnings.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_warning(const char *format, ...);

/**
 * Log errors.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_error(const char *format, ...);

/**
 * Log criticals.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_crit(const char *format, ...);

/**
 * Log alerts.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_log_alert(const char *format, ...);

/**
 * Log critical errors and exit.
 * @param format: printf-style format string, arguments follow.
 *
 */
void ods_fatal_exit(const char *format, ...);

/**
 * Log assertion.
 *
 */
#define ODS_LOG_DEBUG 1
#ifdef ODS_LOG_DEBUG
#define ods_log_assert(x) \
	do { if(!(x)) \
		ods_fatal_exit("%s:%d: %s: assertion %s failed", \
		__FILE__, __LINE__, __func__, #x); \
	} while(0);

#else
#define ods_log_assert(x)
#endif

#endif /* UTIL_LOG_H */
