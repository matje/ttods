/*
 * $Id: cmdhandler.h 5945 2011-11-30 11:54:30Z matthijs $
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
 * Command handler.
 *
 */

#ifndef DAEMON_CMDHANDLER_H
#define DAEMON_CMDHANDLER_H

#include "util/locks.h"
#include "util/region.h"

#include <sys/un.h>

struct engine_struct;

#define ODS_SE_MAX_HANDLERS 5

typedef struct cmdhandler_struct cmdhandler_type;
struct cmdhandler_struct {
    struct engine_struct* engine;
    struct sockaddr_un listen_addr;
    ods_thread_type thread_id;
    int listen_fd;
    int client_fd;
    int need_to_exit;

    /* 1x ptr, 1x struct, 4x int */
    /* est.mem: CMD: 128 bytes */
};

typedef int (*cmdhandler_handle_cmd_func)(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n);

/**
 * Create command handler.
 * @param r:        memory region.
 * @param filename: socket file name
 * @return:         (cmdhandler_type*) command handler.
 *
 */
cmdhandler_type* cmdhandler_create(region_type* r, const char* filename);

/**
 * Start command handler.
 * @param cmdhandler: command handler.
 *
 */
void cmdhandler_start(cmdhandler_type* cmdhandler);

/**
 * Clean up command handler.
 * @param cmdhandler: command handler.
 *
 */
void cmdhandler_cleanup(cmdhandler_type* cmdhandler);

#endif /* DAEMON_CMDHANDLER_H */
