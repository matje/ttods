/*
 * $Id: cmdhandler.c 7039 2013-02-15 08:10:15Z matthijs $
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

#include "config.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "util/file.h"
#include "util/locks.h"
#include "util/log.h"
#include "util/tree.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

static int count = 0;
static char* logstr = "cmdhandler";


/**
 * Handle the 'help' command.
 *
 */
static int
cmdhandler_handle_cmd_help(int sockfd, cmdhandler_type* ATTR_UNUSED(cmdc),
    const char* cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 4 || strncmp(cmd, "help", n) != 0) {
        return 0; /* no match */
    }
    (void) snprintf(buf, ODS_SE_MAXLINE,
        "Commands:\n"
        "zones           Show the currently known zones.\n"
        "sign <zone>     Read zone and schedule for immediate (re-)sign.\n"
        "sign --all      Read all zones and schedule all for immediate "
                         "(re-)sign.\n"
        "clear <zone>    Delete the internal storage of this zone.\n"
        "                All signatures will be regenerated on the next "
                         "re-sign.\n"
        "queue           Show the current task queue.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "flush           Execute all scheduled tasks immediately.\n"
        "update <zone>   Update this zone signer configurations.\n"
        "update [--all]  Update zone list and all signer configurations.\n"
        "start           Start the engine.\n"
        "running         Check if the engine is running.\n"
        "reload          Reload the engine.\n"
        "stop            Stop the engine.\n"
        "verbosity <nr>  Set verbosity.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'zones' command.
 *
 */
static int
cmdhandler_handle_cmd_zones(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i;
    tree_node* node = TREE_NULL;
    zone_type* zone = NULL;
    if (n != 5 || strncmp(cmd, "zones", n) != 0) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    if (!engine->zlist || !engine->zlist->zones) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no zones configured\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1;
    }
    /* how many zones */
    lock_basic_lock(&engine->zlist->zl_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %d zones configured\n",
        (int)tree_count(engine->zlist->zones));
    ods_writen(sockfd, buf, strlen(buf));
    /* list zones */
    node = tree_first(engine->zlist->zones);
    while (node && node != TREE_NULL) {
        zone = (zone_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "- %s\n", zone->name);
        ods_writen(sockfd, buf, strlen(buf));
        node = tree_next(node);
    }
    lock_basic_unlock(&engine->zlist->zl_lock);
    return 1;
}


/**
 * Handle the 'update' command.
 *
 */
static int
cmdhandler_handle_cmd_update(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n < 6 || strncmp(cmd, "update", 6) != 0 ||
        (cmd[6] != ' ' && cmd[6] != '\0')) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;

    (void)snprintf(buf, ODS_SE_MAXLINE, "Update command not implemented.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'sign' command.
 *
 */
static int
cmdhandler_handle_cmd_sign(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n < 4 || strncmp(cmd, "sign", 4) != 0 || cmd[4] != ' ') {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;

    (void)snprintf(buf, ODS_SE_MAXLINE, "Sign command not implemented.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'clear' command.
 *
 */
static int
cmdhandler_handle_cmd_clear(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n < 5 || strncmp(cmd, "clear", 5) != 0 || cmd[5] != ' ') {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;

    (void)snprintf(buf, ODS_SE_MAXLINE, "Clear command not implemented.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'queue' command.
 *
 */
static int
cmdhandler_handle_cmd_queue(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char* strtime = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i;
    time_t now;
    tree_node* node = TREE_NULL;
    if (n != 5 || strncmp(cmd, "queue", 5) != 0) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    if (!engine->taskq || !engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return 1;
    }
    /* current time */
    now = time_now();
    strtime = ctime(&now);
    (void)snprintf(buf, ODS_SE_MAXLINE, "It is now %s",
        strtime?strtime:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    /* current work */
    lock_basic_lock(&engine->taskq->s_lock);
    for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
        if (engine->workers[i]->task) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Working with task %s on "
                "zone %s\n",
                task_what2str(engine->workers[i]->working_with),
                task_who2str(engine->workers[i]->task));
            ods_writen(sockfd, buf, strlen(buf));
        }
    }
    /* how many tasks */
    (void)snprintf(buf, ODS_SE_MAXLINE, "\nI have %i tasks scheduled.\n",
        (int)tree_count(engine->taskq->tasks));
    ods_writen(sockfd, buf, strlen(buf));
    /* list tasks */
    node = tree_first(engine->taskq->tasks);
    while (node && node != TREE_NULL) {
        task_type* task = (task_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)task2str(task, (char*) &buf[0]);
        ods_writen(sockfd, buf, strlen(buf));
        node = tree_next(node);
    }
    lock_basic_unlock(&engine->taskq->s_lock);
    return 1;
}


/**
 * Handle the 'flush' command.
 *
 */
static int
cmdhandler_handle_cmd_flush(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n != 5 || strncmp(cmd, "flush", 5) != 0) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;

    (void)snprintf(buf, ODS_SE_MAXLINE, "Flush command not implemented.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'reload' command.
 *
 */
static int
cmdhandler_handle_cmd_reload(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n != 6 || strncmp(cmd, "reload", 6) != 0) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    engine->need_to_reload = 1;
    lock_basic_lock(&engine->signal_lock);
    lock_basic_alarm(&engine->signal_cond);
    lock_basic_unlock(&engine->signal_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Reload signer engine.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'stop' command.
 *
 */
static int
cmdhandler_handle_cmd_stop(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    engine_type* engine = NULL;
    char buf[ODS_SE_MAXLINE];
    if (n != 4 || strncmp(cmd, "stop", 4) != 0) {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    engine = (engine_type*) cmdc->engine;
    engine->need_to_exit = 1;
    lock_basic_lock(&engine->signal_lock);
    lock_basic_alarm(&engine->signal_cond);
    lock_basic_unlock(&engine->signal_lock);
    (void)snprintf(buf, ODS_SE_MAXLINE, "Signer engine shut down.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'start' command.
 *
 */
static int
cmdhandler_handle_cmd_start(int sockfd, cmdhandler_type* ATTR_UNUSED(cmdc),
    const char* cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 5 || strncmp(cmd, "start", 5) != 0) {
        return 0; /* no match */
    }
    (void)snprintf(buf, ODS_SE_MAXLINE, "Signer engine already running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'running' command.
 *
 */
static int
cmdhandler_handle_cmd_running(int sockfd, cmdhandler_type* ATTR_UNUSED(cmdc),
    const char* cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n != 7 || strncmp(cmd, "running", 7) != 0) {
        return 0; /* no match */
    }
    (void)snprintf(buf, ODS_SE_MAXLINE, "Signer engine is running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle the 'verbosity' command.
 *
 */
static int
cmdhandler_handle_cmd_verbosity(int sockfd, cmdhandler_type* cmdc,
    const char* cmd, ssize_t n)
{
    char buf[ODS_SE_MAXLINE];
    if (n < 9 || strncmp(cmd, "verbosity", 9) != 0 || cmd[9] != ' ') {
        return 0; /* no match */
    }
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    if (cmd[9] == '\0') {
        (void)snprintf(buf, ODS_SE_MAXLINE, "Error: verbosity command missing "
            "an argument (verbosity level).\n");
        ods_writen(sockfd, buf, strlen(buf));
    } else {
        engine_type* engine = (engine_type*) cmdc->engine;
        int val = atoi(&cmd[10]);
        engine = (engine_type*) cmdc->engine;
        ods_log_assert(engine);
        ods_log_assert(engine->cfg);
        ods_log_init(engine->cfg->log_filename,
                     engine->cfg->use_syslog, val);
        (void)snprintf(buf, ODS_SE_MAXLINE, "Verbosity level set to %i.\n",
            val);
        ods_writen(sockfd, buf, strlen(buf));
    }
    return 1;
}


/**
 * Handle unknown commands.
 *
 */
static int
cmdhandler_handle_cmd_unknown(int sockfd, cmdhandler_type* ATTR_UNUSED(cmdc),
    const char* cmd, ssize_t ATTR_UNUSED(n))
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command: %s.\n",
        cmd?cmd:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    return 1;
}


/**
 * Handle client command.
 *
 */
static void
cmdhandler_handle_cmd(int sockfd, cmdhandler_type* cmdc, const char* buf,
    ssize_t n)
{
    cmdhandler_handle_cmd_func cmds[] = {
        cmdhandler_handle_cmd_help,
        cmdhandler_handle_cmd_zones, /* notimpl */
        cmdhandler_handle_cmd_update, /* notimpl */
        cmdhandler_handle_cmd_sign, /* notimpl */
        cmdhandler_handle_cmd_clear, /* notimpl */
        cmdhandler_handle_cmd_queue, /* notimpl */
        cmdhandler_handle_cmd_flush, /* notimpl */
        cmdhandler_handle_cmd_stop,
        cmdhandler_handle_cmd_start,
        cmdhandler_handle_cmd_reload,
        cmdhandler_handle_cmd_running,
        cmdhandler_handle_cmd_verbosity,
        cmdhandler_handle_cmd_unknown /* unknown must be last entry */
    };
    unsigned i;
    int ret;
    ods_log_verbose("[%s] received command %s[%i]", logstr, buf, n);
    for (i=0; i < sizeof(cmds) / sizeof(cmdhandler_handle_cmd_func); i++) {
        if ((ret = cmds[i](sockfd, cmdc, buf, n))) {
            break;
        }
    }
    ods_log_debug("[%s] done handling command %s[%i]", logstr, buf, n);
    return;
}


/**
 * Handle client conversation.
 *
 */
static void
cmdhandler_handle_conversation(cmdhandler_type* cmdc)
{
    ssize_t n;
    int sockfd;
    char buf[ODS_SE_MAXLINE];
    ods_log_assert(cmdc);
    sockfd = cmdc->client_fd;

cmdhandler_handle_conversation:
    n = read(sockfd, buf, ODS_SE_MAXLINE);
    if (n <= 0) {
        if (n == 0 || errno == ECONNRESET) {
            ods_log_debug("[%s] done handling client: %s", logstr,
                strerror(errno));
        } else if (errno == EINTR || errno == EWOULDBLOCK ||
            errno == EAGAIN) {
            goto cmdhandler_handle_conversation;
        } else {
            ods_log_error("[%s] read error: %s", logstr, strerror(errno));
        }
    } else {
        buf[--n] = '\0';
        if (n > 0) {
            cmdhandler_handle_cmd(sockfd, cmdc, buf, n);
            /*goto cmdhandler_handle_conversation;*/
        }
    }
    return;
}


/**
 * Accept client.
 *
 */
static void*
cmdhandler_accept_client(void* arg)
{
    cmdhandler_type* cmdc = (cmdhandler_type*) arg;
    ods_thread_blocksigs();
    ods_thread_detach(cmdc->thread_id);
    ods_log_debug("[%s] accept client %i", logstr, cmdc->client_fd);
    cmdhandler_handle_conversation(cmdc);
    if (cmdc->client_fd) {
        shutdown(cmdc->client_fd, SHUT_RDWR);
        close(cmdc->client_fd);
    }
    count--;
    return NULL;
}


/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(region_type* r, const char* filename)
{
    cmdhandler_type* cmdh = NULL;
    struct sockaddr_un servaddr;
    int listenfd = 0;
    int flags = 0;
    int ret = 0;
    ods_log_assert(r);
    ods_log_assert(filename);
    /* new socket */
    ods_log_debug("[%s] create socket %s", logstr, filename);
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd < 0) {
        ods_log_crit("[%s] create socket failed: %s", logstr, strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_crit("[%s] get fcntl failed: %s", logstr, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_crit("[%s] set fcntl failed: %s", logstr, strerror(errno));
        close(listenfd);
        return NULL;
    }
    /* no surprises so far */
    if (filename) {
        (void)unlink(filename);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SUN_LEN
    servaddr.sun_len = strlen(servaddr.sun_path);
#endif
    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
    if (ret != 0) {
        ods_log_crit("[%s] bind socket failed: %s", logstr, strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        ods_log_crit("[%s] listen failed: %s", logstr, strerror(errno));
        close(listenfd);
        return NULL;
    }
    /* all ok */
    cmdh = (cmdhandler_type*) region_alloc(r, sizeof(cmdhandler_type));
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    return cmdh;
}


/**
 * Start command handler.
 *
 */
void
cmdhandler_start(cmdhandler_type* cmdhandler)
{
    struct sockaddr_un cliaddr;
    socklen_t clilen;
    cmdhandler_type* cmdc = NULL;
    engine_type* engine = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;
    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", logstr);
    engine = (engine_type*) cmdhandler->engine;
    ods_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(cmdhandler->listen_fd+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", logstr,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept() error: %s", logstr,
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) region_alloc(engine->region,
                sizeof(cmdhandler_type));
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            ods_thread_create(&cmdc->thread_id, &cmdhandler_accept_client,
                (void*) cmdc);
            count++;
            ods_log_debug("[%s] %i clients in progress...", logstr, count);
        }
    }
    ods_log_debug("[%s] done", logstr);
    engine = cmdhandler->engine;
    engine->cmdhandler_done = 1;
    return;
}


/**
 * Clean up command handler.
 *
 */
void
cmdhandler_cleanup(cmdhandler_type* cmdhandler)
{
    if (!cmdhandler) {
        return;
    }
    close(cmdhandler->listen_fd);
    return;
}

