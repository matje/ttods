/*
 * $Id: engine.c 7057 2013-02-26 09:30:10Z matthijs $
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
 * The engine.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "util/duration.h"
#include "util/file.h"
#include "util/hsms.h"
#include "util/log.h"
#include "util/privdrop.h"
#include "util/status.h"
#include "util/util.h"

#include <errno.h>
#include <libxml/parser.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char* logstr = "engine";


/**
 * Clean up engine.
 *
 */
static void
engine_cleanup(engine_type* engine)
{
    size_t i = 0;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;
    if (!engine) {
        return;
    }
    signal_cond = engine->signal_cond;
    signal_lock = engine->signal_lock;
    if (engine->workers && engine->cfg) {
        for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
            worker_cleanup(engine->workers[i]);
        }
    }
    if (engine->drudgers && engine->cfg) {
        for (i=0; i < (size_t) engine->cfg->num_signer_threads; i++) {
            worker_cleanup(engine->drudgers[i]);
        }
    }
    cfg_cleanup(engine->cfg);
    zlist_cleanup(engine->zlist);
    schedule_cleanup(engine->taskq);
    fifoq_cleanup(engine->signq);
    cmdhandler_cleanup(engine->cmdhandler);
    /* destroy locks and region */
    lock_basic_destroy(&signal_lock);
    lock_basic_off(&signal_cond);
    region_cleanup(engine->region);
    return;
}


/**
 * Initialize engine.
 *
 */
static void
engine_init(engine_type* engine)
{
    ods_log_debug("[%s] init signer", logstr);
    ods_log_assert(engine);
    engine->cfg = NULL;
    engine->workers = NULL;
    engine->drudgers = NULL;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    /* [TODO] dnshandler */
    /* [TODO] xfrhandler */
    engine->pid = -1;
    engine->uid = -1;
    engine->gid = -1;
    engine->daemonize = 0;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);
    lock_basic_lock(&engine->signal_lock);
    engine->signal = SIGNAL_RUN;
    lock_basic_unlock(&engine->signal_lock);
#ifdef HAVE_TZSET
    tzset();
#endif
    signal_set_engine(engine);
    /* [TODO] edns init */
    engine->zlist = zlist_create(engine->region);
    if (!engine->zlist) {
        ods_fatal_exit("[%s] create zonelist failed", logstr);
        return;
    }
    engine->taskq = schedule_create(engine->region);
    if (!engine->taskq) {
        ods_fatal_exit("[%s] create taskschedule failed", logstr);
        return;
    }
    engine->signq = fifoq_create(engine->region);
    if (!engine->signq) {
        ods_fatal_exit("[%s] create fifoq failed", logstr);
        return;
    }
    return;
}


/**
 * Create engine.
 *
 */
static engine_type*
engine_create(void)
{
    engine_type* engine;
    region_type* region = region_create();
    if (!region) {
        ods_log_crit("[%s] region create failed", logstr);
        return NULL;
    }
    engine = (engine_type*) region_alloc(region, sizeof(engine_type));
    if (!engine) {
        ods_log_crit("[%s] region alloc failed", logstr);
        return NULL;
    }
    engine->region = region;
    engine_init(engine);
    return engine;
}


/**
 * Drop privileges.
 *
 */
static ods_status
engine_privdrop(engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    uid_t uid = -1;
    gid_t gid = -1;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    ods_log_debug("[%s] drop privileges", logstr);
    if (engine->cfg->username && engine->cfg->group) {
        ods_log_verbose("[%s] drop privileges to user %s, group %s",
           logstr, engine->cfg->username, engine->cfg->group);
    } else if (engine->cfg->username) {
        ods_log_verbose("[%s] drop privileges to user %s", logstr,
           engine->cfg->username);
    } else if (engine->cfg->group) {
        ods_log_verbose("[%s] drop privileges to group %s", logstr,
           engine->cfg->group);
    }
    if (engine->cfg->chroot) {
        ods_log_verbose("[%s] chroot to %s", logstr, engine->cfg->chroot);
    }
    status = privdrop(engine->cfg->username, engine->cfg->group,
        engine->cfg->chroot, &uid, &gid);
    engine->uid = uid;
    engine->gid = gid;
    privclose(engine->cfg->username, engine->cfg->group);
    return status;
}


/**
 * Start command handler.
 *
 */
static void*
cmdhandler_thread_start(void* arg)
{
    cmdhandler_type* cmd = (cmdhandler_type*) arg;
    ods_thread_blocksigs();
    cmdhandler_start(cmd);
    return NULL;
}
static void
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] start command handler", logstr);
    engine->cmdhandler->engine = engine;
    ods_thread_create(&engine->cmdhandler->thread_id,
        cmdhandler_thread_start, engine->cmdhandler);
    return;
}
/**
 * Self pipe trick (see Unix Network Programming).
 *
 */
static int
self_pipe_trick(engine_type* engine)
{
    int sockfd, ret;
    struct sockaddr_un servaddr;
    const char* servsock_filename = ODS_SE_SOCKFILE;
    ods_log_assert(engine);
    ods_log_assert(engine->cmdhandler);
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ods_log_error("[%s] unable to connect to command handler: "
            "socket() failed (%s)", logstr, strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);
        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            ods_log_error("[%s] unable to connect to command handler: "
                "connect() failed (%s)", logstr, strerror(errno));
            close(sockfd);
            return 1;
        } else {
            /* self-pipe trick */
            ods_writen(sockfd, "", 1);
            close(sockfd);
        }
    }
    return 0;
}
/**
 * Stop command handler.
 *
 */
static void
engine_stop_cmdhandler(engine_type* engine)
{
    if (!engine || !engine->cmdhandler) {
        return;
    }
    ods_log_debug("[%s] stop command handler", logstr);
    if (!engine->cmdhandler_done) {
        engine->cmdhandler->need_to_exit = 1;
        if (self_pipe_trick(engine) == 0) {
            while (!engine->cmdhandler_done) {
                ods_log_debug("[%s] waiting for command handler to exit...",
                    logstr);
                sleep(1);
            }
        } else {
            ods_log_error("[%s] command handler self pipe trick failed, "
                "unclean shutdown", logstr);
        }
    }
    return;
}



/**
 * Start/stop workers and drudgers.
 *
 */
static void
engine_create_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    engine->workers = (worker_type**) region_alloc(engine->region,
        ((size_t)engine->cfg->num_worker_threads)*sizeof(worker_type*));
    for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
        if (!(engine->workers[i] = worker_create(engine, i, WORKER_WORKER))) {
            ods_fatal_exit("[%s] create worker failed", logstr);
        }
    }
    return;
}
static void
engine_create_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    engine->drudgers = (worker_type**) region_alloc(engine->region,
        ((size_t)engine->cfg->num_signer_threads)*sizeof(worker_type*));
    for (i=0; i < (size_t) engine->cfg->num_signer_threads; i++) {
        if (!(engine->drudgers[i] = worker_create(engine, i, WORKER_DRUDGER))) {
            ods_fatal_exit("[%s] create drudger failed", logstr);
        }
    }
    return;
}
static void*
worker_thread_start(void* arg)
{
    worker_type* worker = (worker_type*) arg;
    ods_thread_blocksigs();
    worker_start(worker);
    return NULL;
}
static void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    ods_log_debug("[%s] start workers", logstr);
    for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        ods_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
    }
    return;
}
void
engine_start_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    ods_log_debug("[%s] start drudgers", logstr);
    for (i=0; i < (size_t) engine->cfg->num_signer_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        ods_thread_create(&engine->drudgers[i]->thread_id, worker_thread_start,
            engine->drudgers[i]);
    }
    return;
}
static void
engine_stop_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    ods_log_debug("[%s] stop workers", logstr);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
        worker_wakeup(engine->workers[i]);
    }
    ods_log_debug("[%s] notify workers", logstr);
    worker_notify_all(&engine->taskq->s_lock, &engine->taskq->s_cond);
    worker_notify_all(&engine->signq->q_lock, &engine->signq->q_nonfull);
    /* head count */
    for (i=0; i < (size_t) engine->cfg->num_worker_threads; i++) {
        ods_log_debug("[%s] join worker %i", logstr, i+1);
        ods_thread_join(engine->workers[i]->thread_id);
    }
    return;
}
void
engine_stop_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    ods_log_debug("[%s] stop drudgers", logstr);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->cfg->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 1;
    }
    ods_log_debug("[%s] notify drudgers", logstr);
    worker_notify_all(&engine->signq->q_lock, &engine->signq->q_threshold);
    /* head count */
    for (i=0; i < (size_t) engine->cfg->num_signer_threads; i++) {
        ods_log_debug("[%s] join drudger %i", logstr, i+1);
        ods_thread_join(engine->drudgers[i]->thread_id);
    }
    return;
}


/**
 * Set up signer engine.
 *
 */
static ods_status
engine_setup(engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    struct sigaction action;
    int result;
    ods_log_debug("[%s] setup signer", logstr);
    ods_log_assert(engine);
    ods_log_assert(engine->cfg);
    /* check pidfile */
    if (!util_check_pidfile(engine->cfg->pid_filename)) {
        exit(1);
    }
    /* open log */
    ods_log_init(engine->cfg->log_filename, engine->cfg->use_syslog,
       engine->cfg->verbosity);
    /* create handlers */
    engine->cmdhandler = cmdhandler_create(engine->region,
        engine->cfg->clisock_filename);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create commandhandler failed", logstr);
        return ODS_STATUS_CMDHDLRERR;
    }
    /* privdrop */
    engine->uid = privuid(engine->cfg->username);
    engine->gid = privgid(engine->cfg->group);
    ods_chown(engine->cfg->pid_filename, engine->uid, engine->gid, 1);
    ods_chown(engine->cfg->clisock_filename, engine->uid, engine->gid, 0);
    ods_chown(engine->cfg->working_dir, engine->uid, engine->gid, 0);
    if (engine->cfg->log_filename && !engine->cfg->use_syslog) {
        ods_chown(engine->cfg->log_filename, engine->uid, engine->gid, 0);
    }
    if (engine->cfg->working_dir && chdir(engine->cfg->working_dir) != 0) {
        ods_log_error("[%s] chdir to %s failed: %s", logstr,
            engine->cfg->working_dir, strerror(errno));
        return ODS_STATUS_CHDIRERR;
    }
    status = engine_privdrop(engine);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] drop privileges failed: %s", logstr,
            ods_status2str(status));
        return ODS_STATUS_PRIVDROPERR;
    }
    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] fork failed: %s", logstr, strerror(errno));
                return ODS_STATUS_FORKERR;
            case 0: /* child */
                break;
            default: /* parent */
                engine_cleanup(engine);
                engine = NULL;
                xmlCleanupParser();
                xmlCleanupGlobals();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            ods_log_error("[%s] setsid failed: %s", logstr, strerror(errno));
            return ODS_STATUS_SETSIDERR;
        }
    }
    engine->pid = getpid();
    ods_log_verbose("[%s] running as pid %lu", logstr,
        (unsigned long) engine->pid);
    /* catch signals */
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGILL, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGALRM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
    /* open hsm */
    result = hsms_open(engine->cfg->cfg_filename);
    if (result != HSM_OK) {
        return ODS_STATUS_HSMOPENERR;
    }
    /* write pidfile */
    if (util_write_pidfile(engine->cfg->pid_filename, engine->pid) == -1) {
        return ODS_STATUS_WRITEPIDERR;
    }
    /* create workers/drudgers */
    engine_create_workers(engine);
    engine_create_drudgers(engine);
    /* start handlers */
    /* setup done */
    return ODS_STATUS_OK;
}


/**
 * Run signer engine.
 *
 */
static void
engine_run(engine_type* engine, int single_run)
{
    int ret;
    ods_log_assert(engine);
    engine_start_workers(engine);
    engine_start_drudgers(engine);
    lock_basic_lock(&engine->signal_lock);
    engine->signal = SIGNAL_RUN;
    lock_basic_unlock(&engine->signal_lock);
    while (!engine->need_to_exit && !engine->need_to_reload) {
        signal_capture();
        lock_basic_lock(&engine->signal_lock);
        switch (engine->signal) {
            case SIGNAL_RUN:
                ods_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                ods_log_warning("[%s] invalid signal %d captured, "
                    "keep running", logstr, signal);
                engine->signal = SIGNAL_RUN;
                break;
        }
        lock_basic_unlock(&engine->signal_lock);

        if (single_run) {
            ods_log_warning("[%s] SINGLE RUN NOT IMPLEMENTED", logstr);
        }
        lock_basic_lock(&engine->signal_lock);
        if (engine->signal == SIGNAL_RUN && !single_run) {
           ods_log_debug("[%s] taking a break", logstr);
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        lock_basic_unlock(&engine->signal_lock);
    }
    ods_log_debug("[%s] signer halted", logstr);
    engine_stop_drudgers(engine);
    engine_stop_workers(engine);
    if ((ret = hsms_reopen(engine->cfg->cfg_filename)) != HSM_OK) {
        ods_log_crit("[%s] reopen hsm failed (%d)", logstr, ret);
    }
    return;
}


/**
 * Log region memory for zones.
 *
 */
static void
engine_log_zone_regions(engine_type* engine)
{
    zone_type* z = NULL;
    ldns_rbnode_t* n = LDNS_RBTREE_NULL;
    if (!engine || !engine->zlist || !engine->zlist->zones) {
        return;
    }
    n = ldns_rbtree_first(engine->zlist->zones);
    while (n && n != LDNS_RBTREE_NULL) {
        z = (zone_type*) n->data;
        region_log(z->region, z->name);
        n = ldns_rbtree_next(n);
    }
    return;
}


/**
 * Start signer engine.
 *
 */
void
engine_start(const char* cfgfile, int cmdline_verbosity, int daemonize,
    int info, int single_run)
{
    engine_type* engine;
    int use_syslog = 0;
    ods_status status;
    ods_status zl_changed;
    ods_log_assert(cfgfile);
    /* create */
    ods_log_init(NULL, use_syslog, cmdline_verbosity);
    xmlInitGlobals();
    xmlInitParser();
    xmlInitThreads();
    engine = engine_create();
    if (!engine) {
        ods_fatal_exit("[%s] create failed", logstr);
        return;
    }
    engine->daemonize = daemonize;
    /* config */
    engine->cfg = cfg_create(engine->region, cfgfile, cmdline_verbosity);
    if (!engine->cfg) {
        ods_fatal_exit("[%s] cfg create failed", logstr);
        return;
    }
    status = cfg_check(engine->cfg);
    if (status != ODS_STATUS_OK) {
        ods_fatal_exit("[%s] cfg check failed: %s", logstr,
            ods_status2str(status));
        return;
    }
    /* info */
    if (info) {
        cfg_print(stdout, engine->cfg);
        exit(0);
    }
    /* setup */
    status = engine_setup(engine);
    if (status != ODS_STATUS_OK) {
        ods_fatal_exit("[%s] setup failed: %s", logstr,
            ods_status2str(status));
        return;
    }
    /* run */
    engine_start_cmdhandler(engine);
    while (!engine->need_to_exit) {
        /* update zone list */
        lock_basic_lock(&engine->zlist->zl_lock);
        zl_changed = zlist_update(engine->zlist,
            engine->cfg->zonelist_filename);
        lock_basic_unlock(&engine->zlist->zl_lock);
        /* start/reload */
        if (engine->need_to_reload) {
            ods_log_info("[%s] reload signer", logstr);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] start signer", logstr);
        }
        if (zl_changed == ODS_STATUS_OK ||
            zl_changed == ODS_STATUS_UNCHANGED) {
            engine_update_zones(engine, zl_changed);
        }
        region_log(engine->region, "engine");
        engine_log_zone_regions(engine);
        engine_run(engine, single_run);
    }
    /* shutdown */
    ods_log_info("[%s] shutdown signer", logstr);
    engine_stop_cmdhandler(engine);
    ods_log_verbose("[%s] close hsm", logstr);
    hsm_close();
    if (engine && engine->cfg) {
        if (engine->cfg->pid_filename) {
            (void)unlink(engine->cfg->pid_filename);
        }
        if (engine->cfg->clisock_filename) {
            (void)unlink(engine->cfg->clisock_filename);
        }
    }
    engine_cleanup(engine);
    ods_log_close();
    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    return;
}


/**
 * Parse notify command.
 *
 */
static void
set_notify_ns(zone_type* zone, const char* cmd)
{
    const char* str = NULL;
    const char* str2 = NULL;
    char* token = NULL;
    ods_log_assert(cmd);
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    return;
}


/**
 * Update zones.
 *
 */
void
engine_update_zones(engine_type* engine, ods_status zl_changed)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    time_t now = time_now();
    if (!engine || !engine->zlist || !engine->zlist->zones) {
        return;
    }
    ods_log_debug("[%s] commit zone list changes", logstr);
    lock_basic_lock(&engine->zlist->zl_lock);
    node = ldns_rbtree_first(engine->zlist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone_type* zone = (zone_type*) node->data;
        task_type* task = NULL;
        if (zone->zl_status == ZONE_ZL_REMOVED) {
            node = ldns_rbtree_next(node);
            lock_basic_lock(&zone->zone_lock);
            (void)zlist_del_zone(engine->zlist, zone);
            /* [TODO] clean up task */
            lock_basic_unlock(&zone->zone_lock);
            /* [TODO] remove netio handler */
            zone_cleanup(zone);
            zone = NULL;
            continue;
        } else if (zone->zl_status == ZONE_ZL_ADDED) {
            lock_basic_lock(&zone->zone_lock);
            ods_log_assert(!zone->task);
            /* set notify nameserver command */
            if (engine->cfg->notify_command && !zone->notify_ns) {
                set_notify_ns(zone, engine->cfg->notify_command);
            }
            /* create task */
            task = task_create(TASK_CONF, now, zone);
            lock_basic_unlock(&zone->zone_lock);
            if (!task) {
                ods_log_crit("[%s] create task for zone %s failed", logstr,
                    zone->name);
                node = ldns_rbtree_next(node);
                continue;
            }
        }
        /* [TODO] load adapter config */

        if (zone->zl_status == ZONE_ZL_ADDED) {
            ods_log_assert(task);
            lock_basic_lock(&zone->zone_lock);
            lock_basic_unlock(&zone->zone_lock);
            lock_basic_lock(&engine->taskq->s_lock);
            status = schedule_task(engine->taskq, task, 0);
            lock_basic_unlock(&engine->taskq->s_lock);
        } else if (zl_changed == ODS_STATUS_OK) {
            /* always try to update signconf */
            lock_basic_lock(&zone->zone_lock);
            status = zone_reschedule_task(zone, engine->taskq, TASK_CONF);
            lock_basic_unlock(&zone->zone_lock);
        }
        if (status != ODS_STATUS_OK) {
            ods_log_crit("[%s] schedule task for zone %s failed: %s",
                logstr, zone->name, ods_status2str(status));
            task_cleanup(task);
            zone->task = NULL;
        } else {
            zone->zl_status = ZONE_ZL_OK;
        }
        node = ldns_rbtree_next(node);
    }
    lock_basic_unlock(&engine->zlist->zl_lock);
    return;
}


/* [TODO] recover engine */

