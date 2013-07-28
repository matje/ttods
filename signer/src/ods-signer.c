/*
 * $Id: ods-signer.c 6573 2012-08-28 14:00:54Z matthijs $
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
 * OpenDNSSEC signer engine client.
 *
 */

#include "config.h"
#include "util/file.h"
#include "util/str.h"
#include "util/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* According to earlier standards, we need sys/time.h, sys/types.h, unistd.h for select() */
#include <sys/types.h>
#include <sys/time.h>

#define SE_CLI_CMDLEN 6

static const char* logstr = "client";


/**
 * Prints usage.
 *
 */
static void
usage(FILE* out)
{
    fprintf(out, "Usage: %s [<cmd>]\n", "ods-signer");
    fprintf(out, "Simple command line interface to control the signer "
                 "engine daemon.\nIf no cmd is given, the tool is going "
                 "into interactive mode.\n");
    fprintf(out, "\nBSD licensed, see LICENSE in source package for "
                 "details.\n");
    fprintf(out, "Version %s. Report bugs to <%s>.\n",
        PACKAGE_VERSION, PACKAGE_BUGREPORT);
    return;
}


/**
 * Interface.
 *
 */
static int
interface_run(const int sockfd, const char* cmd)
{
    int written, n = 0, ret = 0, sockeof = 0;
    fd_set rset;
    char buf[ODS_SE_MAXLINE];

    ods_writen(sockfd, cmd, strlen(cmd)+1);
    FD_ZERO(&rset);
    while (!sockeof) {
        FD_SET(sockfd, &rset); /* pipe */
        ret = select(sockfd + 1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                fprintf(stdout, "[%s] interface select error: %s",
                    logstr, strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(sockfd, &rset)) {
            /* socket is readable */
            memset(buf, 0, ODS_SE_MAXLINE);
            n = read(sockfd, buf, ODS_SE_MAXLINE);
            if (n == 0) {
                /* daemon closed connection */
                sockeof = 1;
                printf("\n");
            } else if (n < 0) {
                fprintf(stderr, "error reading pipe: %s\n", strerror(errno));
                return 1; /* indicates error */
            }
            /* now write what we have to stdout */
            for (written = 0, ret = 0; written < n; written += ret) {
                ret = (int) write(fileno(stdout), buf+written, n-written);
                if (ret < 0) {
                    if (errno == EINTR || errno == EWOULDBLOCK) {
                        ret = 0;
                        continue; /* try again... */
                    }
                    fprintf(stderr, "error writing to stdout: %s\n",
                        strerror(errno));
                    return 1; /*  */
                }
            }
        }
    }
    return 0;
}


/**
 * Start interface.
 *
 */
static int
interface_start(char* cmd_arg, const char* servsock_filename)
{
    int sockfd, flags, return_value, n;
    struct sockaddr_un servaddr;
    char cmd[ODS_SE_MAXLINE];

    do {
        return_value = 0;
        /* read user input */
        if (!cmd_arg) { /* interactive mode */
            memset(cmd, 0, ODS_SE_MAXLINE);
            printf("cmd> ");
            fflush(stdout);
            n = read(fileno(stdin), cmd, ODS_SE_MAXLINE);
            if (n == 0) { /* eof */
                printf("\n");
                break;
            } else if (n == -1) {
                exit(1);
            }
            /* read produces trailing lf */
            cmd[n-1] = 0;
        } else { /* one shot mode */
            strncpy(cmd, cmd_arg, ODS_SE_MAXLINE);
        }
        /* user input, handle with care */
        cmd[ODS_SE_MAXLINE-1] = 0;
        (void)ods_strtrim(cmd);
        /* don't bother daemon w/ whitespace */
        if (cmd[0] == 0) {
            continue;
        }
        /* these commands don't go through the pipe */
        if (ods_strcmp(cmd, "exit") == 0 || ods_strcmp(cmd, "quit") == 0) {
            break;
        }
        if (ods_strcmp(cmd, "start") == 0) {
                if (system(ODS_SE_ENGINE) != 0) {
                    fprintf(stderr, "Failed to start signer engine daemon.\n");
                }
                continue;
        }
        /* now we know what to say, open socket */
        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd <= 0) {
            fprintf(stderr, "Unable to connect to engine. "
                "socket() failed: %s (\"%s\")\n",
                strerror(errno), servsock_filename);
            return_value = 1;
            break;
        }
        /* no suprises */
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);
        if (connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr)) != 0) {
            if (ods_strcmp(cmd, "running") == 0) {
                fprintf(stderr, "Engine not running.\n");
            } else {
                fprintf(stderr, "Unable to connect to engine. "
                    "connect() failed: %s (\"%s\")\n"
                    "Is ods-signerd running?\n",
                    strerror(errno), servsock_filename);
            }
            return_value = 1;
            close(sockfd);
            continue;
        }
        /* set socket to non-blocking */
        flags = fcntl(sockfd, F_GETFL, 0);
        if (flags < 0) {
            fprintf(stderr, "[%s] unable to start interface, fcntl(F_GETFL) "
                "failed: %s", logstr, strerror(errno));
            close(sockfd);
            return_value = 1;
            break;
        }
        flags |= O_NONBLOCK;
        if (fcntl(sockfd, F_SETFL, flags) < 0) {
            fprintf(stderr, "[%s] unable to start interface, fcntl(F_SETFL) "
                "failed: %s", logstr, strerror(errno));
            close(sockfd);
            return_value = 1;
            break;
        }
        return_value = interface_run(sockfd, cmd);
        close(sockfd);
        if (return_value) {
            break;
        }
    } while (!cmd_arg);
    return return_value;
}


/**
 * Main. start interface tool.
 *
 */
int
main(int argc, char* argv[])
{
    int c, ret = 0, options_size = 0;
    const char* options[4];
    char* cmd = NULL;

    if (argc > 3) {
        fprintf(stderr, "[%s] error: Too many arguments.\n", logstr);
        exit(1);
    }
    /* command line options */
    for (c = 0; c < argc; c++) {
        options[c] = argv[c];
        if (c > 0) {
            options_size += strlen(argv[c]) + 1;
        }
    }
    if (argc > 1) {
        cmd = (char*) malloc((options_size+2)*sizeof(char));
        if (!cmd) {
            fprintf(stderr, "[%s] error: Memory allocation failed.\n", logstr);
            exit(1);
        }
        (void)strncpy(cmd, "", 1);
        for (c = 1; c < argc; c++) {
            (void)strncat(cmd, options[c], strlen(options[c]));
            (void)strncat(cmd, " ", 1);
        }
        cmd[options_size-1] = '\0';
    }
    /* main stuff */
    if (cmd && (ods_strcmp(cmd, "-h") == 0 ||
        ods_strcmp(cmd, "--help") == 0)) {
        usage(stdout);
        ret = 1;
    } else {
        ret = interface_start(cmd, ODS_SE_SOCKFILE);
    }
    /* done */
    return ret;
}
