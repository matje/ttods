/*
 * $Id: privdrop.h 4466 2011-02-16 09:32:52Z rb $
 *
 * Copyright (c) 2009 Nominet UK. All rights reserved.
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

#ifndef UTIL_PRIVDROP_H
#define UTIL_PRIVDROP_H

#include "util/status.h"

#include <pwd.h>
#include <grp.h>

/**
 * Get the group identifier from a group name.
 * @param groupname: group name.
 * @return:          (gid_t) group identifier.
 *
 */
gid_t privgid(const char* groupname);

/**
 * Get the user identifier from a username.
 * @param username: username.
 * @return:         (uid_t) user identifier.
 *
 */
uid_t privuid(const char* username);

/**
 * Drop privileges.
 * @param username:  drop priviliges to this user.
 * @param groupname: drop priviliges to this group.
 * @param newroot:   make this the new root directory.
 * @param puid:      user id is stored here.
 * @param pgid:      group id is stored here.
 * @return:          (ods_status) status.
 *
 */
ods_status privdrop(const char *username, const char *groupname,
    const char *newroot, uid_t* puid, gid_t* pgid);

/**
 * Close privdrop.
 * @param: username:  username.
 * @param: groupname: group name.
 *
 */
void privclose(const char* username, const char* groupname);

#endif /* UTIL_PRIVDROP_H */

