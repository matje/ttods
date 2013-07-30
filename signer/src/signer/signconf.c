/*
 * $Id: signconf.c 7039 2013-02-15 08:10:15Z matthijs $
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
 * Signer configuration.
 *
 */

#include "config.h"
#include "parser/signconfparser.h"
#include "signer/signconf.h"
#include "util/file.h"
#include "util/log.h"

static const char* logstr = "signconf";


/**
 * Create a new signer configuration with the 'empty' settings.
 *
 */
signconf_type*
signconf_create(region_type* r)
{
    signconf_type* sc;
    ods_log_assert(r);
    sc = (signconf_type*) region_alloc(r, sizeof(signconf_type));
    sc->last_modified = 0;
    /* Signatures */
    duration_init(&(sc->sig_resign_interval));
    duration_init(&(sc->sig_refresh_interval));
    duration_init(&(sc->sig_validity_default));
    duration_init(&(sc->sig_validity_denial));
    duration_init(&(sc->sig_jitter));
    duration_init(&(sc->sig_inception_offset));
    /* Denial of existence */
    /* Keys */
    duration_init(&(sc->dnskey_ttl));
    /* Source of authority */
    duration_init(&(sc->soa_ttl));
    duration_init(&(sc->soa_min));
    /* Other useful information */
    return sc;
}


/**
 * Read signer configuration.
 *
 */
static ods_status
signconf_read(signconf_type* sc, const char* scfile)
{
    const char* rngfile = ODS_SE_RNGDIR "/signconf.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;
    char salt[SC_SALT_SIZE];
    char serial[SC_SERIAL_SIZE];
    ldns_rr_type nsectype;
    duration_type resign, refresh, valdefault, valdenial, jitter, inception,
        dnskeyttl, soattl, soamin;
    ods_log_assert(sc);
    ods_log_assert(scfile);
    status = parser_filecheck(scfile, rngfile);
    if (parser_filecheck(scfile, rngfile) != ODS_STATUS_OK) {
        ods_log_error("[%s] parse error in %s", logstr, scfile);
        return status;
    }
    /* open file */
    fd = ods_fopen(scfile, NULL, "r");
    if (fd) {
        ods_log_debug("[%s] read signconf file %s", logstr, scfile);
        duration_init(&resign);
        duration_init(&refresh);
        duration_init(&valdefault);
        duration_init(&valdenial);
        duration_init(&jitter);
        duration_init(&inception);
        duration_init(&dnskeyttl);
        duration_init(&soattl);
        duration_init(&soamin);
        status = parser_sc_sig_resign_interval(scfile, &resign);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_sig_refresh_interval(scfile, &refresh);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_sig_validity_default(scfile, &valdefault);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_sig_validity_denial(scfile, &valdenial);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_sig_jitter(scfile, &jitter);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_sig_inception_offset(scfile, &inception);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_dnskey_ttl(scfile, &dnskeyttl);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        nsectype = parser_sc_nsec_type(scfile);
        if (nsectype == LDNS_RR_TYPE_NSEC3) {
            status = parser_sc_nsec3_salt(scfile, &salt[0]);
            if (status != ODS_STATUS_OK) {
                goto signconf_read_done;
            }
        }
        status = parser_sc_soa_ttl(scfile, &soattl);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_soa_min(scfile, &soamin);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }
        status = parser_sc_soa_serial(scfile, &serial[0]);
        if (status != ODS_STATUS_OK) {
            goto signconf_read_done;
        }

signconf_read_done:
        if (status == ODS_STATUS_OK) {
            duration_copy(&(sc->sig_resign_interval), &resign);
            duration_copy(&(sc->sig_refresh_interval), &refresh);
            duration_copy(&(sc->sig_validity_default), &valdefault);
            duration_copy(&(sc->sig_validity_denial), &valdenial);
            duration_copy(&(sc->sig_jitter), &jitter);
            duration_copy(&(sc->sig_inception_offset), &inception);
            sc->nsec_type = nsectype;
            if (sc->nsec_type == LDNS_RR_TYPE_NSEC3) {
                sc->nsec3_optout = parser_sc_nsec_type(scfile);
                /* nsec3 algo */
                /* nsec3 iter */
                strlcpy(&(sc->nsec3_salt[0]), &salt[0], strlen(salt)+1);
                /* nsec3 params */
            }
            /* keys */
            duration_copy(&(sc->dnskey_ttl), &dnskeyttl);
            duration_copy(&(sc->soa_ttl), &soattl);
            duration_copy(&(sc->soa_min), &soamin);
            strlcpy(&(sc->soa_serial[0]), &serial[0], strlen(serial)+1);
        }
        ods_fclose(fd);
        return status;
    }
    ods_log_error("[%s] open signconf file %s failed: %s",
        logstr, scfile, strerror(errno));
    return ODS_STATUS_FOPENERR;
}


/**
 * Update signer configuration.
 *
 */
ods_status
signconf_update(signconf_type* sc, const char* scfile)
{
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(sc);
    ods_log_assert(scfile);
    /* is the file updated? */
    st_mtime = ods_fstat(scfile);
    if (st_mtime <= sc->last_modified) {
        ods_log_verbose("[%s] file %s not modified since %u", logstr,
            scfile, (unsigned) sc->last_modified);
        return ODS_STATUS_UNCHANGED;
    }
    /* if so, read the new signer configuration */
    status = signconf_read(sc, scfile);
    if (status == ODS_STATUS_OK) {
        sc->last_modified = st_mtime;
    } else {
        ods_log_error("[%s] failed to read file %s: %s", logstr, scfile,
            ods_status2str(status));
    }
    return status;
}


/**
 * Log sign configuration.
 *
 */
void
signconf_log(signconf_type* sc, const char* name)
{
    if (sc) {
        char* resign = NULL;
        char* refresh = NULL;
        char* validity = NULL;
        char* denial = NULL;
        char* jitter = NULL;
        char* offset = NULL;
        char* dnskeyttl = NULL;
        char* soattl = NULL;
        char* soamin = NULL;
        region_type* tmpregion = region_create();
        if (!tmpregion) {
            ods_log_crit("[%s] region create failed", logstr);
            return;
        }
        resign = duration2str(tmpregion, &(sc->sig_resign_interval));
        refresh = duration2str(tmpregion, &(sc->sig_refresh_interval));
        validity = duration2str(tmpregion, &(sc->sig_validity_default));
        denial = duration2str(tmpregion, &(sc->sig_validity_denial));
        jitter = duration2str(tmpregion, &(sc->sig_jitter));
        offset = duration2str(tmpregion, &(sc->sig_inception_offset));
        dnskeyttl = duration2str(tmpregion, &(sc->dnskey_ttl));
        soattl = duration2str(tmpregion, &(sc->soa_ttl));
        soamin = duration2str(tmpregion, &(sc->soa_min));
        /* signconf */
        ods_log_info("[%s] zone %s signconf: RESIGN[%s] REFRESH[%s] "
            "VALIDITY[%s] DENIAL[%s] JITTER[%s] OFFSET[%s] NSEC[%i] "
            "DNSKEYTTL[%s] SOATTL[%s] MINIMUM[%s] SERIAL[%s]",
            logstr, name?name:"(null)",
            resign?resign:"(null)",
            refresh?refresh:"(null)",
            validity?validity:"(null)",
            denial?denial:"(null)",
            jitter?jitter:"(null)",
            offset?offset:"(null)",
            (int) sc->nsec_type,
            dnskeyttl?dnskeyttl:"(null)",
            soattl?soattl:"(null)",
            soamin?soamin:"(null)",
            sc->soa_serial?sc->soa_serial:"(null)");
        /* nsec3 parameters */
        /* keys */
        /* cleanup */
        region_cleanup(tmpregion);
    }
    return;
}


/**
 * Clean up signer configuration.
 *
 */
void
signconf_cleanup(signconf_type* ATTR_UNUSED(sc))
{
    return;
}
