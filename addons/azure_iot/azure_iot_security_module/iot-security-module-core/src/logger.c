/*******************************************************************************/
/*                                                                             */
/* Copyright (c) Microsoft Corporation. All rights reserved.                   */
/*                                                                             */
/* This software is licensed under the Microsoft Software License              */
/* Terms for Microsoft Azure Defender for IoT. Full text of the license can be */
/* found in the LICENSE file at https://aka.ms/AzureDefenderForIoT_EULA        */
/* and in the root directory of this software.                                 */
/*                                                                             */
/*******************************************************************************/
#include <asc_config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#include "asc_security_core/logger.h"
#include "asc_security_core/utils/string_utils.h"
#include "asc_security_core/components_manager.h"
#ifdef ASC_COMPONENT_CONFIGURATION
#include "asc_security_core/configuration.h"
#endif
#include "asc_security_core/utils/iconv.h"
#include "asc_security_core/utils/string_utils.h"
#include "asc_security_core/logger.h"

#if ASC_LOG_LEVEL != LOG_LEVEL_NOTSET

static unsigned int _system_level = ASC_LOG_LEVEL;

static code2string_t _log_levels[] = {
    {LOG_LEVEL_NOTSET, "NOSET"},
    {LOG_LEVEL_FATAL, "FATAL"},
    {LOG_LEVEL_ERROR, "ERROR"},
    {LOG_LEVEL_WARN, "WARN"},
    {LOG_LEVEL_INFO, "INFO"},
    {LOG_LEVEL_DEBUG, "DEBUG"},
    {-1, NULL}
};

static asc_result_t _init(component_id_t id)
{
    return ASC_RESULT_OK;
}

#ifdef ASC_COMPONENT_CONFIGURATION
static bool _conf_validate_level(conf_t *conf)
{
    if (conf->value.type != CONF_TYPE_STRING) {
        log_error("Invalid configuration for component=[%.*s]: invalid type for key=[%.*s]",
            conf->component.length, conf->component.string, conf->key.length, conf->key.string);
        return false;
    }

    if (string2code(_log_levels, conf->value.value.string.string, conf->value.value.string.length) == -1) {
        log_error("Invalid configuration for component=[%.*s]: invalid type for key=[%.*s]",
            conf->component.length, conf->component.string, conf->key.length, conf->key.string);
        return false;
    }

    return true;
}

static asc_result_t _conf_validate_or_apply(linked_list_iterator_conf_t *conf_list_iter, bool validate_only)
{
    conf_t *conf;
    bool all_pass = true;

    while ((conf = linked_list_iterator_conf_t_next(conf_list_iter)) != NULL) {
        char *token = NULL, *rest = NULL;
        size_t token_len = 0, rest_len = 0;
        component_id_t id;
        int code;

        log_debug("Validating [%.*s]: key=[%.*s]",
            conf->component.length, conf->component.string, conf->key.length, conf->key.string);

        if (!str_ncmp(conf->key.string, conf->key.length, "Level", str_len("Level"))) {
            if (!_conf_validate_level(conf)) {
                all_pass = false;
                continue;
            }

            if (validate_only) {
                continue;
            }

            code = string2code(_log_levels, conf->value.value.string.string, conf->value.value.string.length);
            logger_set_system_log_level(code);
            continue;
        }

        /* Validate key in format: <Component Name>_Level */
        if (str_split(conf->key.string, &token, &token_len, &rest, &rest_len, "_") != ASC_RESULT_OK) {
            log_error("Invalid configuration for component=[%.*s]: key=[%.*s]",
                conf->component.length, conf->component.string, conf->key.length, conf->key.string);
            all_pass = false;
            continue;
        }

        id = components_manager_get_id_by_name(token, token_len);
        if (id == 0) {
            log_error("Invalid component=[%.*s]", (uint32_t)token_len, token);
            all_pass = false;
            continue;
        }

        if (str_ncmp("Level", str_len("Level"), rest, rest_len)) {
            log_error("Invalid key=[%.*s]", (uint32_t)rest_len, rest);
            all_pass = false;
            continue;
        }

        if (!_conf_validate_level(conf)) {
                all_pass = false;
                continue;
            }

        if (validate_only) {
            continue;
        }

        if (!all_pass) {
            /* Shouldn't happen (it should fail on validation step) */
            log_error("Can't apply new log configuration - validation failed");
            continue;
        }

        code = string2code(_log_levels, conf->value.value.string.string, conf->value.value.string.length);
        components_manager_set_log_level(id, code);
    }

    return all_pass ? ASC_RESULT_OK : ASC_RESULT_BAD_ARGUMENT;
}

static asc_result_t _conf_validate(linked_list_iterator_conf_t *conf_list_iter)
{
    return _conf_validate_or_apply(conf_list_iter, true);
}

static asc_result_t _conf_apply(linked_list_iterator_conf_t *conf_list_iter)
{
    return _conf_validate_or_apply(conf_list_iter, false);
}
#endif

static asc_result_t _deinit(component_id_t id)
{
    return ASC_RESULT_OK;
}

static asc_result_t _subscribe(component_id_t id)
{
#ifdef ASC_COMPONENT_CONFIGURATION
    return configuration_component_register(components_manager_get_name(id), _conf_validate, _conf_apply);
#else
    return ASC_RESULT_OK;
#endif
}

static asc_result_t _unsubscribe(component_id_t id)
{
#ifdef ASC_COMPONENT_CONFIGURATION
    return configuration_component_unregister(components_manager_get_name(id));
#else
    return ASC_RESULT_OK;
#endif
}

static component_ops_t _ops = {
    .init = _init,
    .deinit = _deinit,
    .subscribe = _subscribe,
    .unsubscribe = _unsubscribe,
};

COMPONENTS_FACTORY_DEFINITION(Logger, &_ops)

bool logger_set_system_log_level(int set)
{
    unsigned int level = (set < 0) ? ASC_LOG_LEVEL : (unsigned int)set;

    if (level > ASC_LOG_LEVEL) {
        log_error("Requested log level=[%u] is above than compiled=[%u]", level, ASC_LOG_LEVEL);
        return false;
    }
    _system_level = level;
    return true;
}

bool logger_log(component_id_t id, unsigned int level, const char *filename, const char *func, int line, const char *fmt, ...)
{
    const char *level_str = NULL;

    if (_system_level < level
#ifdef ASC_COMPONENT_CONFIGURATION
        || components_manager_get_log_level(id) < level
#endif
    )
    {
        return false;
    }

    level_str = code2string(_log_levels, (int)level);
    if (level_str == NULL) {
            level_str = "UNDEF";
    }

    printf(MDC_FORMAT , level_str, filename, func, line);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
    return true;
}
#else
COMPONENTS_FACTORY_DEFINITION(Logger, NULL)
#endif