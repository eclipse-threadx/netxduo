#include "asc_security_core/utils/itime.h"

static unix_time_callback_t _time_callback = NULL;

void itime_init(unix_time_callback_t time_callback)
{
    _time_callback = time_callback;
}

uint32_t itime_time(uint32_t *timer)
{
    if (_time_callback == NULL)
    {
        return (uint32_t)-1;
    }

    return _time_callback(timer);
}
