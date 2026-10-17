/* Just enough of <time.h> for libraries that only name the types (Mbed TLS). */
#ifndef STUB_TIME_H
#define STUB_TIME_H
typedef long time_t;
struct tm { int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst; };
time_t time(time_t *);
struct tm *gmtime(const time_t *);
struct tm *gmtime_r(const time_t *, struct tm *);
#endif
