#ifndef SETTINGS
#define SETTINGS
// ALERT_ENABLE_INFO_LOGGING defines whether Logs of the INFO Level (so all
// queries that are executed and don't meet the Byte or Duration Threshold)
// should be logged
static const int ALERT_ENABLE_INFO_LOGGING = 0;
// ALERT_DUMP indicates whether mariadb-dump should be tried to be detected. If
// it is detected an alert is generated.
static const int ALERT_DUMP = 1;
// Threshold for the query size in Megabytes. Queries bigger or equal to the
// defined Threshold generate an alert.
static const double ALERT_QUERY_SIZE_MEGABYTES = 5;
// Threshold for the response time in Milliseconds. Queries that take longer
// than the specified Threshold generate an alert.
static const double ALERT_DURATION_MILLISECONDS = 1000;

#endif
