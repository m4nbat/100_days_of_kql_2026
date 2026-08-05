kql
```
// find events between two dates
AuthenticationEvents
| where timestamp >= startofday(datetime(2024-05-01))
| where timestamp < endofday(datetime(2024-05-01))

// find events before or on a certain date
AuthenticationEvents
| where timestamp <= endofday(datetime(2024-06-19))
| where result == "Failed Login"

// find events between two dates
AuthenticationEvents
| where timestamp between (datetime(2024-06-01) .. datetime(2024-06-07))
| where result == "Failed Login"

// find events using a lookback X days
AuthenticationEvents
| where timestamp > ago(24h)

// group timestamps into buckets
AuthenticationEvents
| where result == "Failed Login"
| summarize hourly_failures = count() by bin(timestamp, 1h)
| order by timestamp asc


// group timestamps into buckets and plot on timechart
AuthenticationEvents
| where result == "Failed Login"
| summarize hourly_failures = count() by bin(timestamp, 1h)
| render timechart

//This shows when each sender first and last sent emails containing that link. If the timestamps are months apart, the attack has been ongoing for a long time.
Email
| where link has "docs.google.com" and sender =~ "raul_wilson@jojoshospital.org"
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by sender

```
