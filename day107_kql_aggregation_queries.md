kql
```
AuthenticationEvents
| where result == "Successful Login"
| summarize total_logins = count() by src_ip

AuthenticationEvents
| where result == "Failed Login"
| summarize failed_attempts = count() by username, src_ip

ProcessEvents
| summarize count() by process_name

AuthenticationEvents
| where result == "Successful Login"
| summarize unique_accounts = dcount(username) by src_ip
| where unique_accounts > 1

AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07)) and hostname =~ "48NM-LAPTOP"
| where result == "Failed Login"
| summarize count() by password_hash

AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize count() by password_hash
| sort by count_ desc
| where count_ == 1


AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize count() by password_hash

//password spray detection
AuthenticationEvents
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where result == "Failed Login"
| summarize unique_accounts = dcount(username) by password_hash
| sort by unique_accounts desc
| where unique_accounts > 10

AuthenticationEvents  // Look in the auth events table
| where result == "Failed Login" // Looking auth attempts that failed
// group by passwords hashes to find accounts that have had multiple passwords guessed
| summarize dcount(username) by password_hash

AuthenticationEvents
| where result == "Failed Login"
| summarize
    total_attempts = count(),
    unique_passwords = dcount(password_hash),
    first_seen = min(timestamp),
    last_seen = max(timestamp)
  by src_ip

//a query that shows for each sender: total emails sent AND the number of unique recipients.
Email
| summarize
    total_sent = count(),
    unique_recipient = dcount(recipient)
  by sender

//This shows when each sender first and last sent emails containing that link. If the timestamps are months apart, the attack has been ongoing for a long time.
Email
| where link has "docs.google.com" and sender =~ "raul_wilson@jojoshospital.org"
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by sender

// query that shows all encrypted (.encrypted) files on the machine with hostname ENRQ-LAPTOP. The query should show the "first seen" and "last seen" time for each file by its filename.
FileCreationEvents
| where filename endswith ".encrypted" and hostname =~ "ENRQ-LAPTOP"
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by filename

```


