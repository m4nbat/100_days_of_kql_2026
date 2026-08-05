```

AuthenticationEvents
| extend hour = hourofday(timestamp)
| where hour < 6 or hour >= 18
| count



```
