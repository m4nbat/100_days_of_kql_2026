```

//look for logins outside of usual hours
AuthenticationEvents
| extend hour = hourofday(timestamp)
| where hour < 6 or hour >= 18
| count


// The iff() function adds conditional logic
AuthenticationEvents
| extend status = iff(result == "Successful Login", "OK", "FAILED")

| extend risk = case(
    attempts > 100, "CRITICAL",
    attempts > 50, "HIGH",
    attempts > 10, "MEDIUM",
    "LOW"
)

//sample events
FileCreationEvents
| take 100
| where filename endswith ".ps1"

// using split to parse out sender domains in an email table
Email
| extend  sender_domain = tostring(split(sender, "@")[-1])
| where sender_domain !in~ ("jojoshospital.org","kentuckypharmasupply.com")
| distinct sender_domain

// has_any operator to look for commandlines
ProcessEvents
| where process_commandline has_any ("schtasks", "net user", "reg add")










```
