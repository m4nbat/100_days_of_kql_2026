

// Identify internet facing devices that could be impacted by MongoBleed vulnerability
let InternetFacingDevices =
// Find all devices that are internet-facing
DeviceInfo
| where IsInternetFacing = true
| distinct DeviceId;
let PatchVersion = dynamic(["8.2.3", "8.0.17", "7.0.28", "6.0.27", "5.0.32", "4.4.30"]);
DeviceNetworkEvents
| where DeviceId in~ (InternetFacingDevices)
| where InitiatingProcessVersionInfoInternalFileName == "mongod.exe"
| where not (InitiatingProcessVersionInfoProductVersion has_any(PatchVersion))
| count | where Count > 0  // comment out or delete to see full fat results
