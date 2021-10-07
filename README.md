# DnsWatcher
Watch DNS records for changes, polling according to the TTL

## Usage
This library provides the `DnsWatcher` type, which can be used like this:
```csharp
var watcher = new QueryWatcher();
watcher.Add("github.com", QueryType.A).OnChange((q, r) => {
    //Do something with the response
    foreach (var a in r.Answers.AddressRecords())
    {
        Console.WriteLine(a.ToString());
    }
});
watcher.Start();
```

## Operation
The `DnsWatcher` polls the DNS server whenever the shortest TTL expires, whenever the local network configuration changes, or when you tell it to by calling the `SkipDelay` method.

It will raise the `Change` event (which you can listen on) whenever the DNS records it receives have changed from what it received last time.

## Changelog

### 1.0.0
Initial release
