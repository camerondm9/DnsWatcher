using DnsClient;
using DnsClient.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsWatcher
{
    public sealed class DnsWatcher : IDisposable
    {
        private readonly LookupClientOptions DnsLookupOptions;

        private CancellationTokenSource? source;
        private Task? task = null;
        private readonly AsyncManualResetEvent networkChange = new();

        private readonly List<Query> queries = new();
        public IReadOnlyList<Query> Queries => queries;

        public DnsWatcher(LookupClientOptions? dnsLookupOptions = null)
        {
            DnsLookupOptions = dnsLookupOptions ?? new();
            DnsLookupOptions.UseCache = false;
            DnsLookupOptions.ThrowDnsErrors = false;
            if (!DnsLookupOptions.CacheFailedResults && DnsLookupOptions.FailedResultsCacheDuration.TotalSeconds == 5)
            {
                DnsLookupOptions.FailedResultsCacheDuration = TimeSpan.FromMinutes(1);
            }
        }

        public void Start()
        {
            if (task?.IsCompleted != false)
            {
                //Listen for network changes...
                networkChange.Reset();
                NetworkChange.NetworkAddressChanged += NetworkChanged;
                NetworkChange.NetworkAvailabilityChanged += NetworkChanged;
                //Create new background task...
                source = new();
                var token = source.Token;
                task = Task.Run(() => DoWork(token), token);
                task.ContinueWith(t => Console.WriteLine(t.Exception?.ToString()));
            }
        }
        public void Stop()
        {
            if (task?.IsFaulted == true)
            {
                throw task.Exception!;
            }
            source?.Cancel();
            NetworkChange.NetworkAddressChanged -= NetworkChanged;
            NetworkChange.NetworkAvailabilityChanged -= NetworkChanged;
        }
        public void Dispose()
        {
            Stop();
        }
        /// <summary>
        /// Short-circuits the current delay and runs the queries again immediately
        /// </summary>
        public void SkipDelay()
        {
            networkChange.Set();
        }
        private void NetworkChanged(object sender, EventArgs e)
        {
            //If network changed but is still available, then retry our queries...
            if (NetworkInterface.GetIsNetworkAvailable())
            {
                networkChange.Set();
            }
        }

        private Query Add(Query q)
        {
            lock (queries)
            {
                queries.Add(q);
            }
            return q;
        }
        public Query Add(string query, QueryType queryType, QueryClass queryClass = QueryClass.IN)
        {
            return Add(new Query(this, new DnsQuestion(query, queryType, queryClass)));
        }
        public Query Add(DnsQuestion question)
        {
            return Add(new Query(this, question));
        }
        public Query Add(IPAddress ipAddress)
        {
            return Add(new Query(this, LookupClient.GetReverseQuestion(ipAddress)));
        }
        public bool Remove(Query q)
        {
            lock (queries)
            {
                return queries.Remove(q);
            }
        }

        private async Task DoWork(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                //Use new LookupClient to get up-to-date DNS settings...
                var dns = new LookupClient(DnsLookupOptions);
                //Prepare queries...
                int minTtl = int.MaxValue;
                if (dns.NameServers.Count > 0)
                {
                    List<Task<int>> tasks;
                    lock (queries)
                    {
                        tasks = new(queries.Count);
                        foreach (var q in queries)
                        {
                            tasks.Add(q.Update(dns, token));
                        }
                    }
                    //Run all queries and determine shortest TTL...
                    foreach (var ttl in await Task.WhenAll(tasks).ConfigureAwait(false))
                    {
                        if (minTtl > ttl)
                        {
                            minTtl = ttl;
                        }
                    }
                }
                if (minTtl == int.MaxValue)
                {
                    //No records found, or all errors...
                    minTtl = (int)DnsLookupOptions.FailedResultsCacheDuration.TotalMilliseconds;
                }
                else
                {
                    //DNS TTL is in seconds, but we need milliseconds...
                    minTtl *= 1000;
                }
                //Constrain refresh timeout...
                if (DnsLookupOptions.MinimumCacheTimeout.HasValue)
                {
                    var minTimeout = (int)DnsLookupOptions.MinimumCacheTimeout.Value.TotalMilliseconds;
                    if (minTtl < minTimeout)
                    {
                        minTtl = minTimeout;
                    }
                }
                if (DnsLookupOptions.MaximumCacheTimeout.HasValue)
                {
                    var maxTimeout = (int)DnsLookupOptions.MaximumCacheTimeout.Value.TotalMilliseconds;
                    if (minTtl > maxTimeout)
                    {
                        minTtl = maxTimeout;
                    }
                }
                //Wait for network connectivity changes or a refresh timeout...
                await networkChange.WaitAsync(minTtl, token).ConfigureAwait(false);
                //Wait couple seconds for all the network changes to be fully in effect...
                await Task.Delay(5000, token).ConfigureAwait(false);
                networkChange.Reset();
            }
        }

        private static bool IPv6Routable()
        {
            foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if ((ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) && !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal)
                {
                    return true;
                }
            }
            return false;
        }

        public class Query
        {
            public readonly DnsWatcher DnsWatcher;
            public readonly DnsQuestion Question;
            public bool OriginServer = false;
            public bool ReportErrors = false;
            private string? lastValue = null;

            public delegate void ChangedEventHandler(Query sender, IDnsQueryResponse e);
            public event ChangedEventHandler? Change = null;

            internal Query(DnsWatcher watcher, DnsQuestion question)
            {
                DnsWatcher = watcher;
                Question = question;
            }

            public Query SetOriginServer(bool originServer = true)
            {
                OriginServer = originServer;
                return this;
            }
            public Query SetReportErrors(bool reportErrors = true)
            {
                ReportErrors = reportErrors;
                return this;
            }
            public Query OnChange(ChangedEventHandler action)
            {
                Change += action;
                return this;
            }

            private static int AddressFamilyMask(AddressFamily family)
            {
                switch (family)
                {
                    case AddressFamily.InterNetwork:
                    default:
                        return 2;
                    case AddressFamily.InterNetworkV6:
                        return 1;
                    case AddressFamily.Unknown:
                    case AddressFamily.Unspecified:
                        return 0;
                }
            }

            public async Task<int> Update(LookupClient dns, CancellationToken cancellationToken)
            {
                DnsQueryAndServerOptions? options = null;
                if (OriginServer)
                {
                    //Check for IPv6 support...
                    bool ipv6 = IPv6Routable();
                    //Get domain names for actual nameservers...
                    var resultNs = await dns.QueryAsync(Question.QueryName, QueryType.NS, Question.QuestionClass, cancellationToken).ConfigureAwait(false);
                    var nameservers = new Dictionary<string, int>();
                    var nameserverIps = new HashSet<IPAddress>();
                    foreach (var ns in resultNs.Answers.NsRecords())
                    {
                        nameservers[ns.NSDName] = 0;
                    }
                    foreach (var glue in resultNs.AllRecords.AddressRecords())
                    {
                        if (nameservers.TryGetValue(glue.DomainName, out var i))
                        {
                            nameserverIps.Add(glue.Address);
                            //Record address family...
                            nameservers[glue.DomainName] = i | AddressFamilyMask(glue.Address.AddressFamily);
                        }
                    }
                    //Get IPs for actual nameservers... (if glue not present)
                    var queries = new List<Task<IDnsQueryResponse>>();
                    foreach (var kv in nameservers)
                    {
                        if (kv.Value == 0 || (!ipv6 && kv.Value == AddressFamilyMask(AddressFamily.InterNetworkV6)))
                        {
                            queries.Add(dns.QueryAsync(kv.Key, QueryType.A, QueryClass.IN, cancellationToken));
                            if (ipv6)
                            {
                                queries.Add(dns.QueryAsync(kv.Key, QueryType.AAAA, QueryClass.IN, cancellationToken));
                            }
                        }
                    }
                    foreach (var response in await Task.WhenAll(queries).ConfigureAwait(false))
                    {
                        foreach (var addr in response.Answers.AddressRecords())
                        {
                            if (nameservers.TryGetValue(addr.DomainName, out var i))
                            {
                                nameserverIps.Add(addr.Address);
                            }
                        }
                    }
                    //Rebuild options with actual nameservers...
                    options = new DnsQueryAndServerOptions((ipv6 ? nameserverIps : nameserverIps.Where(ip => ip.AddressFamily != AddressFamily.InterNetworkV6)).ToArray())
                    {
                        ContinueOnDnsError = dns.Settings.ContinueOnDnsError,
                        ContinueOnEmptyResponse = dns.Settings.ContinueOnEmptyResponse,
                        EnableAuditTrail = dns.Settings.EnableAuditTrail,
                        Recursion = dns.Settings.Recursion,
                        Retries = dns.Settings.Retries,
                        ThrowDnsErrors = dns.Settings.ThrowDnsErrors,
                        Timeout = dns.Settings.Timeout,
                        UseCache = dns.Settings.UseCache,
                        UseRandomNameServer = dns.Settings.UseRandomNameServer,
                        UseTcpFallback = dns.Settings.UseTcpFallback,
                        UseTcpOnly = dns.Settings.UseTcpOnly,
                        ExtendedDnsBufferSize = dns.Settings.ExtendedDnsBufferSize,
                        RequestDnsSecRecords = dns.Settings.RequestDnsSecRecords,
                        CacheFailedResults = dns.Settings.CacheFailedResults,
                        FailedResultsCacheDuration = dns.Settings.FailedResultsCacheDuration,
                    };
                }
                //Perform query...
                var result = await (options != null ? dns.QueryAsync(Question, options, cancellationToken) : dns.QueryAsync(Question, cancellationToken)).ConfigureAwait(false);
                int minTtl = int.MaxValue;
                if (!result.HasError)
                {
                    //Convert records to text and determine shortest TTL...
                    var text = new List<string>();
                    foreach (var r in result.Answers)
                    {
                        if (Match(r.RecordType, Question.QuestionType))
                        {
                            text.Add(r.ToString());
                        }
                        if (minTtl > r.InitialTimeToLive)
                        {
                            minTtl = r.InitialTimeToLive;
                        }
                    }
                    //Make order consistent...
                    text.Sort();
                    //Combine all records into a single string...
                    var sb = new StringBuilder();
                    foreach (var t in text)
                    {
                        var i = t.IndexOf(' ');
                        i++;
                        var j = t.IndexOf(' ', i);
                        sb.Append(t, 0, i);
                        sb.Append("00");
                        sb.Append(t.AsSpan()[j..]);
                    }
                    //Compare with previous value...
                    var value = sb.ToString();
                    if (lastValue != value)
                    {
                        lastValue = value;
                    }
                    else
                    {
                        //Intentionally skips invoking the Change event
                        return minTtl;
                    }
                }
                else if (!ReportErrors)
                {
                    return minTtl;
                }
                try
                {
                    Change?.Invoke(this, result);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.TraceError(ex.ToString());
                }
                return minTtl;
            }
            private static bool Match(ResourceRecordType rType, QueryType qType)
            {
                return ((int)rType == (int)qType) || (qType == QueryType.ANY);
            }
        }

        private class AsyncManualResetEvent
        {
            // Modified from Stephen Toub's example:
            // https://devblogs.microsoft.com/pfxteam/building-async-coordination-primitives-part-1-asyncmanualresetevent/

            private volatile TaskCompletionSource<bool> m_tcs = new();

            public AsyncManualResetEvent(bool initialState = false)
            {
                if (initialState)
                {
                    Set();
                }
            }

            public Task WaitAsync()
            {
                return m_tcs.Task;
            }
            public async Task<bool> WaitAsync(int millisecondsTimeout, CancellationToken cancellationToken = default)
            {
                // Modified from SemaphoreSlim.WaitUntilCountOrTimeoutAsync
                // https://referencesource.microsoft.com/#mscorlib/system/threading/SemaphoreSlim.cs,c44be0c6552c5861
                var task = m_tcs.Task;
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, default))
                {
                    if (task == await Task.WhenAny(task, Task.Delay(millisecondsTimeout, cts.Token)).ConfigureAwait(false))
                    {
                        cts.Cancel(); // ensure that the Task.Delay task is cleaned up
                        return true;
                    }
                    // Timed out or cancelled
                    return false;
                }
            }

            public void Set()
            {
                m_tcs.TrySetResult(true);
            }

            public void Reset()
            {
                TaskCompletionSource<bool> tcs;
                do
                {
                    tcs = m_tcs;
                }
                while (tcs.Task.IsCompleted && Interlocked.CompareExchange(ref m_tcs, new TaskCompletionSource<bool>(), tcs) != tcs);
            }
        }
    }
}
