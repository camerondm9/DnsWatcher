using DnsClient;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace DnsWatcher
{
    public sealed class QueryWatcher : IDisposable
    {
        private readonly LookupClientOptions DnsLookupOptions;

        private CancellationTokenSource? source;
        private Task? task = null;
        private readonly AsyncManualResetEvent networkChange = new();

        private readonly List<Query> queries = new();
        public IReadOnlyList<Query> Queries => queries;

        public QueryWatcher(LookupClientOptions? dnsLookupOptions = null)
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
                int minTtl = int.MaxValue;
                try
                {
                    //Use new LookupClient to get up-to-date DNS settings...
                    var dns = new LookupClient(DnsLookupOptions);
                    //Prepare queries...
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
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    System.Diagnostics.Trace.TraceError(ex.ToString());
                }
                //Wait for network connectivity changes or a refresh timeout...
                await networkChange.WaitAsync(minTtl, token).ConfigureAwait(false);
                //Wait couple seconds for all the network changes to be fully in effect...
                await Task.Delay(5000, token).ConfigureAwait(false);
                networkChange.Reset();
            }
        }
    }
}
