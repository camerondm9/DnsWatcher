using DnsClient;
using DnsClient.Protocol;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsWatcher
{
    public class Query
    {
        public QueryWatcher QueryWatcher { get; }
        public DnsQuestion Question { get; }
        public bool AuthoritativeServers { get; set; } = false;
        /// <summary>
        /// TTL is adjusted continuously by any DNS cache. You should directly access the authoritative server if watching the TTL.
        /// </summary>
        public bool WatchTtl { get; set; } = false;
        public bool SuppressErrors { get; set; } = false;
        private string? lastValue = null;

        public Func<Query, Dictionary<string, HashSet<IPAddress>>, CancellationToken, Task>? FilterAuthoritativeServers = null;

        public delegate void ChangeEventHandler(Query sender, IDnsQueryResponse e);
        public event ChangeEventHandler? Change = null;

        internal Query(QueryWatcher watcher, DnsQuestion question)
        {
            QueryWatcher = watcher;
            Question = question;
        }

        public Query SetAuthoritativeServers(bool authoritativeServers = true, Func<Query, Dictionary<string, HashSet<IPAddress>>, CancellationToken, Task>? filterAuthoritativeServers = null)
        {
            AuthoritativeServers = authoritativeServers;
            FilterAuthoritativeServers = filterAuthoritativeServers;
            return this;
        }
        /// <summary>
        /// TTL is adjusted continuously by any DNS cache. You should directly access the authoritative server if watching the TTL.
        /// </summary>
        public Query SetWatchTtl(bool watchTtl = true)
        {
            WatchTtl = watchTtl;
            return this;
        }
        public Query SetSuppressErrors(bool suppressErrors = true)
        {
            SuppressErrors = suppressErrors;
            return this;
        }
        public Query OnChange(ChangeEventHandler action)
        {
            Change += action;
            return this;
        }

        private static bool IPv6Routable()
        {
            foreach (var ip in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                if ((ip.AddressFamily == AddressFamily.InterNetworkV6) && !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal)
                {
                    return true;
                }
            }
            return false;
        }

        public async Task<int> Update(LookupClient dns, CancellationToken cancellationToken)
        {
            DnsQueryAndServerOptions? options = null;
            if (AuthoritativeServers)
            {
                //Check for IPv6 support...
                bool ipv6 = IPv6Routable();
                //Get domain names for actual nameservers...
                var resultNs = await dns.QueryAsync(Question.QueryName, QueryType.NS, Question.QuestionClass, cancellationToken).ConfigureAwait(false);
                var nameservers = new Dictionary<string, HashSet<IPAddress>>();
                foreach (var ns in resultNs.Answers.NsRecords())
                {
                    nameservers.Add(ns.NSDName, new HashSet<IPAddress>());
                }
                if (nameservers.Count == 0)
                {
                    throw new InvalidOperationException("No nameservers found!");
                }
                //Include glue records... (if any)
                void MergeIps(IDnsQueryResponse response)
                {
                    foreach (var addr in response.AllRecords.AddressRecords())
                    {
                        if (nameservers.TryGetValue(addr.DomainName, out var ips))
                        {
                            ips.Add(addr.Address);
                        }
                    }
                }
                MergeIps(resultNs);
                //Let the user filter the nameservers...
                if (FilterAuthoritativeServers != null)
                {
                    try
                    {
                        await FilterAuthoritativeServers(this, nameservers, cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.TraceError(ex.ToString());
                    }
                    if (nameservers.Count == 0)
                    {
                        //All nameservers removed, cancel this query...
                        return int.MaxValue;
                    }
                }
                //Get IPs for nameservers... (if glue not present)
                var queries = new List<Task<IDnsQueryResponse>>();
                foreach (var kv in nameservers)
                {
                    if ((ipv6 ? kv.Value.Count : kv.Value.Count(ip => ip.AddressFamily != AddressFamily.InterNetworkV6)) == 0)
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
                    MergeIps(response);
                }
                //Combine list of nameserver IPs...
                var nameserverIps = new HashSet<IPAddress>();
                foreach (var kv in nameservers)
                {
                    nameserverIps.UnionWith(kv.Value);
                }
                if (nameserverIps.Count == 0)
                {
                    throw new InvalidOperationException("No nameservers resolved!");
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
                    if (WatchTtl)
                    {
                        sb.Append(t);
                    }
                    else
                    {
                        var i = t.IndexOf(' ');
                        i++;
                        var j = t.IndexOf(' ', i);
                        sb.Append(t, 0, i);
                        sb.Append("00");
                        sb.Append(t.AsSpan()[j..]);
                    }
                    sb.AppendLine();
                }
                //Compare with previous value...
                var value = sb.ToString();
                if (lastValue != value)
                {
                    lastValue = value;
                    OnChange(result);
                }
            }
            else if (!SuppressErrors)
            {
                OnChange(result);
            }
            return minTtl;
        }
        private void OnChange(IDnsQueryResponse response)
        {
            try
            {
                Change?.Invoke(this, response);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.TraceError(ex.ToString());
            }
        }
        private static bool Match(ResourceRecordType rType, QueryType qType)
        {
            return ((int)rType == (int)qType) || (qType == QueryType.ANY);
        }
    }
}
