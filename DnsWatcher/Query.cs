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
        public readonly QueryWatcher QueryWatcher;
        public readonly DnsQuestion Question;
        public bool OriginServer = false;
        public bool ReportErrors = false;
        private string? lastValue = null;

        public delegate void ChangedEventHandler(Query sender, IDnsQueryResponse e);
        public event ChangedEventHandler? Change = null;

        internal Query(QueryWatcher watcher, DnsQuestion question)
        {
            QueryWatcher = watcher;
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
}