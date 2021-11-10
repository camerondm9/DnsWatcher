using System.Threading;
using System.Threading.Tasks;

namespace DnsWatcher
{
    internal class AsyncManualResetEvent
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
            //TODO: The new (.Net 6) Task.WaitAsync method might be a better option here...

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
