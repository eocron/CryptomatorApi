using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi
{
    internal sealed class LazyCryptomatorApi : ICryptomatorApi
    {
        private ICryptomatorApi _inner;
        private readonly SemaphoreSlim _sync = new SemaphoreSlim(1);
        private readonly Func<CancellationToken, Task<ICryptomatorApi>> _provider;
        public LazyCryptomatorApi(Func<CancellationToken, Task<ICryptomatorApi>> apiProvider)
        {
            _provider = apiProvider;
        }

        private async Task EnsureInitialized(CancellationToken cancellationToken)
        {
            if(_inner != null)
                return;

            await _sync.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_inner != null)
                    return;

                _inner = await _provider(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _sync.Release();
            }
        }

        public async IAsyncEnumerable<string> GetFiles(string virtualPath, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await EnsureInitialized(cancellationToken).ConfigureAwait(false);
            await foreach (var e in _inner.GetFiles(virtualPath, cancellationToken).ConfigureAwait(false))
            {
                yield return e;
            }
        }

        public async IAsyncEnumerable<FolderInfo> GetFolders(string virtualPath, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await EnsureInitialized(cancellationToken).ConfigureAwait(false);
            await foreach (var e in _inner.GetFolders(virtualPath, cancellationToken).ConfigureAwait(false))
            {
                yield return e;
            }
        }

        public async Task<Stream> OpenRead(string virtualPath, CancellationToken cancellationToken)
        {
            await EnsureInitialized(cancellationToken).ConfigureAwait(false);
            return await _inner.OpenRead(virtualPath, cancellationToken).ConfigureAwait(false);
        }
    }
}
