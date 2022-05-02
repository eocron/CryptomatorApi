using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi.Core
{
    internal abstract class AsyncStream : Stream
    {
        public override long Seek(long offset, SeekOrigin origin)
        {
            return SeekAsync(offset, origin, CancellationToken.None).GetAwaiter().GetResult();
        }

        public abstract Task<long> SeekAsync(long offset, SeekOrigin origin, CancellationToken cancellationToken);
    }
}
