using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi;

public interface ICryptomatorApi
{
    IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfos(string virtualPath, CancellationToken cancellationToken);
    IAsyncEnumerable<CryptomatorFileInfo> GetFiles(string virtualPath, CancellationToken cancellationToken);
    IAsyncEnumerable<CryptomatorDirectoryInfo> GetDirectories(string virtualPath, CancellationToken cancellationToken);
    Task<Stream> OpenReadAsync(string virtualPath, CancellationToken cancellationToken);
}