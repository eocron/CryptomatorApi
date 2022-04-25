using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi;

public interface ICryptomatorApi
{
    IAsyncEnumerable<string> GetFiles(string virtualPath, CancellationToken cancellationToken);
    IAsyncEnumerable<FolderInfo> GetFolders(string virtualPath, CancellationToken cancellationToken);
    Task DecryptFile(string virtualPath, string outFile, CancellationToken cancellationToken);
    Task DecryptFile(string virtualPath, Stream outputStream, CancellationToken cancellationToken);
}