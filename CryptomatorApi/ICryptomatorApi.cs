using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi;

public interface ICryptomatorApi
{
    IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfos(string folderPath, CancellationToken cancellationToken);
    IAsyncEnumerable<CryptomatorFileInfo> GetFiles(string folderPath, CancellationToken cancellationToken);
    IAsyncEnumerable<CryptomatorDirectoryInfo> GetDirectories(string folderPath, CancellationToken cancellationToken);
    Task<Stream> OpenReadAsync(string filePath, CancellationToken cancellationToken);
}