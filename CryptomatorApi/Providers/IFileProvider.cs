using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi.Providers;

public interface IFileProvider
{
    Task<bool> IsFileExistsAsync(string filePath, CancellationToken cancellationToken);
    IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfosAsync(string folderPath, CancellationToken cancellationToken);
    Task<Stream> OpenReadAsync(string filePath, CancellationToken cancellationToken);
}