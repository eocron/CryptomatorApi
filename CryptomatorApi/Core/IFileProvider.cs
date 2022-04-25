using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi.Core;

public interface IFileProvider
{
    Task<bool> IsFileExistsAsync(string filePath, CancellationToken cancellationToken);
    Task<string> ReadAllTextAsync(string filePath, CancellationToken cancellationToken);
    Task<string[]> ReadAllLinesAsync(string filePath, CancellationToken cancellationToken);
    Task<bool> HasFilesAsync(string folderPath, CancellationToken cancellationToken);
    IAsyncEnumerable<string> GetDirectoriesAsync(string folderPath, CancellationToken cancellationToken);
    IAsyncEnumerable<FileSystemInfo> GetFileSystemInfosAsync(string folderPath, CancellationToken cancellationToken);
    IAsyncEnumerable<string> GetFilesAsync(string folderPath, CancellationToken cancellationToken);
}