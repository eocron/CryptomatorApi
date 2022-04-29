using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi.Providers;

public sealed class SimpleFileProvider : IFileProvider
{
    public Task<bool> IsFileExistsAsync(string filePath, CancellationToken cancellationToken)
    {
        return Task.FromResult(File.Exists(filePath));
    }

    public Task<string> ReadAllTextAsync(string filePath, CancellationToken cancellationToken)
    {
        return File.ReadAllTextAsync(filePath, cancellationToken);
    }

    public Task<string[]> ReadAllLinesAsync(string filePath, CancellationToken cancellationToken)
    {
        return File.ReadAllLinesAsync(filePath, cancellationToken);
    }

    public async IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfosAsync(string folderPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var all = new DirectoryInfo(folderPath).EnumerateFileSystemInfos();
        try
        {
            foreach (var fileSystemInfo in all)
                yield return Map(fileSystemInfo);
        }
        finally
        {
            (all as IDisposable)?.Dispose();
        }
    }

    private CryptomatorFileSystemInfo Map(FileSystemInfo info)
    {
        if ((info.Attributes & FileAttributes.Directory) != 0)
            return new CryptomatorDirectoryInfo
            {
                FullName = info.FullName,
                Name = info.Name
            };
        return new CryptomatorFileInfo
        {
            FullName = info.FullName,
            Name = info.Name
        };
    }

    public Task<Stream> OpenReadAsync(string encryptedFilePath, CancellationToken cancellationToken)
    {
        return Task.FromResult((Stream)new FileStream(encryptedFilePath, FileMode.Open));
    }

    public Task<bool> HasFilesAsync(string folderPath, CancellationToken cancellationToken)
    {
        return Task.FromResult(new DirectoryInfo(folderPath).EnumerateFileSystemInfos().Any());
    }
}