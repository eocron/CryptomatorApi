using System;
using System.Collections.Generic;
using System.IO;
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

    public async IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfosAsync(
        string folderPath,
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
}