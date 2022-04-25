using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;

namespace CryptomatorApi
{
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

        public async IAsyncEnumerable<FileSystemInfo> GetFileSystemInfosAsync(string folderPath, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var all = new DirectoryInfo(folderPath).EnumerateFileSystemInfos();
            try
            {
                foreach (var fileSystemInfo in all)
                {
                    yield return fileSystemInfo;
                }
            }
            finally
            {
                (all as IDisposable)?.Dispose();
            }
        }

        public async IAsyncEnumerable<string> GetFilesAsync(string folderPath, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var files = Directory.GetFiles(folderPath);
            foreach (var file in files)
            {
                yield return file;
            }
        }

        public Task<bool> HasFilesAsync(string folderPath, CancellationToken cancellationToken)
        {
            return Task.FromResult(new DirectoryInfo(folderPath).EnumerateFileSystemInfos().Any());
        }

        public async IAsyncEnumerable<string> GetDirectoriesAsync(string folderPath, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var dirs = Directory.GetDirectories(folderPath);
            foreach (var dir in dirs)
            {
                yield return dir;
            }
        }
    }
}
