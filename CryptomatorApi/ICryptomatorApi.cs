﻿using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CryptomatorApi;

public interface ICryptomatorApi
{
    Task<List<string>> GetFiles(string virtualPath = "", CancellationToken cancellationToken = default);
    Task<List<string>> GetDirs(string virtualPath, CancellationToken cancellationToken);
    Task<List<FolderInfo>> GetFolders(string virtualPath, CancellationToken cancellationToken);
    Task DecryptFile(string virtualPath, string outFile, CancellationToken cancellationToken);
    Task DecryptFile(string virtualPath, Stream outputStream, CancellationToken cancellationToken);
    Task<string> GetEncryptedFilePath(string virtualPath, CancellationToken cancellationToken);
}