using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptomatorApi.Misreant;
using CryptomatorApi.Providers;

namespace CryptomatorApi;

internal abstract class CryptomatorApiBase : ICryptomatorApi
{
    protected readonly IFileProvider _fileProvider;
    protected readonly Keys _keys;
    protected readonly IPathHelper _pathHelper;
    protected readonly string _physicalPathRoot;

    protected readonly HashAlgorithm _sha1 = SHA1.Create();
    protected readonly Aead _siv;
    protected readonly string _vaultPath;

    protected CryptomatorApiBase(Keys keys, string vaultPath, IFileProvider fileProvider, IPathHelper pathHelper)
    {
        _keys = keys;

        _vaultPath = vaultPath;
        _fileProvider = fileProvider;
        _pathHelper = pathHelper;
        _siv = Aead.CreateAesCmacSiv(keys.SivKey);

        var ciphertext = _siv.Seal(Array.Empty<byte>());
        var hash = _sha1.ComputeHash(ciphertext);
        var fullDirName = Base32Encoding.ToString(hash);
        _physicalPathRoot = PathJoin(fullDirName.Substring(0, 2), fullDirName.Substring(2));
    }

    private DirInfo GetRootDirInfo()
    {
        return new DirInfo
        {
            VirtualPath = "",
            PhysicalPath = PathJoin(_vaultPath, "d", _physicalPathRoot),
            ParentDirId = "",
            Level = 0
        };
    }

    protected List<string> GetDirHierarchy(string virtualPath)
    {
        if (string.IsNullOrEmpty(virtualPath))
            return new List<string>();
        return _pathHelper.Split(virtualPath).ToList();
    }


    protected string PathJoin(params string[] values)
    {
        return _pathHelper.Combine(values);
    }


    public async IAsyncEnumerable<CryptomatorFileSystemInfo> GetFileSystemInfos(
        string virtualPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        await foreach (var (parentDir, file) in GetAllEntries(virtualDirHierarchy, true, true, cancellationToken)
                           .ConfigureAwait(false))
            if (file is CryptomatorDirectoryInfo)
            {
                var newDirInfo = await CreateDirInfo(file, parentDir, cancellationToken)
                    .ConfigureAwait(false);
                yield return new CryptomatorDirectoryInfo
                {
                    FullName = PathJoin(parentDir.VirtualPath, newDirInfo.Name),
                    Name = newDirInfo.Name,
                    MetaData = file.MetaData
                };
            }
            else
            {
                var filename = await DecryptFileName(file.FullName, parentDir.ParentDirId, cancellationToken)
                    .ConfigureAwait(false);
                yield return new CryptomatorFileInfo
                {
                    MetaData = file.MetaData,
                    FullName = PathJoin(parentDir.VirtualPath, filename),
                    Name = filename
                };
            }
    }

    public async IAsyncEnumerable<CryptomatorFileInfo> GetFiles(string virtualPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        await foreach (var (parentDir, file) in GetAllEntries(virtualDirHierarchy, false, true, cancellationToken)
                           .ConfigureAwait(false))
        {
            var filename = await DecryptFileName(file.FullName, parentDir.ParentDirId, cancellationToken)
                .ConfigureAwait(false);
            yield return new CryptomatorFileInfo
            {
                MetaData = file.MetaData,
                FullName = PathJoin(parentDir.VirtualPath, filename),
                Name = filename
            };
        }
    }



    public async IAsyncEnumerable<CryptomatorDirectoryInfo> GetDirectories(string virtualPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        await foreach (var (parentDir, dir) in GetAllEntries(virtualDirHierarchy, true, false, cancellationToken)
                           .ConfigureAwait(false))
        {
            var newDirInfo = await CreateDirInfo(dir, parentDir, cancellationToken)
                .ConfigureAwait(false);
            yield return new CryptomatorDirectoryInfo
            {
                FullName = PathJoin(parentDir.VirtualPath, newDirInfo.Name),
                Name = newDirInfo.Name,
                MetaData = dir.MetaData
            };
        }
    }

    public async Task<Stream> OpenReadAsync(string virtualPath, CancellationToken cancellationToken)
    {
        var encryptedFilePath = await GetFilePhysicalPath(virtualPath, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(encryptedFilePath))
            throw new FileNotFoundException("Unable to locate encrypted file");
        return new DecryptStream(
            await _fileProvider.OpenReadAsync(encryptedFilePath, cancellationToken).ConfigureAwait(false), _keys);
    }

    protected async IAsyncEnumerable<(DirInfo, CryptomatorFileSystemInfo)> GetAllEntries(
        List<string> virtualDirHierarchy,
        bool includeDirs,
        bool includeFiles,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var stack = new Stack<DirInfo>();
        stack.Push(GetRootDirInfo());

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var fsi in _fileProvider.GetFileSystemInfosAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
                if (await IsVirtualDirectory(fsi, cancellationToken).ConfigureAwait(false))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Count)
                    {
                        var newDir = await CreateDirInfo(fsi, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(newDir.Name, virtualDirHierarchy[dir.Level]))
                        {
                            stack.Push(newDir);
                            break;
                        }
                    }
                    else if (includeDirs && dir.Level == virtualDirHierarchy.Count)
                    {
                        yield return (dir, fsi);
                    }
                }
                else if (includeFiles && dir.Level == virtualDirHierarchy.Count)
                {
                    //It's a "backup directory file" > skip
                    //https://docs.cryptomator.org/en/latest/security/architecture/
                    
                    /*
                    Note
                    
                    This layer is optional and not required for a complete implementation of the Cryptomator Encryption Scheme. 
                    It doesn’t provide any additional security. 
                    Its sole purpose is to increase data recoverability in case of missing or damaged directory files.
                    
                    By obfuscating the hierarchy of cleartext paths using dir.c9r files, which contain directory IDs, 
                    the directory structure is more vulnerable to problems like incomplete synchronization or bit rotting.
                    
                    When a directory file is missing or damaged, the dirPath cannot be computed, 
                    which effectively makes the directory content inaccessible in the virtual filesystem. 
                    In theory, the contents of the encrypted content of these files can be recovered. 
                    But since the filename encryption is dependent on the directory ID of the parent folder, 
                    which is only stored in the directory file, names of all items (files, directories, or symlinks) are lost.
                    
                    To alleviate this issue, a backup directory file will be stored during the creation of a directory. 
                    Inside the ciphertext directory, a file named dirid.c9r will be created, 
                    which contains the directory ID of its parent folder. It is encrypted like a regular ciphertext file.
                    */
                    if (fsi.Name == "dirid.c9r") continue;
                    
                    yield return (dir, fsi);
                }
        }
    }

    protected abstract Task<string> DecryptFileName(string fileFullName, string parentDirParentDirId,
        CancellationToken cancellationToken);
    protected abstract Task<string> GetFilePhysicalPath(string virtualPath, CancellationToken cancellationToken);

    protected abstract Task<bool> IsVirtualDirectory(CryptomatorFileSystemInfo fsi, CancellationToken cancellationToken);

    protected abstract Task<DirInfo> CreateDirInfo(CryptomatorFileSystemInfo fsi, DirInfo parentDir,
        CancellationToken cancellationToken);

    protected sealed class DirInfo
    {
        public string Name { get; set; }
        public string VirtualPath { get; set; }
        public string PhysicalPath { get; set; }
        public string ParentDirId { get; set; }
        public int Level { get; set; }
    }
}
