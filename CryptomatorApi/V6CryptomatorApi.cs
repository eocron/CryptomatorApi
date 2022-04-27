using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;

namespace CryptomatorApi;

internal sealed class V6CryptomatorApi : CryptomatorApiBase, ICryptomatorApi
{
    public V6CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider, IPathHelper pathHelper) : base(
        keys, vaultPath, fileProvider, pathHelper)
    {
    }

    public async IAsyncEnumerable<string> GetFiles(string virtualPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        var stack = new Stack<DirInfo>();
        stack.Push(GetRootDirInfo());
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var fsi in _fileProvider.GetFileSystemInfosAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
            {
                var encryptedFilename = fsi.Name;
                if (encryptedFilename.StartsWith("0"))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(fsi.FullName, encryptedFilename, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(newDir.Name, virtualDirHierarchy[dir.Level]))
                        {
                            stack.Push(newDir);
                            break;
                        }
                    }
                }
                else
                {
                    //It's a file...  
                    if (dir.Level == virtualDirHierarchy.Length)
                    {
                        var base32EncryptedName = encryptedFilename;
                        var filename = await DecryptFileName(base32EncryptedName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        yield return PathJoin(dir.VirtualPath, filename);
                    }
                }
            }
        }
    }

    public async IAsyncEnumerable<FolderInfo> GetFolders(string virtualPath,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);

        var stack = new Stack<DirInfo>();
        stack.Push(GetRootDirInfo());

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var d in _fileProvider.GetFilesAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
            {
                var encryptedFilename = Path.GetFileName(d);
                if (encryptedFilename.StartsWith("0"))
                {
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(d, encryptedFilename, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(newDir.Name, virtualDirHierarchy[dir.Level]))
                        {
                            stack.Push(newDir);
                            break;
                        }
                    }
                    else if (dir.Level == virtualDirHierarchy.Length)
                    {
                        var newDirInfo = await CreateDirInfo(d, encryptedFilename, dir, cancellationToken)
                            .ConfigureAwait(false);
                        yield return
                            new FolderInfo
                            {
                                VirtualPath = PathJoin(dir.VirtualPath, newDirInfo.Name),
                                Name = newDirInfo.Name,
                                HasChildren = await _fileProvider
                                    .HasFilesAsync(newDirInfo.PhysicalPath, cancellationToken).ConfigureAwait(false)
                            };
                    }
                }
            }
        }
    }

    public async Task<Stream> OpenReadAsync(string virtualPath, CancellationToken cancellationToken)
    {
        var encryptedFilePath = await GetFilePhysicalPath(virtualPath, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(encryptedFilePath))
            throw new FileNotFoundException("Unable to locate encrypted file");
        return new FileDecryptStream(
            await _fileProvider.OpenReadAsync(encryptedFilePath, cancellationToken).ConfigureAwait(false), _keys);
    }

    private async Task<string> GetFilePhysicalPath(string virtualPath, CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        var searchFilename = virtualDirHierarchy[virtualDirHierarchy.Length - 1];
        virtualDirHierarchy =
            virtualDirHierarchy.Take(virtualDirHierarchy.Length - 1)
                .ToArray(); //Remove filename portion of path at the end

        var stack = new Stack<DirInfo>();

        stack.Push(GetRootDirInfo());

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var d in _fileProvider.GetFilesAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
            {
                var encryptedFilename = Path.GetFileName(d);
                if (encryptedFilename.StartsWith("0"))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(d, encryptedFilename, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(newDir.Name, virtualDirHierarchy[dir.Level]))
                        {
                            stack.Push(newDir);
                            break;
                        }
                    }
                }
                else
                {
                    //It's a file...  is the right one?
                    if (dir.Level == virtualDirHierarchy.Length)
                    {
                        var base32EncryptedName = encryptedFilename;
                        var filename = await DecryptFileName(base32EncryptedName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(filename, searchFilename))
                            return d;
                    }
                }
            }
        }

        return "";
    }

    private async Task<DirInfo> CreateDirInfo(string physicalDirFile, string base32EncryptedName, DirInfo parent,
        CancellationToken cancellationToken)
    {
        base32EncryptedName = base32EncryptedName.Substring(1);

        var filename = await DecryptFileName(base32EncryptedName, parent.ParentDirId, cancellationToken)
            .ConfigureAwait(false);

        var lines = await _fileProvider.ReadAllLinesAsync(physicalDirFile, cancellationToken).ConfigureAwait(false);
        var dirId = lines[0];
        Debug.Assert(lines[0].Length == 36 && lines.Length == 1);

        var dirIdHash = Base32Encoding.ToString(_sha1.ComputeHash(_siv.Seal(Encoding.UTF8.GetBytes(dirId))));
        Debug.Assert(dirIdHash.Length == 32);

        var actualDirPath = PathJoin(dirIdHash.Substring(0, 2), dirIdHash.Substring(2));

        return new DirInfo
        {
            Name = filename,
            VirtualPath = PathJoin(parent.VirtualPath, filename),
            PhysicalPath = PathJoin(_vaultPath, "d", actualDirPath),
            ParentDirId = dirId,
            Level = parent.Level + 1
        };
    }

    private async Task<string> DecryptFileName(string fullFileName, string parentDirId,
        CancellationToken cancellationToken)
    {
        var base32EncryptedName = Path.GetFileName(fullFileName);

        if (base32EncryptedName.EndsWith(".lng"))
            base32EncryptedName = await GetEncryptedLongFilename(fullFileName, cancellationToken).ConfigureAwait(false);

        var encryptedName = Base32Encoding.ToBytes(base32EncryptedName);
        var plaintextName = _siv.Open(encryptedName, null, Encoding.UTF8.GetBytes(parentDirId));
        return Encoding.UTF8.GetString(plaintextName);
    }

    private async Task<string> GetEncryptedLongFilename(string base32EncryptedName, CancellationToken cancellationToken)
    {
        var location = PathJoin(_vaultPath, "m", base32EncryptedName.Substring(0, 2),
            base32EncryptedName.Substring(2, 2), base32EncryptedName);

        var lines = await _fileProvider.ReadAllLinesAsync(location, cancellationToken).ConfigureAwait(false);
        return lines[0];
    }
}