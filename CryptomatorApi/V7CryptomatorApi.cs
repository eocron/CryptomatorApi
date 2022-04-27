using System;
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

internal sealed class V7CryptomatorApi : CryptomatorApiBase, ICryptomatorApi
{
    public V7CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider, IPathHelper pathHelper) : base(
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
                if (await IsVirtualDirectory(fsi, cancellationToken).ConfigureAwait(false))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(fsi.FullName, dir, cancellationToken)
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
                        var filename = await DecryptFileName(fsi.FullName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        yield return PathJoin(dir.VirtualPath, filename);
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
            await foreach (var d in _fileProvider.GetDirectoriesAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
            {
                var encryptedFilename = Path.GetFileName(d);
                if (await IsVirtualDirectory(d, cancellationToken).ConfigureAwait(false))
                {
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(d, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(newDir.Name, virtualDirHierarchy[dir.Level]))
                        {
                            stack.Push(newDir);
                            break;
                        }
                    }
                    else if (dir.Level == virtualDirHierarchy.Length)
                    {
                        var newDirInfo = await CreateDirInfo(d, dir, cancellationToken)
                            .ConfigureAwait(false);
                        yield return new FolderInfo
                        {
                            VirtualPath = PathJoin(dir.VirtualPath, newDirInfo.Name),
                            Name = newDirInfo.Name,
                            HasChildren = await _fileProvider.HasFilesAsync(newDirInfo.PhysicalPath, cancellationToken)
                                .ConfigureAwait(false)
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

    private async Task<bool> IsVirtualDirectory(DirOfFileInfo f, CancellationToken cancellationToken)
    {
        if ((f.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
            return await IsVirtualDirectory(f.FullName, cancellationToken).ConfigureAwait(false);
        return false;
    }

    private async Task<bool> IsVirtualDirectory(string directoryFullName, CancellationToken cancellationToken)
    {
        //Rule out that it is a file
        if (directoryFullName.EndsWith(".c9s") && await _fileProvider
                .IsFileExistsAsync(PathJoin(directoryFullName, "contents.c9r"), cancellationToken)
                .ConfigureAwait(false))
            return false;

        return true;
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
            await foreach (var fsi in _fileProvider.GetFileSystemInfosAsync(dir.PhysicalPath, cancellationToken)
                               .ConfigureAwait(false))
                if (await IsVirtualDirectory(fsi, cancellationToken).ConfigureAwait(false))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(fsi.FullName, dir, cancellationToken)
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
                        var filename = await DecryptFileName(fsi.FullName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        if (_pathHelper.Equals(filename, searchFilename))
                        {
                            if (fsi.FullName.EndsWith(".c9s"))
                                return PathJoin(fsi.FullName, "contents.c9r");
                            return fsi.FullName;
                        }
                    }
                }
        }

        return "";
    }

    private async Task<DirInfo> CreateDirInfo(string physicalDirFile, DirInfo parent,
        CancellationToken cancellationToken)
    {
        var filename = await DecryptFileName(physicalDirFile, parent.ParentDirId, cancellationToken)
            .ConfigureAwait(false);
        var lines = await _fileProvider.ReadAllLinesAsync(PathJoin(physicalDirFile, "dir.c9r"), cancellationToken)
            .ConfigureAwait(false);
        var dirId = lines[0];
        Debug.Assert(lines[0].Length == 36 && lines.Length == 1);

        var dirIdHash =
            Base32Encoding.ToString(_sha1.ComputeHash(_siv.Seal(Encoding.UTF8.GetBytes(dirId))));
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
        var base64EncryptedName = Path.GetFileName(fullFileName);

        if (base64EncryptedName.EndsWith(".c9s"))
            base64EncryptedName = await GetEncryptedLongFilename(fullFileName, cancellationToken).ConfigureAwait(false);

        if (base64EncryptedName.EndsWith(".c9r"))
            base64EncryptedName = base64EncryptedName.Substring(0, base64EncryptedName.Length - 4);

        var encryptedName = Base64Url.ToBytes(base64EncryptedName);
        var plaintextName = _siv.Open(encryptedName, null, Encoding.UTF8.GetBytes(parentDirId));
        return Encoding.UTF8.GetString(plaintextName);
    }

    private async Task<string> GetEncryptedLongFilename(string fullFileName, CancellationToken cancellationToken)
    {
        var location = PathJoin(fullFileName, "name.c9s");
        var lines = await _fileProvider.ReadAllLinesAsync(location, cancellationToken).ConfigureAwait(false);
        return lines[0];
    }
}