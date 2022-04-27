using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptomatorApi.Misreant;

namespace CryptomatorApi;

internal sealed class V7CryptomatorApi : ICryptomatorApi
{
    private readonly IFileProvider _fileProvider;
    private readonly Keys _keys;
    private static readonly string PathSeparator = Path.DirectorySeparatorChar.ToString();
    private readonly string _physicalPathRoot;

    private readonly HashAlgorithm _sha1 = SHA1.Create();
    private readonly Aead _siv;
    private readonly string _vaultPath;

    public V7CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider)
    {
        _keys = keys;

        _vaultPath = vaultPath;
        _fileProvider = fileProvider;
        _siv = Aead.CreateAesCmacSiv(keys.SivKey);

        var ciphertext = _siv.Seal(Array.Empty<byte>());
        var hash = _sha1.ComputeHash(ciphertext);
        var fullDirName = Base32Encoding.ToString(hash);
        _physicalPathRoot = PathJoin(fullDirName.Substring(0, 2), fullDirName.Substring(2));
    }

    public async IAsyncEnumerable<string> GetFiles(string virtualPath, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        var stack = new Stack<DirInfo>();
        stack.Push(GetRootDirInfo());

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var fsi in _fileProvider.GetFileSystemInfosAsync(dir.PhysicalPath, cancellationToken).ConfigureAwait(false))
            {
                var encryptedFilename = fsi.Name;
                if (await IsVirtualDirectory(fsi, cancellationToken).ConfigureAwait(false))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(fsi.FullName, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (newDir.Name.ToLower() == virtualDirHierarchy[dir.Level].ToLower())
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
    }

    public async IAsyncEnumerable<FolderInfo> GetFolders(string virtualPath, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);

        var stack = new Stack<DirInfo>();
        stack.Push(GetRootDirInfo());

        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            await foreach (var d in _fileProvider.GetDirectoriesAsync(dir.PhysicalPath, cancellationToken).ConfigureAwait(false))
            {
                var encryptedFilename = Path.GetFileName(d);
                if (await IsVirtualDirectory(d, cancellationToken).ConfigureAwait(false))
                {
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(d, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (newDir.Name.ToLower() == virtualDirHierarchy[dir.Level].ToLower())
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

    public async Task<Stream> OpenRead(string virtualPath, CancellationToken cancellationToken)
    {
        var encryptedFilePath = await GetFilePhysicalPath(virtualPath, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(encryptedFilePath))
            throw new ArgumentException("Unable to locate encrypted file");
        return new FileDecryptStream(new FileStream(encryptedFilePath, FileMode.Open), _keys);
        //var outputStream = new MemoryStream();
        //await using var encryptedStream = new FileStream(encryptedFilePath, FileMode.Open);
        //using var reader = new BinaryReader(encryptedStream);
        //FileDecryptStream.DecryptStream(encryptedStream, outputStream, _keys);
        //outputStream.Position = 0;
        //return outputStream;
    }

    private async Task<bool> IsVirtualDirectory(FileSystemInfo f, CancellationToken cancellationToken)
    {
        if ((f.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
            return await IsVirtualDirectory(f.FullName, cancellationToken).ConfigureAwait(false);
        return false;
    }

    private async Task<bool> IsVirtualDirectory(string directoryFullName, CancellationToken cancellationToken)
    {
        //Rule out that it is a file
        if (directoryFullName.EndsWith(".c9s") && await _fileProvider
                .IsFileExistsAsync(PathJoin(directoryFullName, "contents.c9r"), cancellationToken).ConfigureAwait(false))
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
            await foreach (var fsi in _fileProvider.GetFileSystemInfosAsync(dir.PhysicalPath, cancellationToken).ConfigureAwait(false))
            {
                var encryptedFilename = fsi.Name;
                if (await IsVirtualDirectory(fsi, cancellationToken).ConfigureAwait(false))
                {
                    //It's a directory...
                    if (dir.Level < virtualDirHierarchy.Length)
                    {
                        var newDir = await CreateDirInfo(fsi.FullName, dir, cancellationToken)
                            .ConfigureAwait(false);
                        if (newDir.Name.ToLower() == virtualDirHierarchy[dir.Level].ToLower())
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
                        var base64EncryptedName = encryptedFilename;
                        var filename = await DecryptFileName(fsi.FullName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        if (filename.ToLower() == searchFilename.ToLower())
                        {
                            if (fsi.FullName.EndsWith(".c9s"))
                                return PathJoin(fsi.FullName, "contents.c9r");
                            return fsi.FullName;
                        }
                    }
                }
            }
        }

        return "";
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

    private string[] GetDirHierarchy(string virtualPath)
    {
        if (virtualPath.Contains(PathSeparator + PathSeparator))
            throw new ArgumentException("Invalid file path");

        if (virtualPath.StartsWith(PathSeparator))
            virtualPath = virtualPath.Substring(1);

        var dirList = virtualPath.Split(PathSeparator[0]);

        if (dirList[0] == "")
            return Array.Empty<string>(); //root only, return empty hierarchy.
        return dirList;
    }


    private string PathJoin(params string[] values)
    {
        var result = string.Join(PathSeparator, values);

        //All returned paths are relative to root (ie. no leading backslash required)
        //so remove leading backslash if present (happens when valu[0] == "" [root])

        if (result.StartsWith(PathSeparator))
            result = result.Substring(1);

        return result;
    }

    private class DirInfo
    {
        public string Name { get; set; }
        public string VirtualPath { get; set; }
        public string PhysicalPath { get; set; }
        public string ParentDirId { get; set; }
        public int Level { get; set; }
    }
}