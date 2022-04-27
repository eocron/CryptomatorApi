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

internal sealed class V6CryptomatorApi : ICryptomatorApi
{
    private static readonly string PathSeparator = Path.DirectorySeparatorChar.ToString();
    private readonly IFileProvider _fileProvider;
    private readonly Keys _keys;
    private readonly string _physicalPathRoot;

    private readonly HashAlgorithm _sha1 = SHA1.Create();
    private readonly Aead _siv;
    private readonly string _vaultPath;

    public V6CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider)
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
                        if (newDir.Name.ToLower() == virtualDirHierarchy[dir.Level].ToLower())
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
            throw new ArgumentException("Unable to locate encrypted file");
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
                        var base32EncryptedName = encryptedFilename;
                        var filename = await DecryptFileName(base32EncryptedName, dir.ParentDirId, cancellationToken)
                            .ConfigureAwait(false);
                        if (filename.ToLower() == searchFilename.ToLower())
                            return d;
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

    private sealed class DirInfo
    {
        public string Name { get; set; }
        public string VirtualPath { get; set; }
        public string PhysicalPath { get; set; }
        public string ParentDirId { get; set; }
        public int Level { get; set; }
    }
}