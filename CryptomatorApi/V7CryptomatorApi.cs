using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptomatorApi.Providers;

namespace CryptomatorApi;

internal sealed class V7CryptomatorApi : CryptomatorApiBase, ICryptomatorApi
{
    public V7CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider, IPathHelper pathHelper) : 
        base(keys, vaultPath, fileProvider, pathHelper)
    {
    }

    protected override async Task<bool> IsVirtualDirectory(CryptomatorFileSystemInfo f, CancellationToken cancellationToken)
    {
        if (f is CryptomatorDirectoryInfo)
        {
            if (f.FullName.EndsWith(".c9s") && await _fileProvider
                    .IsFileExistsAsync(PathJoin(f.FullName, "contents.c9r"), cancellationToken)
                    .ConfigureAwait(false))
                return false;

            return true;
        }

        return false;
    }

    protected override async Task<string> GetFilePhysicalPath(string virtualPath, CancellationToken cancellationToken)
    {
        var virtualDirHierarchy = GetDirHierarchy(virtualPath);
        var searchFilename = virtualDirHierarchy[^1];
        virtualDirHierarchy.RemoveAt(virtualDirHierarchy.Count - 1);
        await foreach (var (parentDir, file) in GetAllEntries(virtualDirHierarchy, false, true, cancellationToken).ConfigureAwait(false))
        {
            var filename = await DecryptFileName(file.FullName, parentDir.ParentDirId, cancellationToken).ConfigureAwait(false);
            if (_pathHelper.Equals(filename, searchFilename))
            {
                if (file.FullName.EndsWith(".c9s"))
                    return PathJoin(file.FullName, "contents.c9r");
                return file.FullName;
            }
        }
        return "";
    }

    protected override async Task<DirInfo> CreateDirInfo(CryptomatorFileSystemInfo dirOfFileInfo, DirInfo parent,
        CancellationToken cancellationToken)
    {
        var filename = await DecryptFileName(dirOfFileInfo.FullName, parent.ParentDirId, cancellationToken)
            .ConfigureAwait(false);
        var lines = await _fileProvider.ReadAllLinesAsync(PathJoin(dirOfFileInfo.FullName, "dir.c9r"), cancellationToken)
            .ConfigureAwait(false);
        var dirId = lines[0];
        var dirIdHash = Base32Encoding.ToString(_sha1.ComputeHash(_siv.Seal(Encoding.UTF8.GetBytes(dirId))));
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

    protected override async Task<string> DecryptFileName(string fullFileName, string parentDirId,
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