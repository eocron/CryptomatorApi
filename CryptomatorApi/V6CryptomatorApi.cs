using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptomatorApi.Providers;

namespace CryptomatorApi;

internal sealed class V6CryptomatorApi : CryptomatorApiBase, ICryptomatorApi
{
    public V6CryptomatorApi(Keys keys, string vaultPath, IFileProvider fileProvider, IPathHelper pathHelper) : base(
        keys, vaultPath, fileProvider, pathHelper)
    {
    }

    protected override Task<bool> IsVirtualDirectory(CryptomatorFileSystemInfo f, CancellationToken cancellationToken)
    {
        return Task.FromResult(f.Name.StartsWith("0"));
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
                return file.FullName;
            }
        }
        return "";
    }

    protected override async Task<DirInfo> CreateDirInfo(CryptomatorFileSystemInfo dirOfFileInfo, DirInfo parent,
        CancellationToken cancellationToken)
    {
        var base32EncryptedName = dirOfFileInfo.Name.Substring(1);

        var filename = await DecryptFileName(base32EncryptedName, parent.ParentDirId, cancellationToken)
            .ConfigureAwait(false);
        var lines = await _fileProvider.ReadAllLinesAsync(dirOfFileInfo.FullName, cancellationToken)
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