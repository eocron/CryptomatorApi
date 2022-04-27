using System;
using System.Security.Cryptography;
using CryptomatorApi.Core;
using CryptomatorApi.Core.Contract;
using CryptomatorApi.Misreant;

namespace CryptomatorApi;

internal abstract class CryptomatorApiBase
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

    protected DirInfo GetRootDirInfo()
    {
        return new DirInfo
        {
            VirtualPath = "",
            PhysicalPath = PathJoin(_vaultPath, "d", _physicalPathRoot),
            ParentDirId = "",
            Level = 0
        };
    }

    protected string[] GetDirHierarchy(string virtualPath)
    {
        return _pathHelper.Split(virtualPath);
    }


    protected string PathJoin(params string[] values)
    {
        return _pathHelper.Combine(values);
    }

    protected sealed class DirInfo
    {
        public string Name { get; set; }
        public string VirtualPath { get; set; }
        public string PhysicalPath { get; set; }
        public string ParentDirId { get; set; }
        public int Level { get; set; }
    }
}