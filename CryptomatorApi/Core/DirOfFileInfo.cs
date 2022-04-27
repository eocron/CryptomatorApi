using System;
using System.IO;

namespace CryptomatorApi.Core;

public class DirOfFileInfo
{
    public readonly FileAttributes Attributes;
    public readonly string FullName;
    public readonly string Name;

    public DirOfFileInfo(string name, string fullName, FileAttributes attributes)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        FullName = fullName ?? throw new ArgumentNullException(fullName);
        Attributes = attributes;
    }
}