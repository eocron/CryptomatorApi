using System;
using System.IO;

namespace CryptomatorApi.Core;

public class DirOfFileInfo
{
    public readonly string Name;
    public readonly string FullName;
    public readonly FileAttributes Attributes;

    public DirOfFileInfo(string name, string fullName, FileAttributes attributes)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        FullName = fullName ?? throw new ArgumentNullException(fullName);
        Attributes = attributes;
    }
}