using System.Collections.Generic;

namespace CryptomatorApi;

public abstract class CryptomatorFileSystemInfo
{
    public string Name { get; set; }
    public string FullName { get; set; }
    public Dictionary<string, string> MetaData { get; set; }
}